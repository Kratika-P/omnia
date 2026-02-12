#!/usr/bin/env python3
# Copyright 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Playbook Watcher Service for OIM Core Container.

This service monitors the NFS playbook request queue, executes Ansible playbooks,
and writes results back to the results queue. It is designed to be stateless and
run as a systemd service in the OIM Core container.

Architecture:
- Polls /opt/omnia/build_stream/playbook_queue/requests/ every 2 seconds
- Moves requests to processing/ to prevent duplicate execution
- Executes ansible-playbook with timeout and error handling
- Writes structured results to /opt/omnia/build_stream/playbook_queue/results/
- Supports max 5 concurrent playbook executions
"""

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread, Semaphore
from typing import Dict, Optional, Any

# Implicit logging utilities for secure logging
def log_secure_info(level: str, message: str, identifier: Optional[str] = None) -> None:
    """Log information securely with optional identifier truncation.
    
    This function provides consistent secure logging across all modules.
    When an identifier is provided, only the first 8 characters are logged
    to prevent exposure of sensitive data while maintaining debugging capability.
    
    Args:
        level: Log level ('info', 'warning', 'error', 'debug', 'critical')
        message: Log message template
        identifier: Optional identifier (job_id, request_id, etc.) - first 8 chars logged
    """
    logger = logging.getLogger(__name__)

    if identifier:
        # Always log first 8 characters for identification
        log_message = f"{message}: {identifier[:8]}..."
    else:
        # Generic message when no identifier context
        log_message = message

    log_func = getattr(logger, level)
    log_func(log_message)

# Configuration
QUEUE_BASE = Path(os.getenv("PLAYBOOK_QUEUE_BASE", "/opt/omnia/build_stream/playbook_queue"))
REQUESTS_DIR = QUEUE_BASE / "requests"
RESULTS_DIR = QUEUE_BASE / "results"
PROCESSING_DIR = QUEUE_BASE / "processing"
ARCHIVE_DIR = QUEUE_BASE / "archive"

# NFS shared path configuration
NFS_SHARE_PATH = Path(os.getenv("NFS_SHARE_PATH", "/abc"))
HOST_LOG_BASE_DIR = NFS_SHARE_PATH / "omnia" / "build_stream_logs"
CONTAINER_LOG_BASE_DIR = Path("/opt/omnia/build_stream_logs")

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "2"))
MAX_CONCURRENT_JOBS = int(os.getenv("MAX_CONCURRENT_JOBS", "5"))
DEFAULT_TIMEOUT_MINUTES = int(os.getenv("DEFAULT_TIMEOUT_MINUTES", "30"))

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("playbook_watcher")

# Global state
SHUTDOWN_REQUESTED = False
job_semaphore = Semaphore(MAX_CONCURRENT_JOBS)


def signal_handler(signum, _):
    """Handle shutdown signals gracefully."""
    global SHUTDOWN_REQUESTED
    log_secure_info(
        "info",
        "Received signal",
        str(signum)
    )
    SHUTDOWN_REQUESTED = True


def ensure_directories():
    """Ensure all required directories exist with proper permissions."""
    directories = [
        REQUESTS_DIR,
        RESULTS_DIR,
        PROCESSING_DIR,
        ARCHIVE_DIR,
        ARCHIVE_DIR / "requests",
        ARCHIVE_DIR / "results",
        HOST_LOG_BASE_DIR,  # NFS log directory
    ]

    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            log_secure_info(
                "debug",
                "Ensured directory exists"
            )
        except (OSError, IOError) as e:
            log_secure_info(
                "error",
                "Failed to create directory"
            )
            raise


def validate_playbook_path(playbook_path: str) -> bool:
    """Validate playbook path to prevent command injection.
    
    Args:
        playbook_path: Path to the playbook file
        
    Returns:
        True if path is valid, False otherwise
    """
    # Must be an absolute path
    if not playbook_path.startswith('/'):
        return False
    
    # Prevent path traversal attempts
    if '..' in playbook_path:
        return False
    
    # Reject any shell metacharacters or command injection patterns
    # Only allow alphanumeric, underscores, hyphens, forward slashes, and dots
    pattern = r'^[a-zA-Z0-9_\-/.]+$'
    
    if not re.match(pattern, playbook_path):
        return False
    
    # Ensure it ends with .yml or .yaml
    if not (playbook_path.endswith('.yml') or playbook_path.endswith('.yaml')):
        return False
    
    # Additional security: Check for suspicious patterns
    suspicious_patterns = [
        r';',  # Command separator
        r'\|', # Pipe
        r'&',  # Background execution
        r'\$', # Variable expansion
        r'`',  # Command substitution
        r'<',  # Input redirection
        r'>',  # Output redirection
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, playbook_path):
            return False
    
    return True


def validate_job_id(job_id: str) -> bool:
    """Validate job ID format.
    
    Args:
        job_id: Job identifier
        
    Returns:
        True if valid, False otherwise
    """
    # Allow UUID format or alphanumeric with hyphens/underscores
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    alnum_pattern = r'^[a-zA-Z0-9_-]+$'
    
    return bool(re.match(uuid_pattern, job_id) or re.match(alnum_pattern, job_id))


def validate_stage_name(stage_name: str) -> bool:
    """Validate stage name to prevent injection.
    
    Args:
        stage_name: Name of the stage
        
    Returns:
        True if valid, False otherwise
    """
    # Only allow alphanumeric, spaces, hyphens, and underscores
    pattern = r'^[a-zA-Z0-9 _-]+$'
    return bool(re.match(pattern, stage_name))


def validate_extra_vars(extra_vars: Dict[str, Any]) -> bool:
    """Validate extra_vars to prevent injection through JSON.
    
    Args:
        extra_vars: Dictionary of extra variables for Ansible
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(extra_vars, dict):
        return False
    
    # Check for suspicious patterns in keys and values
    suspicious_patterns = [
        r';',  # Command separator
        r'\|', # Pipe
        r'&',  # Background execution
        r'\$', # Variable expansion
        r'`',  # Command substitution
        r'<',  # Input redirection
        r'>',  # Output redirection
        r'\(', # Subshell
        r'\)', # Subshell
    ]
    
    def check_value(value):
        """Recursively check values for suspicious patterns."""
        if isinstance(value, str):
            for pattern in suspicious_patterns:
                if re.search(pattern, value):
                    return False
        elif isinstance(value, dict):
            for v in value.values():
                if not check_value(v):
                    return False
        elif isinstance(value, list):
            for item in value:
                if not check_value(item):
                    return False
        return True
    
    # Check all keys and values
    for key, value in extra_vars.items():
        # Check keys
        if isinstance(key, str):
            for pattern in suspicious_patterns:
                if re.search(pattern, key):
                    return False
        
        # Check values recursively
        if not check_value(value):
            return False
    
    return True


def parse_request_file(request_path: Path) -> Optional[Dict[str, Any]]:
    """Parse and validate request file.

    Args:
        request_path: Path to the request JSON file

    Returns:
        Parsed request dictionary or None if invalid
    """
    try:
        with open(request_path, 'r', encoding='utf-8') as f:
            request_data = json.load(f)

        # Validate required fields
        required_fields = ["job_id", "stage_name", "playbook_path"]
        missing_fields = [field for field in required_fields if field not in request_data]

        if missing_fields:
            logger.error(
                "Request file missing required fields: %s",
                ', '.join(missing_fields)
            )
            return None

        # Validate inputs to prevent injection
        job_id = str(request_data["job_id"])
        stage_name = str(request_data["stage_name"])
        playbook_path = str(request_data["playbook_path"])
        extra_vars = request_data.get("extra_vars", {})
        
        if not validate_job_id(job_id):
            logger.error("Invalid job_id format in request")
            return None
            
        if not validate_stage_name(stage_name):
            logger.error("Invalid stage_name format in request")
            return None
            
        if not validate_playbook_path(playbook_path):
            logger.error("Invalid or potentially malicious playbook path in request")
            return None
            
        if not validate_extra_vars(extra_vars):
            logger.error("Invalid or potentially malicious extra_vars in request")
            return None

        # Set defaults
        request_data.setdefault("timeout_minutes", DEFAULT_TIMEOUT_MINUTES)
        request_data["extra_vars"] = extra_vars
        request_data.setdefault("correlation_id", job_id)

        log_secure_info(
            "info",
            "Parsed request for job",
            job_id
        )
        log_secure_info(
            "debug",
            "Stage name",
            stage_name
        )

        return request_data

    except json.JSONDecodeError as e:
        log_secure_info(
            "error",
            "Invalid JSON in request file"
        )
        return None
    except (KeyError, TypeError, ValueError) as e:
        log_secure_info(
            "error",
            "Error parsing request file"
        )
        return None


def _build_log_paths(job_id: str, stage_name: str, started_at: datetime) -> tuple:
    """Build host and container log file paths.

    Args:
        job_id: Job identifier
        stage_name: Stage name
        started_at: Start time for timestamp

    Returns:
        Tuple of (host_log_file_path, container_log_file_path, host_log_dir)
    """
    # Create job-specific log directory on NFS share
    host_log_dir = HOST_LOG_BASE_DIR / job_id / stage_name
    host_log_dir.mkdir(parents=True, exist_ok=True)

    # Create log file path with timestamp
    timestamp = started_at.strftime("%Y%m%d_%H%M%S")
    host_log_file_path = host_log_dir / f"ansible_playbook_{timestamp}.log"

    # Container log path (equivalent path in container)
    container_log_file_path = (
        CONTAINER_LOG_BASE_DIR / job_id / stage_name / f"ansible_playbook_{timestamp}.log"
    )

    return host_log_file_path, container_log_file_path, host_log_dir


def execute_playbook(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Ansible playbook and capture results.

    Args:
        request_data: Parsed request dictionary

    Returns:
        Result dictionary with execution details
    """
    job_id = request_data["job_id"]
    stage_name = request_data["stage_name"]
    playbook_path = request_data["playbook_path"]
    extra_vars = request_data.get("extra_vars", {})
    timeout_minutes = request_data.get("timeout_minutes", DEFAULT_TIMEOUT_MINUTES)
    correlation_id = request_data.get("correlation_id", job_id)

    log_secure_info(
        "info",
        "Executing playbook for job",
        job_id
    )
    log_secure_info(
        "debug",
        "Stage name",
        stage_name
    )

    started_at = datetime.now(timezone.utc)
    host_log_file_path, container_log_file_path, _ = _build_log_paths(
        job_id, stage_name, started_at
    )

    # Build podman command to execute playbook in omnia_core container
    # Use a list to avoid shell injection and properly escape arguments
    import shlex
    
    # Sanitize and validate the playbook path
    if not playbook_path.startswith('/'):
        logger.error("Playbook path must be absolute")
        raise ValueError("Invalid playbook path")
    
    # Build command as a list to prevent shell injection
    cmd = [
        "podman", "exec",
        "-e", f"ANSIBLE_LOG_PATH={container_log_file_path}",
        "omnia_core",
        "ansible-playbook",
        playbook_path,
        "--extra-vars", json.dumps(extra_vars) if extra_vars else "{}",
        "-v"
    ]

    # Don't log the full command with potentially sensitive paths
    log_secure_info(
        "debug",
        "Executing ansible playbook for job",
        job_id
    )
    log_secure_info(
        "info",
        "Ansible logs will be written to job directory",
        job_id
    )

    try:
        # Execute playbook with timeout and custom log path
        timeout_seconds = timeout_minutes * 60
        result = subprocess.run(
            cmd,
            capture_output=False,  # Don't capture to avoid duplication with ANSIBLE_LOG_PATH
            timeout=timeout_seconds,
            check=False,
            env=os.environ.copy(),  # Pass environment variables
            shell=False  # Explicitly set shell=False to prevent injection
        )

        # Log file is directly accessible via NFS share, no need to copy
        # Wait a moment for log to be written
        time.sleep(0.5)

        # Verify log file exists
        if host_log_file_path.exists():
            log_secure_info(
                "info",
                "Log file confirmed for job",
                job_id
            )
        else:
            log_secure_info(
                "warning",
                "Log file not found at expected location for job",
                job_id
            )

        completed_at = datetime.now(timezone.utc)
        duration_seconds = (completed_at - started_at).total_seconds()

        # Determine status
        status = "success" if result.returncode == 0 else "failed"

        log_secure_info(
            "info",
            "Playbook execution completed for job",
            job_id
        )
        log_secure_info(
            "debug",
            "Execution status",
            status
        )

        # Build result dictionary
        result_data = {
            "job_id": job_id,
            "stage_name": stage_name,
            "request_id": request_data.get("request_id", job_id),
            "correlation_id": correlation_id,
            "status": status,
            "exit_code": result.returncode,
            "log_file_path": str(host_log_file_path),  # Host path to Ansible log file (NFS share)
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": int(duration_seconds),
            "timestamp": completed_at.isoformat(),
        }

        # Add error details if failed
        if status == "failed":
            result_data["error_code"] = "PLAYBOOK_EXECUTION_FAILED"
            result_data["error_summary"] = f"Playbook exited with code {result.returncode}"

        return result_data

    except subprocess.TimeoutExpired:
        completed_at = datetime.now(timezone.utc)
        duration_seconds = (completed_at - started_at).total_seconds()

        log_secure_info(
            "error",
            "Playbook execution timed out for job",
            job_id
        )

        return {
            "job_id": job_id,
            "stage_name": stage_name,
            "request_id": request_data.get("request_id", job_id),
            "correlation_id": correlation_id,
            "status": "failed",
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Playbook execution timed out after {timeout_minutes} minutes",
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": int(duration_seconds),
            "error_code": "PLAYBOOK_TIMEOUT",
            "error_summary": f"Execution exceeded timeout of {timeout_minutes} minutes",
            "timestamp": completed_at.isoformat(),
        }

    except (OSError, subprocess.SubprocessError) as e:
        completed_at = datetime.now(timezone.utc)
        duration_seconds = (completed_at - started_at).total_seconds()

        logger.exception(
            "Unexpected error executing playbook for job %s",
            job_id
        )

        return {
            "job_id": job_id,
            "stage_name": stage_name,
            "request_id": request_data.get("request_id", job_id),
            "correlation_id": correlation_id,
            "status": "failed",
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": int(duration_seconds),
            "error_code": "SYSTEM_ERROR",
            "error_summary": f"System error during execution: {str(e)}",
            "timestamp": completed_at.isoformat(),
        }

def write_result_file(result_data: Dict[str, Any], original_filename: str) -> bool:
    """Write result file to results directory.

    Args:
        result_data: Result dictionary to write
        original_filename: Original request filename for correlation

    Returns:
        True if successful, False otherwise
    """
    job_id = result_data["job_id"]

    try:
        # Use same filename pattern as request for easy correlation
        result_filename = original_filename
        result_path = RESULTS_DIR / result_filename

        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2)

        log_secure_info(
            "info",
            "Wrote result file for job",
            job_id
        )
        return True

    except (OSError, IOError) as e:
        log_secure_info(
            "error",
            "Failed to write result file for job",
            job_id
        )
        return False

def archive_request_file(request_path: Path) -> None:
    """Archive processed request file.

    Args:
        request_path: Path to the request file to archive
    """
    try:
        archive_path = ARCHIVE_DIR / "requests" / request_path.name
        shutil.move(str(request_path), str(archive_path))
        log_secure_info(
            "debug",
            "Archived request file",
            request_path.name[:8] if request_path.name else None
        )
    except (OSError, IOError) as e:
        log_secure_info(
            "warning",
            "Failed to archive request file",
            request_path.name[:8] if request_path.name else None
        )

def process_request(request_path: Path) -> None:
    """Process a single request file.

    This function handles the complete lifecycle of a request:
    1. Move to processing directory (atomic lock)
    2. Parse request
    3. Execute playbook
    4. Write result
    5. Archive request

    Args:
        request_path: Path to the request file
    """
    request_filename = request_path.name
    processing_path = PROCESSING_DIR / request_filename

    with job_semaphore:

        try:
            # Move to processing directory (atomic lock)
            try:
                shutil.move(str(request_path), str(processing_path))
                log_secure_info(
                    "debug",
                    "Moved request to processing",
                    request_filename[:8] if request_filename else None
                )
            except FileNotFoundError:
                # File already moved by another process
                log_secure_info(
                    "debug",
                    "Request already being processed",
                    request_filename[:8] if request_filename else None
                )
                return

            # Parse request
            request_data = parse_request_file(processing_path)
            if not request_data:
                log_secure_info(
                    "error",
                    "Invalid request file",
                    request_filename[:8] if request_filename else None
                )
                # Write error result
                error_result = {
                    "job_id": "unknown",
                    "stage_name": "unknown",
                    "status": "failed",
                    "exit_code": -1,
                    "error_code": "INVALID_REQUEST",
                    "error_summary": "Failed to parse request file",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                write_result_file(error_result, request_filename)
                archive_request_file(processing_path)
                return

            # Execute playbook
            result_data = execute_playbook(request_data)

            # Write result
            write_result_file(result_data, request_filename)

            # Archive request
            archive_request_file(processing_path)

        finally:
            # Ensure processing file is cleaned up even on error
            if processing_path.exists():
                try:
                    processing_path.unlink()
                except (OSError, IOError) as e:
                    log_secure_info(
                        "warning",
                        "Failed to remove processing file",
                        request_filename[:8] if request_filename else None
                    )

def process_request_async(request_path: Path) -> None:
    """Process request in a separate thread.

    Args:
        request_path: Path to the request file
    """
    thread = Thread(target=process_request, args=(request_path,), daemon=True)
    thread.start()

def scan_and_process_requests() -> int:
    """Scan requests directory and process new requests.

    Returns:
        Number of requests processed
    """
    try:
        request_files = sorted(REQUESTS_DIR.glob("*.json"))

        if not request_files:
            return 0

        log_secure_info(
            "debug",
            "Found request files",
            str(len(request_files))
        )

        processed_count = 0
        for request_path in request_files:
            if SHUTDOWN_REQUESTED:
                log_secure_info(
                    "info",
                    "Shutdown requested"
                )
                break

            try:
                # Process asynchronously
                process_request_async(request_path)
                processed_count += 1
            except (OSError, IOError) as e:
                log_secure_info(
                    "error",
                    "Error processing request",
                    request_path.name[:8] if request_path.name else None
                )

        return processed_count

    except (OSError, IOError) as e:
        log_secure_info(
            "error",
            "Error scanning requests directory"
        )
        return 0

def run_watcher_loop():
    """Main watcher loop that continuously polls for requests."""
    log_secure_info(
        "info",
        "Starting Playbook Watcher Service"
    )
    log_secure_info(
        "info",
        "Queue base directory"
    )
    log_secure_info(
        "info",
        f"Poll interval: {POLL_INTERVAL_SECONDS}s"
    )
    log_secure_info(
        "info",
        f"Max concurrent jobs: {MAX_CONCURRENT_JOBS}"
    )
    log_secure_info(
        "info",
        f"Default timeout: {DEFAULT_TIMEOUT_MINUTES}m"
    )

    # Ensure directories exist
    try:
        ensure_directories()
    except (OSError, IOError) as e:
        log_secure_info(
            "critical",
            "Failed to initialize directories"
        )
        sys.exit(1)

    # Main loop
    iteration = 0
    while not SHUTDOWN_REQUESTED:
        iteration += 1

        try:
            processed_count = scan_and_process_requests()

            if processed_count > 0:
                log_secure_info(
                    "info",
                    "Processed requests in iteration",
                    str(processed_count)
                )

        except RuntimeError as e:
            logger.exception(
                "Unexpected error in watcher loop iteration %d",
                iteration
            )

        # Sleep before next poll
        time.sleep(POLL_INTERVAL_SECONDS)

    log_secure_info(
        "info",
        "Playbook Watcher Service stopped"
    )

def main():
    """Main entry point for the watcher service."""
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        run_watcher_loop()
    except KeyboardInterrupt:
        log_secure_info(
            "info",
            "Received keyboard interrupt"
        )
    except (RuntimeError, OSError):
        log_secure_info(
            "critical",
            "Fatal error in watcher service"
        )
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
