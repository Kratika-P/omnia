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
from typing import Dict, Optional, Any, List

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
    # Whitelisted playbook directories - these paths are inside the container
    ALLOWED_PREFIXES = (
        '/omnia/utils/',
        '/omnia/build_image_aarch64/',
        '/omnia/build_image_x86_64/',
        '/omnia/discovery/',
        '/omnia/local_repo/',
    )
    
    # Only allow safe filesystem characters
    pattern = r'^[a-zA-Z0-9_\-/.]+$'
    
    # Must be an absolute path
    if not playbook_path.startswith('/'):
        log_secure_info(
            "error",
            "Playbook path must be absolute",
            playbook_path[:8] if playbook_path else None
        )
        return False
    
    # Prevent path traversal attempts
    if '..' in playbook_path:
        log_secure_info(
            "error",
            "Path traversal detected in playbook path",
            playbook_path[:8] if playbook_path else None
        )
        return False
        
    # Whitelist directory check
    if not any(playbook_path.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        log_secure_info(
            "error",
            "Playbook path not in allowed directories",
            playbook_path[:8] if playbook_path else None
        )
        return False
    
    # Reject any shell metacharacters or command injection patterns
    if not re.match(pattern, playbook_path):
        log_secure_info(
            "error",
            "Invalid characters in playbook path",
            playbook_path[:8] if playbook_path else None
        )
        return False
    
    # Ensure it ends with .yml or .yaml
    if not (playbook_path.endswith('.yml') or playbook_path.endswith('.yaml')):
        log_secure_info(
            "error",
            "Playbook must have .yml or .yaml extension",
            playbook_path[:8] if playbook_path else None
        )
        return False
    
    # No spaces (prevents argument splitting)
    if ' ' in playbook_path:
        log_secure_info(
            "error",
            "Playbook path cannot contain spaces",
            playbook_path[:8] if playbook_path else None
        )
        return False
    
    return True


def sanitize_playbook_path(playbook_path: str) -> Optional[str]:
    """Validate and sanitize playbook path to prevent command injection.
    
    Returns a sanitized copy of the path (breaking the taint chain)
    or None if the path is invalid. The returned path is constructed
    as a new string that is not derived from the original untrusted input.
    
    Note: We don't check for file existence because the playbook paths
    are relative to the container filesystem, not the host filesystem.
    
    Args:
        playbook_path: Path to the playbook file (untrusted input)
        
    Returns:
        Sanitized absolute path string, or None if validation fails
    """
    # First validate the path using the existing validation function
    if not validate_playbook_path(playbook_path):
        return None
        
    # Create a new string to break the taint chain
    # We don't use os.path.realpath() because the path is inside the container
    # Instead, we create a new string by concatenating parts
    path_parts = playbook_path.split('/')
    sanitized_path = '/' + '/'.join(part for part in path_parts if part)
    
    # Ensure the sanitized path still passes validation
    if not validate_playbook_path(sanitized_path):
        log_secure_info(
            "error",
            "Sanitized path failed validation",
            sanitized_path[:8]
        )
        return None
        
    return sanitized_path


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


def validate_command(cmd: list, playbook_path: str, extra_vars_json: str) -> bool:
    """Validate command structure and arguments to prevent injection.
    
    This function implements strict command allowlisting with rigorous validation
    of each command argument to prevent any possibility of command injection.
    
    Args:
        cmd: Command list to validate
        playbook_path: Expected playbook path (already validated)
        extra_vars_json: Expected extra vars JSON (already validated)
        
    Returns:
        True if valid, raises ValueError with detailed message if invalid
    """
    # Define the allowlisted command structure
    # This defines the exact structure and position of each argument
    ALLOWED_CMD_STRUCTURE = [
        {"value": "podman", "fixed": True},
        {"value": "exec", "fixed": True},
        {"value": "-e", "fixed": True},
        {"value": "ANSIBLE_LOG_PATH=", "prefix": True},  # Only the prefix is fixed, value is validated separately
        {"value": "omnia_core", "fixed": True},
        {"value": "ansible-playbook", "fixed": True},
        {"value": None, "fixed": False},  # playbook_path (validated separately)
        {"value": "--extra-vars", "fixed": True},
        {"value": None, "fixed": False},  # extra_vars_json (validated separately)
        {"value": "-v", "fixed": True}
    ]
    
    # 1. Length check - command must have exactly the expected number of arguments
    if len(cmd) != len(ALLOWED_CMD_STRUCTURE):
        log_secure_info(
            "error",
            "Command structure length mismatch",
            f"Expected {len(ALLOWED_CMD_STRUCTURE)}, got {len(cmd)}"
        )
        raise ValueError("Invalid command structure")
    
    # 2. Structure validation - each argument must match the allowlisted structure
    for i, (arg, allowed) in enumerate(zip(cmd, ALLOWED_CMD_STRUCTURE)):
        # Type check - must be string
        if not isinstance(arg, str):
            log_secure_info(
                "error",
                "Non-string argument in command",
                f"Position: {i}"
            )
            raise ValueError("Invalid command argument type")
        
        # Length check - prevent excessively long arguments
        if len(arg) > 4096:  # Reasonable maximum length
            log_secure_info(
                "error",
                "Command argument exceeds maximum allowed length",
                f"Position: {i}, Length: {len(arg)}"
            )
            raise ValueError("Command argument too long")
            
        # Fixed arguments must match exactly
        if allowed.get("fixed", False) and arg != allowed.get("value", ""):
            log_secure_info(
                "error",
                f"Command argument at position {i} does not match allowlist",
                f"Expected '{allowed.get('value', '')}', got '{arg}'"
            )
            raise ValueError(f"Invalid command argument at position {i}")
        
        # Arguments with prefix must start with the specified prefix
        if allowed.get("prefix") and not arg.startswith(allowed.get("value", "")):
            log_secure_info(
                "error",
                f"Command argument at position {i} does not start with required prefix",
                f"Expected prefix '{allowed.get('value', '')}', got '{arg}'"
            )
            raise ValueError(f"Invalid command argument prefix at position {i}")
            
        # Special validation for variable arguments
        if not allowed.get("fixed", True) and i == 6:  # playbook_path position
            if arg != playbook_path:
                log_secure_info(
                    "error",
                    "Playbook path in command does not match validated path"
                )
                raise ValueError("Playbook path mismatch")
                
        if not allowed.get("fixed", True) and i == 8:  # extra_vars_json position
            if arg != extra_vars_json:
                log_secure_info(
                    "error",
                    "Extra vars in command does not match validated vars"
                )
                raise ValueError("Extra vars mismatch")
    
    # 3. Character validation - check for dangerous characters in all arguments
    DANGEROUS_CHARS = ['\n', '\r', '\0', '\t', '\v', '\f', '\a', '\b', '\\', '`', '$', '&', '|', ';', '<', '>', '(', ')', '*', '?', '~', '#']
    
    # Skip validation for specific positions (playbook_path and extra_vars_json)
    SKIP_POSITIONS = [6, 8]  # Position of playbook_path and extra_vars_json
    
    for i, arg in enumerate(cmd):
        # Skip validation for playbook_path and extra_vars_json
        if i in SKIP_POSITIONS:
            continue
            
        for char in DANGEROUS_CHARS:
            if char in arg:
                log_secure_info(
                    "error",
                    "Dangerous character detected in command argument",
                    f"Position: {i}, Character: {repr(char)}"
                )
                raise ValueError("Invalid command argument content")
    
    # 4. Shell binary check - prevent shell execution
    SHELL_BINARIES = ["sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish"]
    for i, arg in enumerate(cmd):
        if arg in SHELL_BINARIES:
            log_secure_info(
                "error",
                "Shell binary detected in command argument",
                f"Position: {i}, Value: {arg}"
            )
            raise ValueError("Shell binary not allowed in command")
    
    # 5. URL check - prevent remote resource fetching
    for i, arg in enumerate(cmd):
        if re.search(r'(https?|ftp|file)://', arg):
            log_secure_info(
                "error",
                "URL detected in command argument",
                f"Position: {i}, Value: {arg[:8]}"
            )
            raise ValueError("URLs not allowed in command arguments")
    
    return True


def validate_extra_vars(extra_vars: Dict[str, Any]) -> bool:
    """Validate extra_vars to prevent injection through JSON.
    
    Args:
        extra_vars: Dictionary of extra variables for Ansible
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(extra_vars, dict):
        log_secure_info(
            "error",
            "extra_vars must be a dictionary"
        )
        return False
        
    # Limit the size of extra_vars to prevent DoS
    if len(json.dumps(extra_vars)) > 10240:  # 10KB limit
        log_secure_info(
            "error",
            "extra_vars exceeds maximum allowed size"
        )
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
        r'\\', # Backslash (potential escaping)
        r'\"', # Quote (potential string termination)
        r'\'', # Single quote (potential string termination)
        r'\{', # Brace expansion
        r'\}', # Brace expansion
        r'\[', # Command substitution
        r'\]'  # Command substitution
    ]
    
    # Whitelist for allowed keys
    allowed_key_pattern = r'^[a-zA-Z0-9_-]+$'
    
    def check_value(value, path=""):
        """Recursively check values for suspicious patterns.
        
        Args:
            value: The value to check
            path: Current path in the nested structure for error reporting
            
        Returns:
            True if valid, False otherwise
        """
        if isinstance(value, str):
            # Limit string length
            if len(value) > 1024:  # 1KB limit per string
                log_secure_info(
                    "error",
                    f"String value at {path} exceeds maximum allowed length"
                )
                return False
                
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, value):
                    log_secure_info(
                        "error",
                        f"Suspicious pattern detected in value at {path}"
                    )
                    return False
                    
        elif isinstance(value, dict):
            # Limit nesting depth
            if path.count('.') > 5:  # Max 5 levels of nesting
                log_secure_info(
                    "error",
                    f"Dictionary at {path} exceeds maximum allowed nesting depth"
                )
                return False
                
            # Limit number of keys
            if len(value) > 50:  # Max 50 keys per dict
                log_secure_info(
                    "error",
                    f"Dictionary at {path} exceeds maximum number of keys"
                )
                return False
                
            for k, v in value.items():
                # Validate key format
                if isinstance(k, str):
                    if not re.match(allowed_key_pattern, k):
                        log_secure_info(
                            "error",
                            f"Invalid key format at {path}: {k[:8]}"
                        )
                        return False
                else:
                    log_secure_info(
                        "error",
                        f"Non-string key at {path}"
                    )
                    return False
                    
                # Recursively check nested value
                if not check_value(v, f"{path}.{k}" if path else k):
                    return False
                    
        elif isinstance(value, list):
            # Limit list length
            if len(value) > 100:  # Max 100 items per list
                log_secure_info(
                    "error",
                    f"List at {path} exceeds maximum length"
                )
                return False
                
            for i, item in enumerate(value):
                if not check_value(item, f"{path}[{i}]"):
                    return False
                    
        elif not isinstance(value, (int, float, bool, type(None))):
            # Only allow primitive types
            log_secure_info(
                "error",
                f"Unsupported value type at {path}: {type(value).__name__}"
            )
            return False
            
        return True
    
    # Check all keys and values
    return check_value(extra_vars)



def parse_request_file(request_path: Path) -> Optional[Dict[str, Any]]:
    """Parse and validate request file.

    Args:
        request_path: Path to the request JSON file

    Returns:
        Parsed request dictionary or None if invalid
    """
    try:
        # Validate file path to prevent directory traversal
        request_path_str = str(request_path)
        if '..' in request_path_str or not request_path_str.startswith('/'):
            log_secure_info(
                "error",
                "Invalid request file path: possible directory traversal",
                request_path_str[:8]
            )
            return None
            
        # Ensure file exists and is a regular file
        if not os.path.isfile(request_path):
            log_secure_info(
                "error",
                "Request path is not a regular file",
                request_path_str[:8]
            )
            return None
            
        with open(request_path, 'r', encoding='utf-8') as f:
            try:
                request_data = json.load(f)
            except json.JSONDecodeError:
                log_secure_info(
                    "error",
                    "Invalid JSON in request file",
                    request_path_str[:8]
                )
                return None
                
        # Validate data type
        if not isinstance(request_data, dict):
            log_secure_info(
                "error",
                "Request data is not a dictionary",
                request_path_str[:8]
            )
            return None

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
            log_secure_info("error", "Invalid job_id format in request", job_id[:8])
            return None
            
        if not validate_stage_name(stage_name):
            log_secure_info("error", "Invalid stage_name format in request", stage_name[:8])
            return None
            
        # Use sanitize_playbook_path instead of validate_playbook_path
        # This returns a sanitized path or None if validation fails
        safe_playbook_path = sanitize_playbook_path(playbook_path)
        if safe_playbook_path is None:
            log_secure_info("error", "Invalid or potentially malicious playbook path in request", playbook_path[:8])
            return None
            
        if not validate_extra_vars(extra_vars):
            log_secure_info("error", "Invalid or potentially malicious extra_vars in request")
            return None

        # Set defaults
        request_data.setdefault("timeout_minutes", DEFAULT_TIMEOUT_MINUTES)
        request_data["extra_vars"] = extra_vars
        request_data.setdefault("correlation_id", job_id)
        
        # Use the sanitized playbook path instead of the original
        request_data["playbook_path"] = safe_playbook_path

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
    # Build command as a list to prevent shell injection
    # Ensure environment variable value is properly sanitized
    log_path_str = str(container_log_file_path)
    
    # Strict validation for log path
    if not log_path_str.startswith('/') or '..' in log_path_str:
        log_secure_info(
            "error",
            "Container log path must be absolute and cannot contain path traversal",
            log_path_str[:8]
        )
        raise ValueError("Invalid container log path")
        
    # Validate log path format using regex (alphanumeric, underscore, hyphen, forward slash, and dots)
    if not re.match(r'^[a-zA-Z0-9_\-/.]+$', log_path_str):
        log_secure_info(
            "error",
            "Container log path contains invalid characters",
            log_path_str[:8]
        )
        raise ValueError("Invalid container log path format")
    
    # Build command as a list to prevent shell injection
    # Sanitize and validate extra_vars to prevent injection through JSON
    if not isinstance(extra_vars, dict):
        log_secure_info(
            "error",
            "Extra vars must be a dictionary"
        )
        raise ValueError("Invalid extra_vars format")
    
    # Deep validation of extra_vars structure and content
    if not validate_extra_vars(extra_vars):
        log_secure_info(
            "error",
            "Invalid or potentially malicious content in extra_vars"
        )
        raise ValueError("Security validation failed for extra_vars")
        
    # Convert extra_vars to JSON string with strict validation
    try:
        extra_vars_json = json.dumps(extra_vars) if extra_vars else "{}"
    except (TypeError, ValueError) as e:
        log_secure_info(
            "error",
            "Failed to serialize extra_vars to JSON"
        )
        raise ValueError("Invalid extra_vars content")
    
    # Verify the JSON string is valid and can be parsed back
    try:
        json.loads(extra_vars_json)
    except json.JSONDecodeError:
        log_secure_info(
            "error",
            "Generated extra_vars JSON is invalid"
        )
        raise ValueError("Invalid extra_vars JSON format")
    
    # Additional safety: Ensure playbook_path has no spaces (prevents argument splitting)
    if ' ' in playbook_path:
        log_secure_info(
            "error",
            "Playbook path contains spaces",
            playbook_path[:8]
        )
        raise ValueError("Invalid playbook path format")
    
    # Command structure will be validated by the validate_command function
    
    # Build command as a list with all validated components
    # Each element is a separate argument - no shell interpretation possible
    cmd = [
        "podman", "exec",
        "-e", f"ANSIBLE_LOG_PATH={log_path_str}",
        "omnia_core",
        "ansible-playbook",
        playbook_path,  # Validated: no spaces, whitelisted directory
        "--extra-vars", extra_vars_json,  # Validated: proper JSON format
        "-v"
    ]
    
    # Use the dedicated command validation function to perform comprehensive validation
    # This includes structure validation, argument validation, and security checks
    try:
        validate_command(cmd, playbook_path, extra_vars_json)
    except ValueError as e:
        log_secure_info(
            "error",
            "Command validation failed",
            str(e)
        )
        raise ValueError(f"Command validation failed: {e}")

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
        # Create a sanitized environment with only necessary variables
        safe_env = {
            # Include only essential environment variables
            'PATH': os.environ.get('PATH', ''),
            'HOME': os.environ.get('HOME', ''),
            'USER': os.environ.get('USER', ''),
            'LANG': os.environ.get('LANG', 'en_US.UTF-8'),
            'ANSIBLE_LOG_PATH': log_path_str
        }
        
        # Log the command being executed (without sensitive details)
        log_secure_info(
            "debug",
            "Executing command",
            f"podman exec omnia_core ansible-playbook [playbook]"
        )
        
        # Execute with explicit shell=False and validated arguments
        result = subprocess.run(
            cmd,
            capture_output=False,  # Don't capture to avoid duplication with ANSIBLE_LOG_PATH
            timeout=timeout_seconds,
            check=False,
            env=safe_env,  # Pass minimal sanitized environment
            shell=False,  # Explicitly set shell=False to prevent injection
            text=False,   # Don't interpret output as text to prevent encoding issues
            start_new_session=True  # Isolate the process from the parent session
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
