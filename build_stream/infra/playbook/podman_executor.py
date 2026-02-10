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

"""Infrastructure adapter for executing playbooks via podman."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PodmanExecutorAdapter:
    """Infrastructure adapter for executing playbooks via podman exec.
    
    This adapter handles the technical details of executing playbooks
    in the OIM Core container via podman exec commands.
    """

    def __init__(self, container_name: str = "omnia_core") -> None:
        """Initialize podman executor adapter.
        
        Args:
            container_name: Name of the container to execute playbooks in.
        """
        self.container_name = container_name
        self.running_tasks: Dict[str, asyncio.Task] = {}

    async def execute(
        self,
        job_id: str,
        playbook_path: str,
        extra_vars: Optional[dict],
        timeout_minutes: int,
        correlation_id: Optional[str],
    ) -> asyncio.Task:
        """Execute playbook via podman exec.
        
        Args:
            job_id: Job identifier
            playbook_path: Path to the playbook file
            extra_vars: Extra variables to pass to the playbook
            timeout_minutes: Execution timeout in minutes
            correlation_id: Request correlation ID
            
        Returns:
            Task that will complete when execution is done
        """
        # Create log directory
        log_dir = Path(f"/opt/omnia/log/build_stream/jobs/{job_id}")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "create-local-repository_playbook.log"

        # Build command
        cmd = ["podman", "exec", self.container_name, "ansible-playbook", str(playbook_path)]
        if extra_vars:
            cmd.extend(["--extra-vars", json.dumps(extra_vars.to_dict())])
        cmd.append("-v")  # Verbose output

        logger.debug("Executing command: %s", " ".join(cmd))

        # Create and register task
        task = asyncio.create_task(
            self._run_playbook(cmd, job_id, timeout_minutes, log_path, correlation_id)
        )
        self.running_tasks[job_id] = task

        # Return task that will complete when playbook is done
        return task

    async def _run_playbook(
        self,
        cmd: list,
        job_id: str,
        timeout_minutes: int,
        log_path: Path,
        correlation_id: Optional[str],
    ) -> Dict:
        """Run playbook and handle results.
        
        Args:
            cmd: Command to execute
            job_id: Job identifier
            timeout_minutes: Execution timeout in minutes
            log_path: Path to log file
            correlation_id: Request correlation ID
            
        Returns:
            Dictionary containing execution results
        """
        started_at = datetime.now(timezone.utc)

        try:
            # Execute with timeout
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout_minutes * 60
                )

                completed_at = datetime.now(timezone.utc)
                duration_seconds = (completed_at - started_at).total_seconds()

                # Copy log file from container
                await self._copy_log_file(job_id, log_path)

                # Return result
                return {
                    "job_id": job_id,
                    "status": "success" if proc.returncode == 0 else "failed",
                    "exit_code": proc.returncode,
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode(),
                    "started_at": started_at.isoformat(),
                    "completed_at": completed_at.isoformat(),
                    "duration_seconds": int(duration_seconds),
                    "log_file": str(log_path) if log_path.exists() else None,
                    "correlation_id": correlation_id,
                }

            except asyncio.TimeoutError:
                # Kill process on timeout
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()

                completed_at = datetime.now(timezone.utc)
                duration_seconds = (completed_at - started_at).total_seconds()

                # Try to copy log even after timeout
                await self._copy_log_file(job_id, log_path)

                logger.error(
                    "Playbook execution timed out: job_id=%s, timeout=%dm",
                    job_id,
                    timeout_minutes,
                )

                return {
                    "job_id": job_id,
                    "status": "failed",
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Playbook execution timed out after {timeout_minutes} minutes",
                    "started_at": started_at.isoformat(),
                    "completed_at": completed_at.isoformat(),
                    "duration_seconds": int(duration_seconds),
                    "error_code": "PLAYBOOK_TIMEOUT",
                    "error_summary": f"Execution exceeded timeout of {timeout_minutes} minutes",
                    "log_file": str(log_path) if log_path.exists() else None,
                    "correlation_id": correlation_id,
                }

        except Exception as exc:  # pylint: disable=broad-except
            completed_at = datetime.now(timezone.utc)
            duration_seconds = (completed_at - started_at).total_seconds()

            # Try to copy log even after error
            await self._copy_log_file(job_id, log_path)

            logger.exception("Unexpected error executing playbook: job_id=%s", job_id)

            return {
                "job_id": job_id,
                "status": "failed",
                "exit_code": -1,
                "stdout": "",
                "stderr": str(exc),
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "duration_seconds": int(duration_seconds),
                "error_code": "SYSTEM_ERROR",
                "error_summary": f"System error during execution: {str(exc)}",
                "log_file": str(log_path) if log_path.exists() else None,
                "correlation_id": correlation_id,
            }

        finally:
            # Clean up task reference
            if job_id in self.running_tasks:
                del self.running_tasks[job_id]

    async def _copy_log_file(self, job_id: str, log_path: Path) -> bool:
        """Copy log file from container to job-specific location.
        
        Args:
            job_id: Job identifier
            log_path: Destination path for log file
            
        Returns:
            True if successful, False otherwise
        """
        container_log_path = "/opt/omnia/log/core/playbooks/utils.log"

        try:
            cp_cmd = [
                "podman",
                "cp",
                f"{self.container_name}:{container_log_path}",
                str(log_path),
            ]

            cp_proc = await asyncio.create_subprocess_exec(
                *cp_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            await cp_proc.wait()

            if cp_proc.returncode == 0:
                logger.info("Copied playbook log to %s", log_path)
                return True

            logger.warning("Failed to copy playbook log for job %s", job_id)
            return False

        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Error copying playbook log: %s", exc)
            return False

    async def get_log(self, job_id: str, stage_name: str) -> Optional[str]:
        """Get execution log for a specific job and stage.
        
        Args:
            job_id: Job identifier
            stage_name: Stage name
            
        Returns:
            Log file path if available, None otherwise
        """
        log_path = Path(f"/opt/omnia/log/build_stream/jobs/{job_id}/{stage_name}_playbook.log")
        if log_path.exists():
            return str(log_path)
        return None
