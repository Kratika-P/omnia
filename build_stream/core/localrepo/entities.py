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

"""Domain entities for Local Repository module."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from build_stream.core.jobs.value_objects import CorrelationId, JobId

from .value_objects import ExecutionTimeout, ExtraVars, PlaybookPath


@dataclass(frozen=True)
class PlaybookRequest:
    """Immutable value object representing a playbook execution request.

    Written to the NFS playbook queue for OIM Core consumption.

    Attributes:
        job_id: Parent job identifier.
        stage_name: Stage identifier (create-local-repository).
        playbook_path: Validated path to the playbook.
        extra_vars: Ansible extra variables.
        correlation_id: Request tracing identifier.
        timeout: Execution timeout configuration.
        submitted_at: Request submission timestamp.
        request_id: Unique request identifier.
    """

    job_id: str
    stage_name: str
    playbook_path: PlaybookPath
    extra_vars: ExtraVars
    correlation_id: str
    timeout: ExecutionTimeout
    submitted_at: str
    request_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize request to dictionary for JSON file writing."""
        return {
            "job_id": self.job_id,
            "stage_name": self.stage_name,
            "playbook_path": str(self.playbook_path),
            "extra_vars": self.extra_vars.to_dict(),
            "correlation_id": self.correlation_id,
            "timeout_minutes": self.timeout.minutes,
            "submitted_at": self.submitted_at,
            "request_id": self.request_id,
        }

    def generate_filename(self) -> str:
        """Generate request file name following naming convention.

        Returns:
            Filename: {job_id}_{stage_name}_{timestamp}.json
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"{self.job_id}_{self.stage_name}_{timestamp}.json"


@dataclass(frozen=True)
class PlaybookResult:
    """Immutable value object representing a playbook execution result.

    Read from the NFS playbook queue results directory.

    Attributes:
        job_id: Parent job identifier.
        stage_name: Stage identifier.
        request_id: Original request identifier.
        status: Execution status (success or failed).
        exit_code: Process exit code.
        stdout: Captured standard output.
        stderr: Captured standard error.
        started_at: Execution start timestamp.
        completed_at: Execution completion timestamp.
        duration_seconds: Total execution duration.
        error_code: Error classification code (if failed).
        error_summary: Human-readable error description (if failed).
        timestamp: Result creation timestamp.
    """

    job_id: str
    stage_name: str
    request_id: str
    status: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: int = 0
    error_code: Optional[str] = None
    error_summary: Optional[str] = None
    timestamp: str = ""

    @property
    def is_success(self) -> bool:
        """Check if execution was successful."""
        return self.status == "success"

    @property
    def is_failed(self) -> bool:
        """Check if execution failed."""
        return self.status == "failed"

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "PlaybookResult":
        """Deserialize result from dictionary (parsed from JSON file).

        Args:
            data: Dictionary parsed from result JSON file.

        Returns:
            PlaybookResult instance.

        Raises:
            KeyError: If required fields are missing.
            ValueError: If field values are invalid.
        """
        return PlaybookResult(
            job_id=data["job_id"],
            stage_name=data["stage_name"],
            request_id=data.get("request_id", ""),
            status=data["status"],
            exit_code=data.get("exit_code", -1),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            duration_seconds=data.get("duration_seconds", 0),
            error_code=data.get("error_code"),
            error_summary=data.get("error_summary"),
            timestamp=data.get("timestamp", ""),
        )


@dataclass
class LocalRepoExecution:
    """Aggregate root for local repository playbook execution.

    Tracks the lifecycle of a single playbook execution request
    from submission through completion.

    Attributes:
        job_id: Parent job identifier.
        correlation_id: Request tracing identifier.
        request: The playbook request (set after submission).
        result: The playbook result (set after completion).
        submitted_at: Submission timestamp.
        completed_at: Completion timestamp.
    """

    job_id: JobId
    correlation_id: CorrelationId
    request: Optional[PlaybookRequest] = None
    result: Optional[PlaybookResult] = None
    submitted_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def submit(self, request: PlaybookRequest) -> None:
        """Record that a playbook request has been submitted.

        Args:
            request: The submitted playbook request.
        """
        self.request = request
        self.submitted_at = datetime.now(timezone.utc)

    def complete(self, result: PlaybookResult) -> None:
        """Record that playbook execution has completed.

        Args:
            result: The playbook execution result.
        """
        self.result = result
        self.completed_at = datetime.now(timezone.utc)

    @property
    def is_submitted(self) -> bool:
        """Check if request has been submitted."""
        return self.request is not None

    @property
    def is_completed(self) -> bool:
        """Check if execution has completed."""
        return self.result is not None

    @property
    def is_successful(self) -> bool:
        """Check if execution completed successfully."""
        return self.is_completed and self.result.is_success
