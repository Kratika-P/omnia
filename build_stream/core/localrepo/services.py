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

"""Domain services for Local Repository module."""

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Callable, Optional, Protocol

from api.logging_utils import log_secure_info

from core.localrepo.entities import PlaybookRequest, PlaybookResult
from core.localrepo.exceptions import (
    InputDirectoryInvalidError,
    InputFilesMissingError,
    QueueUnavailableError,
)
from core.localrepo.repositories import (
    InputDirectoryRepository,
    PlaybookQueueRequestRepository,
    PlaybookQueueResultRepository,
)

logger = logging.getLogger(__name__)


class PlaybookExecutorPort(Protocol):
    """Port for executing playbooks asynchronously.

    This protocol defines the interface that infrastructure adapters
    must implement to execute playbooks.
    """

    async def execute(
        self,
        job_id: str,
        playbook_path: str,
        extra_vars: Optional[dict],
        timeout_minutes: int,
        correlation_id: Optional[str],
    ) -> asyncio.Task:
        """Execute playbook asynchronously.

        Args:
            job_id: Job identifier
            playbook_path: Path to the playbook file
            extra_vars: Extra variables to pass to the playbook
            timeout_minutes: Execution timeout in minutes
            correlation_id: Request correlation ID

        Returns:
            Task that will complete when execution is done
        """

    async def get_log(self, job_id: str, stage_name: str) -> Optional[str]:
        """Get execution log for a specific job and stage.

        Args:
            job_id: Job identifier
            stage_name: Stage name

        Returns:
            Log file path if available, None otherwise
        """


class InputFileService:
    """Service for validating and preparing input files before playbook execution.

    Ensures that required input files exist and are properly staged
    in the destination directory expected by the playbook.
    """

    def __init__(self, input_repo: InputDirectoryRepository) -> None:
        """Initialize input file service.

        Args:
            input_repo: Input directory repository implementation.
        """
        self._input_repo = input_repo

    def prepare_playbook_input(
        self,
        job_id: str,
        correlation_id: str = "",
    ) -> bool:
        """Prepare input files for playbook execution.

        Validates source input files exist, then copies them to the
        destination directory expected by the playbook.

        Args:
            job_id: Job identifier to prepare input for.
            correlation_id: Request correlation ID for tracing.

        Returns:
            True if input preparation was successful.

        Raises:
            InputFilesMissingError: If source input files not found.
            InputDirectoryInvalidError: If source directory is invalid.
        """
        source_path = self._input_repo.get_source_input_repository_path(job_id)
        destination_path = self._input_repo.get_destination_input_repository_path()

        if not self._input_repo.validate_input_directory(source_path):
            logger.error(
                "Input files not found for job %s at %s, correlation_id=%s",
                job_id,
                source_path,
                correlation_id,
            )
            raise InputFilesMissingError(
                job_id=job_id,
                input_path=str(source_path),
                correlation_id=correlation_id,
            )

        try:
            destination_path.mkdir(parents=True, exist_ok=True)
            for item in source_path.iterdir():
                dest_item = destination_path / item.name
                if item.is_dir():
                    shutil.copytree(str(item), str(dest_item), dirs_exist_ok=True)
                else:
                    shutil.copy2(str(item), str(dest_item))

            log_secure_info(
                "info",
                f"Input files prepared for job {job_id}",
                str(correlation_id),
            )
            return True

        except OSError as exc:
            log_secure_info(
                "error",
                f"Failed to prepare input files for job {job_id}",
                str(correlation_id),
            )
            raise InputDirectoryInvalidError(
                job_id=job_id,
                input_path=str(source_path),
                reason=str(exc),
                correlation_id=correlation_id,
            ) from exc


class PlaybookQueueRequestService:
    """Service for managing playbook request queue operations.

    Handles writing playbook requests to the NFS shared volume
    for consumption by the OIM Core watcher service.
    """

    def __init__(self, request_repo: PlaybookQueueRequestRepository) -> None:
        """Initialize request queue service.

        Args:
            request_repo: Playbook queue request repository implementation.
        """
        self._request_repo = request_repo

    def submit_request(
        self,
        request: PlaybookRequest,
        correlation_id: str = "",
    ) -> Path:
        """Submit a playbook request to the NFS queue.

        Args:
            request: Playbook request to submit.
            correlation_id: Request correlation ID for tracing.

        Returns:
            Path to the written request file.

        Raises:
            QueueUnavailableError: If the queue is not accessible.
        """
        if not self._request_repo.is_available():
            raise QueueUnavailableError(
                queue_path="requests",
                reason="Request queue directory is not accessible",
                correlation_id=correlation_id,
            )

        request_path = self._request_repo.write_request(request)
        log_secure_info(
            "info",
            f"Request submitted for job {request.job_id}",
            str(request.correlation_id),
        )
        return request_path


class PlaybookQueueResultService:
    """Service for polling and processing playbook execution results.

    Monitors the NFS result queue and invokes callbacks when
    results are available.
    """

    def __init__(self, result_repo: PlaybookQueueResultRepository) -> None:
        """Initialize result queue service.

        Args:
            result_repo: Playbook queue result repository implementation.
        """
        self._result_repo = result_repo

    def poll_results(
        self,
        callback: Callable[[PlaybookResult], None],
    ) -> int:
        """Poll for new results and invoke callback for each.

        Args:
            callback: Function to call with each new result.

        Returns:
            Number of results processed.
        """
        if not self._result_repo.is_available():
            logger.warning("Result queue directory is not accessible")
            return 0

        result_files = self._result_repo.get_unprocessed_results()
        processed_count = 0

        for result_path in result_files:
            try:
                result = self._result_repo.read_result(result_path)
                callback(result)
                self._result_repo.archive_result(result_path)
                processed_count += 1
                log_secure_info(
                    "info",
                    f"Processed result for job {result.job_id}",
                    str(result.correlation_id),
                )
            except (ValueError, KeyError) as exc:
                log_secure_info(
                    "error",
                    "Failed to parse result file",
                )
            except Exception as exc:  # pylint: disable=broad-except
                log_secure_info(
                    "error",
                    "Failed to process result file",
                )

        return processed_count


class PlaybookExecutionService:
    """Core service for executing playbooks asynchronously.

    This service contains the business logic for playbook execution
    and delegates the technical implementation to infrastructure adapters.
    """

    def __init__(self, playbook_executor_adapter: PlaybookExecutorPort) -> None:
        """Initialize playbook execution service.

        Args:
            playbook_executor_adapter: Infrastructure adapter for playbook execution.
        """
        self._executor_adapter = playbook_executor_adapter

    async def execute_playbook(self, execution_request: PlaybookRequest) -> asyncio.Task:
        """Execute playbook asynchronously.

        Args:
            execution_request: Domain entity containing execution parameters

        Returns:
            Task that will complete when execution is done

        Raises:
            ValueError: If the execution request is invalid
        """
        # Domain validation logic
        if not execution_request.job_id:
            raise ValueError("Job ID is required for playbook execution")

        if not execution_request.playbook_path:
            raise ValueError("Playbook path is required for playbook execution")

        logger.info(
            "Executing playbook for job_id=%s, correlation_id=%s",
            execution_request.job_id,
            execution_request.correlation_id,
        )

        # Map domain entity to adapter parameters
        return await self._executor_adapter.execute(
            job_id=execution_request.job_id,
            playbook_path=execution_request.playbook_path,
            extra_vars=execution_request.extra_vars,
            timeout_minutes=execution_request.timeout.minutes,
            correlation_id=execution_request.correlation_id,
        )

    async def get_execution_log(self, job_id: str, stage_name: str) -> Optional[str]:
        """Get execution log for a specific job and stage.

        Args:
            job_id: Job identifier
            stage_name: Stage name

        Returns:
            Log file path if available, None otherwise
        """
        return await self._executor_adapter.get_log(job_id, stage_name)
