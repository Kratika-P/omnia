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

"""Completion callback handlers for local repository stage."""

import logging
from typing import Protocol

from build_stream.core.jobs.repositories import JobRepository, StageRepository
from build_stream.core.jobs.value_objects import JobId, StageName, StageType
from build_stream.core.localrepo.entities import PlaybookResult

logger = logging.getLogger(__name__)


class StageCompletionCallback(Protocol):
    """Protocol for stage completion notification."""

    def on_stage_completed(self, result: PlaybookResult) -> None:
        """Handle stage completion notification.

        Args:
            result: Playbook execution result.
        """
        ...


class LocalRepoStageCallback:
    """Callback handler for local repository stage completion.

    Updates job and stage state based on playbook execution results.
    Invoked by the result poller when a result file is processed.
    """

    def __init__(
        self,
        job_repo: JobRepository,
        stage_repo: StageRepository,
    ) -> None:
        """Initialize callback with repository dependencies.

        Args:
            job_repo: Job repository for state updates.
            stage_repo: Stage repository for state updates.
        """
        self._job_repo = job_repo
        self._stage_repo = stage_repo

    def on_stage_completed(self, result: PlaybookResult) -> None:
        """Handle stage completion by updating job and stage state.

        Args:
            result: Playbook execution result from OIM Core.
        """
        job_id = JobId(result.job_id)
        stage_name = StageName(StageType.CREATE_LOCAL_REPOSITORY.value)

        stage = self._stage_repo.find_by_job_and_name(job_id, stage_name)
        if stage is None:
            logger.error(
                "Stage not found for callback: job_id=%s, stage=%s",
                result.job_id,
                stage_name,
            )
            return

        if result.is_success:
            stage.complete()
            logger.info(
                "Stage completed successfully: job_id=%s, stage=%s",
                result.job_id,
                stage_name,
            )
        else:
            error_code = result.error_code or "PLAYBOOK_FAILED"
            error_summary = result.error_summary or result.stderr or "Unknown error"
            stage.fail(error_code=error_code, error_summary=error_summary)
            logger.warning(
                "Stage failed: job_id=%s, stage=%s, error=%s",
                result.job_id,
                stage_name,
                error_code,
            )

        self._stage_repo.save(stage)
