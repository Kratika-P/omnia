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

"""Background asyncio polling service for playbook results.

Monitors the NFS result queue and invokes the orchestrator callback
when results are available.
"""

import asyncio
import logging

from build_stream.core.localrepo.services import PlaybookQueueResultService
from build_stream.orchestrator.local_repo.callbacks import StageCompletionCallback

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL_SECONDS = 5


class ResultPoller:
    """Background asyncio task that polls for playbook execution results.

    Runs as a background task within the FastAPI application lifecycle.
    Polls the NFS result queue at configurable intervals and invokes
    the stage completion callback for each result.
    """

    def __init__(
        self,
        result_service: PlaybookQueueResultService,
        callback: StageCompletionCallback,
        poll_interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> None:
        """Initialize result poller.

        Args:
            result_service: Service for polling result queue.
            callback: Callback to invoke for each result.
            poll_interval: Polling interval in seconds.
        """
        self._result_service = result_service
        self._callback = callback
        self._poll_interval = poll_interval
        self._running = False
        self._task: asyncio.Task = None

    async def start(self) -> None:
        """Start the background polling task."""
        if self._running:
            logger.warning("Result poller is already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info(
            "Result poller started with %d second interval",
            self._poll_interval,
        )

    async def stop(self) -> None:
        """Stop the background polling task."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Result poller stopped")

    async def _poll_loop(self) -> None:
        """Main polling loop that runs as a background task."""
        while self._running:
            try:
                processed = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._result_service.poll_results,
                    self._callback.on_stage_completed,
                )
                if processed > 0:
                    logger.info("Processed %d result(s)", processed)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Error in result poller: %s", exc)

            await asyncio.sleep(self._poll_interval)

    @property
    def is_running(self) -> bool:
        """Check if the poller is currently running."""
        return self._running
