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

This infrastructure service monitors the NFS result queue and invokes
the orchestrator callback when results are available.
"""

import asyncio
import logging
from typing import Protocol

from core.localrepo.entities import PlaybookResult
from core.localrepo.services import PlaybookQueueResultService

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL_SECONDS = 5


class ResultPollerCallback(Protocol):
    """Protocol for result poller callbacks.
    
    Implemented by orchestrator layer callbacks.
    """

    def on_stage_completed(self, result: PlaybookResult) -> None:
        """Handle stage completion notification.

        Args:
            result: Playbook execution result.
        """
        ...


class ResultPoller:
    """Background asyncio task that polls for playbook execution results.

    This infrastructure service runs as a background task within the
    FastAPI application lifecycle. It polls the NFS result queue at
    configurable intervals and invokes the orchestrator callback for
    each result.
    
    Architecture:
        Infrastructure Layer (this class)
            ↓ polls via
        Core Layer (PlaybookQueueResultService)
            ↓ invokes callback
        Orchestrator Layer (LocalRepoResultPoller)
            ↓ updates
        Domain Layer (Stage entity)
    """

    def __init__(
        self,
        result_service: PlaybookQueueResultService,
        callback: ResultPollerCallback,
        poll_interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> None:
        """Initialize result poller.

        Args:
            result_service: Core service for polling result queue.
            callback: Orchestrator callback to invoke for each result.
            poll_interval: Polling interval in seconds.
        """
        self._result_service = result_service
        self._callback = callback
        self._poll_interval = poll_interval
        self._running = False
        self._task: asyncio.Task = None
        self._processed_count = 0

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
        logger.info(
            "Result poller stopped. Processed %d results total",
            self._processed_count,
        )

    async def _poll_loop(self) -> None:
        """Main polling loop that runs as a background task."""
        while self._running:
            try:
                # Run blocking I/O in executor to avoid blocking event loop
                processed = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._result_service.poll_results,
                    self._callback.on_stage_completed,
                )
                if processed > 0:
                    self._processed_count += processed
                    logger.info(
                        "Processed %d result(s). Total: %d",
                        processed,
                        self._processed_count,
                    )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error(
                    "Error in result poller: %s",
                    exc,
                    exc_info=True,
                )

            await asyncio.sleep(self._poll_interval)

    @property
    def is_running(self) -> bool:
        """Check if the poller is currently running."""
        return self._running

    @property
    def processed_count(self) -> int:
        """Get the total number of processed results."""
        return self._processed_count
