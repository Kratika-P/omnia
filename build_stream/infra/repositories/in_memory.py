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

""" This file contains in-memory implementations of the job repository.
    It is used in testing and development."""

from typing import Dict, List, Optional

from core.jobs.entities import Job, Stage, IdempotencyRecord, AuditEvent
from core.jobs.value_objects import JobId, IdempotencyKey, StageName

class InMemoryJobRepository:
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}

    def save(self, job: Job) -> None:
        self._jobs[str(job.job_id)] = job

    def find_by_id(self, job_id: JobId) -> Optional[Job]:
        return self._jobs.get(str(job_id))

    def exists(self, job_id: JobId) -> bool:
        return str(job_id) in self._jobs


class InMemoryStageRepository:
    def __init__(self) -> None:
        self._stages: Dict[str, List[Stage]] = {}

    def save(self, stage: Stage) -> None:
        job_key = str(stage.job_id)
        if job_key not in self._stages:
            self._stages[job_key] = []
        
        existing = self.find_by_job_and_name(stage.job_id, stage.stage_name)
        if existing:
            stages = self._stages[job_key]
            self._stages[job_key] = [s for s in stages if str(s.stage_name) != str(stage.stage_name)]
        
        self._stages[job_key].append(stage)

    def save_all(self, stages: List[Stage]) -> None:
        for stage in stages:
            self.save(stage)

    def find_by_job_and_name(self, job_id: JobId, stage_name: StageName) -> Optional[Stage]:
        job_key = str(job_id)
        if job_key not in self._stages:
            return None
        
        for stage in self._stages[job_key]:
            if str(stage.stage_name) == str(stage_name):
                return stage
        return None

    def find_all_by_job(self, job_id: JobId) -> List[Stage]:
        return self._stages.get(str(job_id), [])


class InMemoryIdempotencyRepository:
    def __init__(self) -> None:
        self._records: Dict[str, IdempotencyRecord] = {}

    def save(self, record: IdempotencyRecord) -> None:
        self._records[str(record.idempotency_key)] = record

    def find_by_key(self, key: IdempotencyKey) -> Optional[IdempotencyRecord]:
        return self._records.get(str(key))


class InMemoryAuditEventRepository:
    def __init__(self) -> None:
        self._events: Dict[str, List[AuditEvent]] = {}

    def save(self, event: AuditEvent) -> None:
        job_key = str(event.job_id)
        if job_key not in self._events:
            self._events[job_key] = []
        self._events[job_key].append(event)

    def find_by_job(self, job_id: JobId) -> List[AuditEvent]:
        return self._events.get(str(job_id), [])
