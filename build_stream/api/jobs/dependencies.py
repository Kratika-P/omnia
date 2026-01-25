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

from typing import Optional

from dependency_injector.wiring import Provide, inject
from fastapi import Depends, Header, HTTPException, status

from core.jobs.value_objects import ClientId, CorrelationId
from container import Container
from infra.id_generator import UUIDv7Generator
from infra.repositories import InMemoryJobRepository, InMemoryStageRepository
from orchestrator.jobs.use_cases import CreateJobUseCase


@inject
def get_id_generator(
    generator: UUIDv7Generator = Depends(Provide[Container.job_id_generator]),
) -> UUIDv7Generator:
    return generator


@inject
def get_create_job_use_case(
    use_case: CreateJobUseCase = Depends(Provide[Container.create_job_use_case]),
) -> CreateJobUseCase:
    return use_case


@inject
def get_job_repo(
    repo: InMemoryJobRepository = Depends(Provide[Container.job_repository]),
) -> InMemoryJobRepository:
    return repo


@inject
def get_stage_repo(
    repo: InMemoryStageRepository = Depends(Provide[Container.stage_repository]),
) -> InMemoryStageRepository:
    return repo


def get_client_id(
    authorization: str = Header(..., description="Bearer token for authentication"),
) -> ClientId:
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
        )
    
    token = authorization[7:]
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )
    
    # TODO: Implement actual token validation and client_id extraction
    # For now, use token as client_id placeholder
    try:
        return ClientId(token[:128] if len(token) > 128 else token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        ) from e


@inject
def get_correlation_id(
    x_correlation_id: Optional[str] = Header(
        default=None,
        alias="X-Correlation-Id",
        description="Request tracing ID",
    ),
    generator: UUIDv7Generator = Depends(Provide[Container.job_id_generator]),
) -> CorrelationId:
    if x_correlation_id:
        try:
            correlation_id = CorrelationId(x_correlation_id)
            return correlation_id
        except ValueError:
            pass
    
    generated_id = generator.generate()
    return CorrelationId(generated_id.value)


def get_idempotency_key(
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        description="Client-provided deduplication token",
    ),
) -> str:
    if not idempotency_key or len(idempotency_key) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Idempotency-Key must be 1-255 characters",
        )
    return idempotency_key
