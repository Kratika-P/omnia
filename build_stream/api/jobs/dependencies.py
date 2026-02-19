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

"""FastAPI dependency providers for Jobs API.

In production, we need request-scoped sessions so all repositories
share the same DB session within a single request. The container
cannot provide this, so we handle it here at the FastAPI dependency level.
"""

import os
from typing import Generator, Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from core.jobs.value_objects import ClientId, CorrelationId
from infra.id_generator import JobUUIDGenerator
from orchestrator.jobs.use_cases import CreateJobUseCase

_ENV = os.getenv("ENV", "dev")


def _get_container():
    """Lazy import of container to avoid circular imports."""
    from container import container  # pylint: disable=import-outside-toplevel
    return container


# ------------------------------------------------------------------
# Request-scoped database session (prod only)
# ------------------------------------------------------------------
def get_db_session() -> Generator[Session, None, None]:
    """Yield a single DB session per request for shared transaction context."""
    if _ENV != "prod":
        yield None  # type: ignore[misc]
        return
    
    from infra.db.session import SessionLocal  # pylint: disable=import-outside-toplevel
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ------------------------------------------------------------------
# Repository & use-case providers
# ------------------------------------------------------------------
def get_id_generator() -> JobUUIDGenerator:
    """Provide job ID generator."""
    return _get_container().job_id_generator()


def get_create_job_use_case(
    db_session: Session = Depends(get_db_session),
) -> CreateJobUseCase:
    """Provide create-job use case with shared session in prod."""
    if _ENV == "prod":
        from infra.db.repositories import (  # pylint: disable=import-outside-toplevel
            SqlJobRepository,
            SqlStageRepository,
            SqlIdempotencyRepository,
            SqlAuditEventRepository,
        )
        container = _get_container()
        return CreateJobUseCase(
            job_repo=SqlJobRepository(session=db_session),
            stage_repo=SqlStageRepository(session=db_session),
            idempotency_repo=SqlIdempotencyRepository(session=db_session),
            audit_repo=SqlAuditEventRepository(session=db_session),
            job_id_generator=container.job_id_generator(),
            uuid_generator=container.uuid_generator(),
        )
    return _get_container().create_job_use_case()


def get_job_repo(
    db_session: Session = Depends(get_db_session),
):
    """Provide job repository with shared session in prod."""
    if _ENV == "prod":
        from infra.db.repositories import SqlJobRepository  # pylint: disable=import-outside-toplevel
        return SqlJobRepository(session=db_session)
    return _get_container().job_repository()


def get_stage_repo(
    db_session: Session = Depends(get_db_session),
):
    """Provide stage repository with shared session in prod."""
    if _ENV == "prod":
        from infra.db.repositories import SqlStageRepository  # pylint: disable=import-outside-toplevel
        return SqlStageRepository(session=db_session)
    return _get_container().stage_repository()


def get_client_id(token_data: dict) -> ClientId:
    """Extract ClientId from verified token data.
    
    Note: token_data comes from verify_token dependency injected in the route.
    This function is called after verify_token has already validated the JWT.
    
    Args:
        token_data: Token data dict from verify_token dependency.
        
    Returns:
        ClientId extracted from token.
    """
    return ClientId(token_data["client_id"])


def get_correlation_id(
    x_correlation_id: Optional[str] = Header(
        default=None,
        alias="X-Correlation-Id",
        description="Request tracing ID",
    ),
) -> CorrelationId:
    """Return provided correlation ID or generate one."""
    generator = _get_container().uuid_generator()
    if x_correlation_id:
        try:
            correlation_id = CorrelationId(x_correlation_id)
            return correlation_id
        except ValueError:
            pass

    generated_id = generator.generate()
    return CorrelationId(str(generated_id))


def get_idempotency_key(
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        description="Client-provided deduplication token",
    ),
) -> str:
    """Validate and return the Idempotency-Key header."""
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Idempotency-Key must be provided",
        )

    key = idempotency_key.strip()

    if len(key) > 255:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Idempotency-Key length must be <= 255 characters",
        )

    return key
