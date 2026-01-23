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

"""FastAPI routes for OAuth2 authentication endpoints."""

import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .schemas import (
    AuthErrorResponse,
    ClientRegistrationRequest,
    ClientRegistrationResponse,
)
from .service import (
    AuthenticationError,
    AuthService,
    ClientExistsError,
    MaxClientsReachedError,
    RegistrationDisabledError,
)
from .vault_client import VaultError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])

security = HTTPBasic()

_auth_service = AuthService()


def _verify_basic_auth(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)],
) -> HTTPBasicCredentials:
    """Verify Basic Authentication credentials for registration.

    Args:
        credentials: HTTP Basic Auth credentials from request.

    Returns:
        Validated credentials.

    Raises:
        HTTPException: If authentication fails.
    """
    try:
        _auth_service.verify_registration_credentials(
            credentials.username,
            credentials.password,
        )
        return credentials
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_credentials", "error_description": "Invalid Basic Auth credentials"},
            headers={"WWW-Authenticate": "Basic"},
        ) from None
    except RegistrationDisabledError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "service_unavailable", "error_description": "Registration service is not available"},
        ) from None


@router.post(
    "/register",
    response_model=ClientRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new OAuth client",
    description="Register a new OAuth client using HTTP Basic Authentication. "
    "Returns client_id and client_secret which must be securely stored.",
    responses={
        201: {
            "description": "Client registered successfully",
            "model": ClientRegistrationResponse,
        },
        400: {
            "description": "Invalid request (missing or malformed request body)",
            "model": AuthErrorResponse,
        },
        401: {
            "description": "Invalid Basic Auth credentials",
            "model": AuthErrorResponse,
        },
        409: {
            "description": "Client name already registered",
            "model": AuthErrorResponse,
        },
        422: {
            "description": "Validation error (invalid field values)",
            "model": AuthErrorResponse,
        },
        429: {
            "description": "Rate limit exceeded",
            "model": AuthErrorResponse,
        },
        500: {
            "description": "Internal server error",
            "model": AuthErrorResponse,
        },
        503: {
            "description": "Registration service unavailable",
            "model": AuthErrorResponse,
        },
    },
)
async def register_client(
    request: ClientRegistrationRequest,
    credentials: Annotated[HTTPBasicCredentials, Depends(_verify_basic_auth)],  # pylint: disable=unused-argument
) -> ClientRegistrationResponse:
    """Register a new OAuth client.

    This endpoint requires HTTP Basic Authentication with pre-configured
    registration credentials. On success, returns client_id and client_secret
    which the client must securely store.

    **Important:** The client_secret is shown only once during registration.

    Args:
        request: Client registration request containing client_name and optional fields.
        credentials: Validated Basic Auth credentials (injected by dependency).

    Returns:
        ClientRegistrationResponse with client_id and client_secret.

    Raises:
        HTTPException: With appropriate status code on failure.
    """
    logger.info("Client registration request received")

    try:
        registered_client = _auth_service.register_client(
            client_name=request.client_name,
            description=request.description,
            allowed_scopes=request.allowed_scopes,
        )

        logger.info("Client registered successfully")

        return ClientRegistrationResponse(
            client_id=registered_client.client_id,
            client_secret=registered_client.client_secret,
            client_name=registered_client.client_name,
            allowed_scopes=registered_client.allowed_scopes,
            created_at=registered_client.created_at,
            expires_at=registered_client.expires_at,
        )

    except ClientExistsError:
        logger.warning("Client registration failed - client exists")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "client_exists", "error_description": "Client name already registered"},
        ) from None

    except MaxClientsReachedError:
        logger.warning("Client registration failed - max clients reached")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "max_clients_reached",
                "error_description": "Maximum number of clients (1) already registered"
            },
        ) from None

    except VaultError:
        logger.error("Client registration failed - vault error for: %s", request.client_name)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "server_error", "error_description": "Failed to store client credentials"},
        ) from None

    except Exception:
        logger.exception("Unexpected error during client registration: %s", request.client_name)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "server_error", "error_description": "An unexpected error occurred"},
        ) from None
