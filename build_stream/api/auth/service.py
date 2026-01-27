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

"""Authentication service for OAuth2 client registration."""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from .password_handler import generate_credentials, verify_password
from .vault_client import VaultClient, VaultDecryptError, VaultError, VaultNotFoundError

logger = logging.getLogger(__name__)

DEFAULT_SCOPES = ["catalog:read"]


class AuthenticationError(Exception):
    """Exception raised when authentication fails."""


class ClientExistsError(Exception):
    """Exception raised when client name already exists."""


class MaxClientsReachedError(Exception):
    """Exception raised when maximum number of clients is already registered."""


class RegistrationDisabledError(Exception):
    """Exception raised when registration is disabled or misconfigured."""


@dataclass
class RegisteredClient:
    """Data class representing a registered OAuth client."""

    client_id: str
    client_secret: str
    client_name: str
    allowed_scopes: List[str]
    created_at: datetime
    expires_at: Optional[datetime] = None


class AuthService:  # pylint: disable=too-few-public-methods
    """Service for handling OAuth2 authentication operations."""

    def __init__(self, vault_client: Optional[VaultClient] = None):
        """Initialize the authentication service.

        Args:
            vault_client: Optional VaultClient instance. Creates default if not provided.
        """
        self.vault_client = vault_client or VaultClient()
        self._registration_username = os.getenv("AUTH_REGISTRATION_USERNAME")

    def verify_registration_credentials(self, username: str, password: str) -> bool:
        """Verify the Basic Auth credentials for registration endpoint.

        Args:
            username: The provided username.
            password: The provided password.

        Returns:
            True if credentials are valid.

        Raises:
            AuthenticationError: If credentials are invalid.
            RegistrationDisabledError: If registration is not configured.
        """
        try:
            auth_config = self.vault_client.get_auth_config()
        except VaultNotFoundError:
            logger.error("Auth configuration vault not found")
            raise RegistrationDisabledError(
                "Registration is not configured"
            ) from None
        except VaultDecryptError:
            logger.error("Failed to decrypt auth configuration")
            raise RegistrationDisabledError(
                "Registration configuration error"
            ) from None

        registration_config = auth_config.get("auth_registration", {})
        stored_username = registration_config.get("username")
        stored_password_hash = registration_config.get("password_hash")

        if not stored_username or not stored_password_hash:
            logger.error("Registration credentials not configured in vault")
            raise RegistrationDisabledError(
                "Registration is not configured"
            ) from None

        if username != stored_username:
            logger.warning("Invalid registration username attempted")
            raise AuthenticationError("Invalid credentials")

        if not verify_password(password, stored_password_hash):
            logger.warning("Invalid registration password attempted")
            raise AuthenticationError("Invalid credentials")

        logger.info("Registration credentials verified successfully")
        return True

    def register_client(
        self,
        client_name: str,
        description: Optional[str] = None,
        allowed_scopes: Optional[List[str]] = None,
    ) -> RegisteredClient:
        """Register a new OAuth client.

        Args:
            client_name: Unique name for the client.
            description: Optional description of the client.
            allowed_scopes: List of OAuth scopes to grant.

        Returns:
            RegisteredClient with credentials (secret shown only once).

        Raises:
            ClientExistsError: If client_name is already registered.
            MaxClientsReachedError: If maximum client limit (1) is reached.
            VaultError: If vault operations fail.
        """
        active_count = self.vault_client.get_active_client_count()
        if active_count >= 1:
            logger.warning("Max client limit reached")
            raise MaxClientsReachedError(
                "Maximum number of clients (1) already registered. "
                "Only one active client is supported."
            )

        if self.vault_client.client_exists(client_name):
            logger.warning("Attempted to register existing client")
            raise ClientExistsError("Client already exists")

        scopes = allowed_scopes if allowed_scopes else DEFAULT_SCOPES
        client_id, client_secret, hashed_secret = generate_credentials()
        created_at = datetime.now(timezone.utc)

        client_data = {
            "client_name": client_name,
            "client_secret_hash": hashed_secret,
            "description": description,
            "allowed_scopes": scopes,
            "created_at": created_at.isoformat(),
            "is_active": True,
        }

        try:
            self.vault_client.save_oauth_client(client_id, client_data)
        except VaultError as e:
            logger.error("Failed to save client to vault: %s", client_name)
            raise

        logger.info("Client registered successfully")

        return RegisteredClient(
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_name,
            allowed_scopes=scopes,
            created_at=created_at,
            expires_at=None,
        )
