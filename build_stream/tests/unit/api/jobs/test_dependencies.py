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

import pytest
from fastapi import HTTPException

from api.jobs.dependencies import get_client_id, get_idempotency_key
from core.jobs.value_objects import ClientId


class TestGetClientId:
    
    def test_valid_bearer_token_returns_client_id(self):
        authorization = "Bearer test-client-123"
        
        client_id = get_client_id(authorization)
        
        assert isinstance(client_id, ClientId)
        assert client_id.value == "test-client-123"
    
    def test_bearer_token_with_spaces_trimmed(self):
        authorization = "Bearer   test-client-123   "
        
        client_id = get_client_id(authorization)
        
        assert client_id.value == "test-client-123   "
    
    def test_long_token_truncated_to_128_chars(self):
        long_token = "a" * 200
        authorization = f"Bearer {long_token}"
        
        client_id = get_client_id(authorization)
        
        assert len(client_id.value) == 128
        assert client_id.value == long_token[:128]
    
    def test_missing_bearer_prefix_raises_401(self):
        authorization = "InvalidFormat test-token"
        
        with pytest.raises(HTTPException) as exc_info:
            get_client_id(authorization)
        
        assert exc_info.value.status_code == 401
        assert "Invalid authorization header format" in exc_info.value.detail
    
    def test_empty_token_raises_401(self):
        authorization = "Bearer "
        
        with pytest.raises(HTTPException) as exc_info:
            get_client_id(authorization)
        
        assert exc_info.value.status_code == 401
        assert "Missing authentication token" in exc_info.value.detail
    
    def test_bearer_only_raises_401(self):
        authorization = "Bearer"
        
        with pytest.raises(HTTPException) as exc_info:
            get_client_id(authorization)
        
        assert exc_info.value.status_code == 401


class TestGetIdempotencyKey:
    
    def test_valid_idempotency_key_returned(self):
        key = "test-key-12345"
        
        result = get_idempotency_key(key)
        
        assert result == "test-key-12345"
    
    def test_idempotency_key_with_special_chars(self):
        key = "test-key-abc-123_xyz"
        
        result = get_idempotency_key(key)
        
        assert result == "test-key-abc-123_xyz"
    
    def test_empty_idempotency_key_raises_422(self):
        key = ""
        
        with pytest.raises(HTTPException) as exc_info:
            get_idempotency_key(key)
        
        assert exc_info.value.status_code == 422
    
    def test_whitespace_only_key_raises_422(self):
        key = "   "
        
        with pytest.raises(HTTPException) as exc_info:
            get_idempotency_key(key)
        
        assert exc_info.value.status_code == 422
    
    def test_key_exceeding_max_length_raises_422(self):
        key = "a" * 256
        
        with pytest.raises(HTTPException) as exc_info:
            get_idempotency_key(key)
        
        assert exc_info.value.status_code == 422
        assert "length" in exc_info.value.detail.lower()
    
    def test_key_at_max_length_accepted(self):
        key = "a" * 255
        
        result = get_idempotency_key(key)
        
        assert result == key
        assert len(result) == 255
