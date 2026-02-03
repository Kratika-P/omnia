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


class TestGetJobSuccess:
    
    def test_get_existing_job_returns_200(self, client, auth_headers):
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=auth_headers)
        assert create_response.status_code == 201
        job_id = create_response.json()["job_id"]
        
        get_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        get_response = client.get(f"/api/v1/jobs/{job_id}", headers=get_headers)
        
        assert get_response.status_code == 200
        data = get_response.json()
        assert data["job_id"] == job_id
        assert "job_state" in data
        assert "created_at" in data
        assert "stages" in data
    
    def test_get_job_returns_all_stages(self, client, auth_headers):
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=auth_headers)
        job_id = create_response.json()["job_id"]
        
        get_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        get_response = client.get(f"/api/v1/jobs/{job_id}", headers=get_headers)
        
        assert get_response.status_code == 200
        stages = get_response.json()["stages"]
        assert len(stages) == 9
    
    def test_get_job_returns_correlation_id(self, client, auth_headers, unique_correlation_id):
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=auth_headers)
        job_id = create_response.json()["job_id"]
        
        get_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": unique_correlation_id,
        }
        get_response = client.get(f"/api/v1/jobs/{job_id}", headers=get_headers)
        
        assert get_response.status_code == 200
        assert get_response.json()["correlation_id"] == unique_correlation_id


class TestGetJobNotFound:
    
    def test_get_nonexistent_job_returns_404(self, client, auth_headers):
        nonexistent_job_id = "019bf590-1234-7890-abcd-ef1234567890"
        
        get_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        response = client.get(f"/api/v1/jobs/{nonexistent_job_id}", headers=get_headers)
        
        assert response.status_code == 404
    
    def test_get_job_invalid_uuid_format_returns_400(self, client, auth_headers):
        invalid_job_id = "not-a-valid-uuid"
        
        get_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        response = client.get(f"/api/v1/jobs/{invalid_job_id}", headers=get_headers)
        
        assert response.status_code == 400


class TestGetJobAuthentication:
    
    def test_get_job_missing_authorization_returns_422(self, client, unique_correlation_id):
        job_id = "019bf590-1234-7890-abcd-ef1234567890"
        headers = {"X-Correlation-Id": unique_correlation_id}
        
        response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        
        assert response.status_code == 422
    
    def test_get_job_invalid_authorization_format_returns_401(self, client, unique_correlation_id):
        job_id = "019bf590-1234-7890-abcd-ef1234567890"
        headers = {
            "Authorization": "InvalidFormat test-token",
            "X-Correlation-Id": unique_correlation_id,
        }
        
        response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        
        assert response.status_code == 401


class TestGetJobClientIsolation:
    
    def test_different_client_cannot_access_job(self, client, unique_idempotency_key, unique_correlation_id):
        create_headers = {
            "Authorization": "Bearer client-a",
            "X-Correlation-Id": unique_correlation_id,
            "Idempotency-Key": unique_idempotency_key,
        }
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=create_headers)
        assert create_response.status_code == 201
        job_id = create_response.json()["job_id"]
        
        get_headers = {
            "Authorization": "Bearer client-b",
            "X-Correlation-Id": unique_correlation_id,
        }
        get_response = client.get(f"/api/v1/jobs/{job_id}", headers=get_headers)
        
        assert get_response.status_code in [403, 404]
