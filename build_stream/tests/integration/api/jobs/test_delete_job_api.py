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


class TestDeleteJobSuccess:
    
    def test_delete_existing_job_returns_204(self, client, auth_headers):
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=auth_headers)
        assert create_response.status_code == 201
        job_id = create_response.json()["job_id"]
        
        delete_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        delete_response = client.delete(f"/api/v1/jobs/{job_id}", headers=delete_headers)
        
        assert delete_response.status_code == 204
        assert delete_response.content == b""
    
    def test_delete_job_is_idempotent(self, client, auth_headers):
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=auth_headers)
        job_id = create_response.json()["job_id"]
        
        delete_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        
        delete_response1 = client.delete(f"/api/v1/jobs/{job_id}", headers=delete_headers)
        assert delete_response1.status_code == 204
        
        delete_response2 = client.delete(f"/api/v1/jobs/{job_id}", headers=delete_headers)
        assert delete_response2.status_code in [204, 404, 410]
    
    def test_deleted_job_not_retrievable(self, client, auth_headers):
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=auth_headers)
        job_id = create_response.json()["job_id"]
        
        headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        
        delete_response = client.delete(f"/api/v1/jobs/{job_id}", headers=headers)
        assert delete_response.status_code == 204
        
        get_response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert get_response.status_code in [404, 410]


class TestDeleteJobNotFound:
    
    def test_delete_nonexistent_job_returns_404(self, client, auth_headers):
        nonexistent_job_id = "019bf590-1234-7890-abcd-ef1234567890"
        
        delete_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        response = client.delete(f"/api/v1/jobs/{nonexistent_job_id}", headers=delete_headers)
        
        assert response.status_code == 404
    
    def test_delete_job_invalid_uuid_format_returns_400(self, client, auth_headers):
        invalid_job_id = "not-a-valid-uuid"
        
        delete_headers = {
            "Authorization": auth_headers["Authorization"],
            "X-Correlation-Id": auth_headers["X-Correlation-Id"],
        }
        response = client.delete(f"/api/v1/jobs/{invalid_job_id}", headers=delete_headers)
        
        assert response.status_code == 400


class TestDeleteJobAuthentication:
    
    def test_delete_job_missing_authorization_returns_422(self, client, unique_correlation_id):
        job_id = "019bf590-1234-7890-abcd-ef1234567890"
        headers = {"X-Correlation-Id": unique_correlation_id}
        
        response = client.delete(f"/api/v1/jobs/{job_id}", headers=headers)
        
        assert response.status_code == 422
    
    def test_delete_job_invalid_authorization_format_returns_401(self, client, unique_correlation_id):
        job_id = "019bf590-1234-7890-abcd-ef1234567890"
        headers = {
            "Authorization": "InvalidFormat test-token",
            "X-Correlation-Id": unique_correlation_id,
        }
        
        response = client.delete(f"/api/v1/jobs/{job_id}", headers=headers)
        
        assert response.status_code == 401


class TestDeleteJobClientIsolation:
    
    def test_different_client_cannot_delete_job(self, client, unique_idempotency_key, unique_correlation_id):
        create_headers = {
            "Authorization": "Bearer client-a",
            "X-Correlation-Id": unique_correlation_id,
            "Idempotency-Key": unique_idempotency_key,
        }
        create_payload = {"client_id": "client-123", "client_name": "test-client"}
        create_response = client.post("/api/v1/jobs", json=create_payload, headers=create_headers)
        assert create_response.status_code == 201
        job_id = create_response.json()["job_id"]
        
        delete_headers = {
            "Authorization": "Bearer client-b",
            "X-Correlation-Id": unique_correlation_id,
        }
        delete_response = client.delete(f"/api/v1/jobs/{job_id}", headers=delete_headers)
        
        assert delete_response.status_code in [403, 404]
        
        verify_headers = {
            "Authorization": "Bearer client-a",
            "X-Correlation-Id": unique_correlation_id,
        }
        verify_response = client.get(f"/api/v1/jobs/{job_id}", headers=verify_headers)
        assert verify_response.status_code == 200
