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

import re

import pytest


class TestCreateJobSuccess:
    
    def test_create_job_returns_201_with_valid_request(self, client, auth_headers):
        payload = {
            "catalog_uri": "s3://test-bucket/catalog.json",
            "metadata": {"description": "Test job creation"}
        }
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code == 201
        data = response.json()
        assert "job_id" in data
        assert "correlation_id" in data
        assert "job_state" in data
        assert "created_at" in data
        assert "stages" in data
    
    def test_create_job_returns_valid_uuid_v7(self, client, auth_headers):
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code == 201
        job_id = response.json()["job_id"]
        
        uuid_v7_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        assert re.match(uuid_v7_pattern, job_id.lower()), f"Invalid UUID v7 format: {job_id}"
        assert len(job_id) == 36
    
    def test_create_job_returns_created_state(self, client, auth_headers):
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code == 201
        assert response.json()["job_state"] == "CREATED"
    
    def test_create_job_creates_all_nine_stages(self, client, auth_headers):
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code == 201
        stages = response.json()["stages"]
        assert len(stages) == 9
        
        expected_stages = [
            "parse-catalog",
            "generate-input-files",
            "create-local-repository",
            "update-local-repository",
            "create-image-repository",
            "build-image",
            "validate-image",
            "validate-image-on-test",
            "promote"
        ]
        
        stage_names = [s["stage_name"] for s in stages]
        assert stage_names == expected_stages
    
    def test_create_job_all_stages_pending(self, client, auth_headers):
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code == 201
        stages = response.json()["stages"]
        
        for stage in stages:
            assert stage["stage_state"] == "PENDING"
            assert stage["started_at"] is None
            assert stage["ended_at"] is None
            assert stage["error_code"] is None
            assert stage["error_summary"] is None
    
    def test_create_job_returns_correlation_id(self, client, unique_correlation_id, unique_idempotency_key):
        headers = {
            "Authorization": "Bearer test-client-123",
            "X-Correlation-Id": unique_correlation_id,
            "Idempotency-Key": unique_idempotency_key,
        }
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=headers)
        
        assert response.status_code == 201
        assert response.json()["correlation_id"] == unique_correlation_id


class TestCreateJobIdempotency:
    
    def test_idempotent_request_returns_200_with_same_job(self, client, unique_idempotency_key, unique_correlation_id):
        headers = {
            "Authorization": "Bearer test-client-123",
            "X-Correlation-Id": unique_correlation_id,
            "Idempotency-Key": unique_idempotency_key,
        }
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response1 = client.post("/api/v1/jobs", json=payload, headers=headers)
        assert response1.status_code == 201
        job_id_1 = response1.json()["job_id"]
        
        response2 = client.post("/api/v1/jobs", json=payload, headers=headers)
        assert response2.status_code == 200
        job_id_2 = response2.json()["job_id"]
        
        assert job_id_1 == job_id_2
    
    def test_idempotency_with_different_correlation_id(self, client, unique_idempotency_key):
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        headers1 = {
            "Authorization": "Bearer test-client-123",
            "X-Correlation-Id": "019bf590-1111-7890-abcd-ef1234567890",
            "Idempotency-Key": unique_idempotency_key,
        }
        response1 = client.post("/api/v1/jobs", json=payload, headers=headers1)
        assert response1.status_code == 201
        job_id_1 = response1.json()["job_id"]
        
        headers2 = {
            "Authorization": "Bearer test-client-123",
            "X-Correlation-Id": "019bf590-2222-7890-abcd-ef1234567890",
            "Idempotency-Key": unique_idempotency_key,
        }
        response2 = client.post("/api/v1/jobs", json=payload, headers=headers2)
        assert response2.status_code == 200
        job_id_2 = response2.json()["job_id"]
        
        assert job_id_1 == job_id_2
    
    def test_idempotency_conflict_different_payload(self, client, unique_idempotency_key, unique_correlation_id):
        headers = {
            "Authorization": "Bearer test-client-123",
            "X-Correlation-Id": unique_correlation_id,
            "Idempotency-Key": unique_idempotency_key,
        }
        
        payload1 = {"catalog_uri": "s3://test-bucket/catalog1.json"}
        response1 = client.post("/api/v1/jobs", json=payload1, headers=headers)
        assert response1.status_code == 201
        
        payload2 = {"catalog_uri": "s3://test-bucket/catalog2.json"}
        response2 = client.post("/api/v1/jobs", json=payload2, headers=headers)
        assert response2.status_code == 409
        
        error_detail = response2.json()["detail"]
        assert "IDEMPOTENCY_CONFLICT" in error_detail["error"]


class TestCreateJobValidation:
    
    def test_missing_catalog_uri_returns_422(self, client, auth_headers):
        payload = {}
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code == 422
    
    def test_empty_catalog_uri_returns_400(self, client, auth_headers):
        payload = {"catalog_uri": ""}
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422]
    
    def test_invalid_catalog_uri_format(self, client, auth_headers):
        payload = {"catalog_uri": "not-a-valid-uri"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=auth_headers)
        
        assert response.status_code in [400, 422]


class TestCreateJobAuthentication:
    
    def test_missing_authorization_header_returns_422(self, client, unique_idempotency_key):
        headers = {
            "X-Correlation-Id": "019bf590-1234-7890-abcd-ef1234567890",
            "Idempotency-Key": unique_idempotency_key,
        }
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_invalid_authorization_format_returns_401(self, client, unique_idempotency_key):
        headers = {
            "Authorization": "InvalidFormat test-token",
            "X-Correlation-Id": "019bf590-1234-7890-abcd-ef1234567890",
            "Idempotency-Key": unique_idempotency_key,
        }
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=headers)
        
        assert response.status_code == 401
    
    def test_empty_bearer_token_returns_401(self, client, unique_idempotency_key):
        headers = {
            "Authorization": "Bearer ",
            "X-Correlation-Id": "019bf590-1234-7890-abcd-ef1234567890",
            "Idempotency-Key": unique_idempotency_key,
        }
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=headers)
        
        assert response.status_code == 401


class TestCreateJobHeaders:
    
    def test_missing_idempotency_key_returns_422(self, client):
        headers = {
            "Authorization": "Bearer test-client-123",
            "X-Correlation-Id": "019bf590-1234-7890-abcd-ef1234567890",
        }
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=headers)
        
        assert response.status_code == 422
    
    def test_auto_generates_correlation_id_if_missing(self, client, unique_idempotency_key):
        headers = {
            "Authorization": "Bearer test-client-123",
            "Idempotency-Key": unique_idempotency_key,
        }
        payload = {"catalog_uri": "s3://test-bucket/catalog.json"}
        
        response = client.post("/api/v1/jobs", json=payload, headers=headers)
        
        assert response.status_code == 201
        assert "correlation_id" in response.json()
        correlation_id = response.json()["correlation_id"]
        assert len(correlation_id) == 36
