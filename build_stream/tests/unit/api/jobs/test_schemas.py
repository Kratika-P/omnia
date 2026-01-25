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
from pydantic import ValidationError

from api.jobs.schemas import (
    CreateJobRequest,
    CreateJobResponse,
    GetJobResponse,
    StageResponse,
    ErrorResponse,
)


class TestCreateJobRequest:
    
    def test_valid_request_with_required_fields(self):
        data = {"catalog_uri": "s3://bucket/catalog.json"}
        
        request = CreateJobRequest(**data)
        
        assert request.catalog_uri == "s3://bucket/catalog.json"
        assert request.metadata is None
    
    def test_valid_request_with_metadata(self):
        data = {
            "catalog_uri": "s3://bucket/catalog.json",
            "metadata": {"description": "Test", "tags": ["test"]}
        }
        
        request = CreateJobRequest(**data)
        
        assert request.catalog_uri == "s3://bucket/catalog.json"
        assert request.metadata == {"description": "Test", "tags": ["test"]}
    
    def test_missing_catalog_uri_raises_validation_error(self):
        data = {}
        
        with pytest.raises(ValidationError) as exc_info:
            CreateJobRequest(**data)
        
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("catalog_uri",) for e in errors)
    
    def test_empty_catalog_uri_raises_validation_error(self):
        data = {"catalog_uri": ""}
        
        with pytest.raises(ValidationError) as exc_info:
            CreateJobRequest(**data)
        
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("catalog_uri",) for e in errors)
    
    def test_catalog_uri_max_length_validation(self):
        data = {"catalog_uri": "s3://" + "a" * 2048}
        
        with pytest.raises(ValidationError):
            CreateJobRequest(**data)
    
    def test_metadata_can_be_none(self):
        data = {"catalog_uri": "s3://bucket/catalog.json", "metadata": None}
        
        request = CreateJobRequest(**data)
        
        assert request.metadata is None


class TestCreateJobResponse:
    
    def test_valid_response_with_all_fields(self):
        data = {
            "job_id": "019bf590-1234-7890-abcd-ef1234567890",
            "correlation_id": "019bf590-5678-7890-abcd-ef1234567890",
            "job_state": "CREATED",
            "created_at": "2026-01-25T15:00:00+00:00",
            "stages": []
        }
        
        response = CreateJobResponse(**data)
        
        assert response.job_id == "019bf590-1234-7890-abcd-ef1234567890"
        assert response.correlation_id == "019bf590-5678-7890-abcd-ef1234567890"
        assert response.job_state == "CREATED"
        assert response.created_at == "2026-01-25T15:00:00+00:00"
        assert response.stages == []
    
    def test_missing_required_field_raises_validation_error(self):
        data = {
            "job_id": "019bf590-1234-7890-abcd-ef1234567890",
            "job_state": "CREATED",
        }
        
        with pytest.raises(ValidationError):
            CreateJobResponse(**data)


class TestStageResponse:
    
    def test_valid_stage_response(self):
        data = {
            "stage_name": "parse-catalog",
            "stage_state": "PENDING",
            "started_at": None,
            "ended_at": None,
            "error_code": None,
            "error_summary": None,
        }
        
        stage = StageResponse(**data)
        
        assert stage.stage_name == "parse-catalog"
        assert stage.stage_state == "PENDING"
        assert stage.started_at is None
        assert stage.ended_at is None
    
    def test_stage_with_timestamps(self):
        data = {
            "stage_name": "parse-catalog",
            "stage_state": "RUNNING",
            "started_at": "2026-01-25T15:00:00Z",
            "ended_at": None,
            "error_code": None,
            "error_summary": None,
        }
        
        stage = StageResponse(**data)
        
        assert stage.started_at == "2026-01-25T15:00:00Z"
        assert stage.ended_at is None
    
    def test_stage_with_error(self):
        data = {
            "stage_name": "parse-catalog",
            "stage_state": "FAILED",
            "started_at": "2026-01-25T15:00:00Z",
            "ended_at": "2026-01-25T15:01:00Z",
            "error_code": "CATALOG_PARSE_ERROR",
            "error_summary": "Invalid JSON format",
        }
        
        stage = StageResponse(**data)
        
        assert stage.error_code == "CATALOG_PARSE_ERROR"
        assert stage.error_summary == "Invalid JSON format"


class TestGetJobResponse:
    
    def test_valid_get_job_response(self):
        data = {
            "job_id": "019bf590-1234-7890-abcd-ef1234567890",
            "correlation_id": "019bf590-5678-7890-abcd-ef1234567890",
            "job_state": "CREATED",
            "created_at": "2026-01-25T15:00:00+00:00",
            "stages": []
        }
        
        response = GetJobResponse(**data)
        
        assert response.job_id == "019bf590-1234-7890-abcd-ef1234567890"
        assert response.stages == []


class TestErrorResponse:
    
    def test_valid_error_response(self):
        data = {
            "error": "VALIDATION_ERROR",
            "message": "Invalid request",
            "correlation_id": "019bf590-1234-7890-abcd-ef1234567890",
            "timestamp": "2026-01-25T15:00:00Z",
        }
        
        response = ErrorResponse(**data)
        
        assert response.error == "VALIDATION_ERROR"
        assert response.message == "Invalid request"
        assert response.correlation_id == "019bf590-1234-7890-abcd-ef1234567890"
    
    def test_error_response_missing_required_field(self):
        data = {
            "error": "VALIDATION_ERROR",
            "message": "Invalid request",
        }
        
        with pytest.raises(ValidationError):
            ErrorResponse(**data)
