#!/usr/bin/env python3
"""Manual test script for PostgreSQL integration.

This script demonstrates the PostgreSQL repository implementations
without requiring a full API server. Useful for debugging and
verification.

Usage:
    export DATABASE_URL="postgresql://user:pass@host:5432/db"
    python test_postgres_integration.py
"""

import os
import sys
import uuid
from datetime import datetime, timezone

# Add build_stream to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.jobs.entities.audit import AuditEvent
from core.jobs.entities.idempotency import IdempotencyRecord
from core.jobs.entities.job import Job
from core.jobs.entities.stage import Stage
from core.jobs.value_objects import (
    ClientId,
    CorrelationId,
    IdempotencyKey,
    JobId,
    JobState,
    RequestFingerprint,
    StageName,
    StageState,
)
from infra.db.models import Base
from infra.db.repositories import (
    SqlAuditEventRepository,
    SqlIdempotencyRepository,
    SqlJobRepository,
    SqlStageRepository,
)
from infra.db.session import get_db_session
from sqlalchemy import text


def setup_database():
    """Create database tables."""
    print("Setting up database tables...")
    with get_db_session() as session:
        Base.metadata.create_all(bind=session.bind)
    print("✓ Tables created")


def test_job_repository():
    """Test job repository operations."""
    print("\n=== Testing Job Repository ===")
    
    with get_db_session() as session:
        repo = SqlJobRepository(session)
        
        # Create a job
        job_id = JobId(str(uuid.uuid4()))
        job = Job(
            job_id=job_id,
            client_id=ClientId("test-client"),
            request_client_id="req-123",
            client_name="Test Client",
            job_state=JobState.CREATED,
        )
        
        print(f"Creating job: {job_id}")
        repo.save(job)
        
        # Retrieve it
        found = repo.find_by_id(job_id)
        assert found is not None
        print(f"✓ Retrieved job: state={found.job_state}, version={found.version}")
        
        # Check exists
        assert repo.exists(job_id)
        print("✓ Job exists check passed")
        
        # Update with state change
        job.start()  # Changes state and increments version
        repo.save(job)
        
        # Verify update
        updated = repo.find_by_id(job_id)
        assert updated is not None
        assert updated.job_state == JobState.IN_PROGRESS
        assert updated.version == 2
        print(f"✓ Updated job: state={updated.job_state}, version={updated.version}")
        
        return job_id


def test_stage_repository(job_id: JobId):
    """Test stage repository operations."""
    print("\n=== Testing Stage Repository ===")
    
    with get_db_session() as session:
        repo = SqlStageRepository(session)
        
        # Create stages
        stages = [
            Stage(
                job_id=job_id,
                stage_name=StageName("parse-catalog"),
                stage_state=StageState.IN_PROGRESS,
                started_at=datetime.now(timezone.utc),
            ),
            Stage(
                job_id=job_id,
                stage_name=StageName("generate-input-files"),
                stage_state=StageState.PENDING,
            ),
        ]
        
        print(f"Creating {len(stages)} stages...")
        repo.save_all(stages)
        
        # Find all stages for job
        found_stages = repo.find_all_by_job(job_id)
        assert len(found_stages) == 2
        print(f"✓ Found {len(found_stages)} stages for job")
        
        # Find specific stage
        stage = repo.find_by_job_and_name(job_id, StageName("parse-catalog"))
        assert stage is not None
        assert stage.stage_state == StageState.IN_PROGRESS
        print(f"✓ Found parse-catalog stage: state={stage.stage_state}")
        
        # Update stage - fail it
        stage.fail("TIMEOUT", "Stage timed out")
        repo.save(stage)
        
        # Verify update
        updated = repo.find_by_job_and_name(job_id, StageName("parse-catalog"))
        assert updated is not None
        assert updated.stage_state == StageState.FAILED
        assert updated.error_code == "TIMEOUT"
        print(f"✓ Updated stage: state={updated.stage_state}, error={updated.error_code}")


def test_idempotency_repository(job_id: JobId):
    """Test idempotency repository operations."""
    print("\n=== Testing Idempotency Repository ===")
    
    with get_db_session() as session:
        repo = SqlIdempotencyRepository(session)
        
        # Create record
        record = IdempotencyRecord(
            idempotency_key=IdempotencyKey("unique-key-123"),
            job_id=job_id,
            request_fingerprint=RequestFingerprint("a" * 64),
            client_id=ClientId("test-client"),
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        
        print(f"Creating idempotency record: {record.idempotency_key}")
        repo.save(record)
        
        # Retrieve it
        found = repo.find_by_key(record.idempotency_key)
        assert found is not None
        assert str(found.job_id) == str(job_id)
        print(f"✓ Retrieved idempotency record for job: {found.job_id}")


def test_audit_repository(job_id: JobId):
    """Test audit repository operations."""
    print("\n=== Testing Audit Repository ===")
    
    with get_db_session() as session:
        repo = SqlAuditEventRepository(session)
        
        # Create audit events
        events = [
            AuditEvent(
                event_id=str(uuid.uuid4()),
                job_id=job_id,
                event_type="job_created",
                correlation_id=CorrelationId(str(uuid.uuid4())),
                client_id=ClientId("test-client"),
                timestamp=datetime.now(timezone.utc),
                details={"source": "test_script"},
            ),
            AuditEvent(
                event_id=str(uuid.uuid4()),
                job_id=job_id,
                event_type="stage_completed",
                correlation_id=CorrelationId(str(uuid.uuid4())),
                client_id=ClientId("test-client"),
                timestamp=datetime.now(timezone.utc),
                details={"stage": "parse-catalog", "duration_ms": 5000},
            ),
        ]
        
        print(f"Creating {len(events)} audit events...")
        for event in events:
            repo.save(event)
        
        # Retrieve all events for job
        found_events = repo.find_by_job(job_id)
        assert len(found_events) == 2
        print(f"✓ Found {len(found_events)} audit events for job")
        
        # Verify chronological order
        assert found_events[0].timestamp < found_events[1].timestamp
        print("✓ Events are in chronological order")
        
        # Verify details
        stage_event = next(e for e in found_events if e.event_type == "stage_completed")
        assert stage_event.details["stage"] == "parse-catalog"
        print(f"✓ Event details preserved: {stage_event.details}")


def test_optimistic_locking(job_id: JobId):
    """Test optimistic locking behavior."""
    print("\n=== Testing Optimistic Locking ===")
    
    with get_db_session() as session:
        repo = SqlJobRepository(session)
        
        # Get current job
        job = repo.find_by_id(job_id)
        assert job is not None
        original_version = job.version
        
        print(f"Current job version: {original_version}")
        
        # Update job normally
        job.fail()
        repo.save(job)
        
        # Verify version incremented
        updated = repo.find_by_id(job_id)
        assert updated is not None
        assert updated.version == original_version + 1
        print(f"✓ Version incremented to: {updated.version}")
        
        # Try to save with stale version
        stale_job = Job(
            job_id=job_id,
            client_id=ClientId("test-client"),
            request_client_id="req-123",
            job_state=JobState.COMPLETED,
            version=original_version,  # Stale version
        )
        
        try:
            repo.save(stale_job)
            assert False, "Should have raised OptimisticLockError"
        except Exception as e:
            print(f"✓ Optimistic lock error raised: {type(e).__name__}")
            assert "Version conflict" in str(e)


def show_database_state():
    """Show current database state."""
    print("\n=== Database State ===")
    
    with get_db_session() as session:
        # Count records
        job_count = session.execute(text("SELECT COUNT(*) FROM jobs")).scalar()
        stage_count = session.execute(text("SELECT COUNT(*) FROM job_stages")).scalar()
        idempotency_count = session.execute(text("SELECT COUNT(*) FROM idempotency_keys")).scalar()
        audit_count = session.execute(text("SELECT COUNT(*) FROM audit_events")).scalar()
        
        print(f"Jobs: {job_count}")
        print(f"Stages: {stage_count}")
        print(f"Idempotency keys: {idempotency_count}")
        print(f"Audit events: {audit_count}")
        
        # Show latest job
        if job_count > 0:
            latest = session.execute(
                text("SELECT job_id, client_id, job_state, version FROM jobs ORDER BY created_at DESC LIMIT 1")
            ).fetchone()
            print(f"\nLatest job: {latest[0]} (client={latest[1]}, state={latest[2]}, version={latest[3]})")


def main():
    """Run all tests."""
    if not os.getenv("DATABASE_URL"):
        print("ERROR: DATABASE_URL environment variable not set")
        print("Example: export DATABASE_URL='postgresql://user:pass@host:5432/db'")
        sys.exit(1)
    
    print("PostgreSQL Integration Test")
    print("=" * 50)
    
    try:
        # Setup
        setup_database()
        
        # Run tests
        job_id = test_job_repository()
        test_stage_repository(job_id)
        test_idempotency_repository(job_id)
        test_audit_repository(job_id)
        test_optimistic_locking(job_id)
        
        # Show final state
        show_database_state()
        
        print("\n" + "=" * 50)
        print("✅ All tests passed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
