# Manual PostgreSQL Testing Guide

This guide shows how to test the PostgreSQL integration manually against a running PostgreSQL container.

## 1. Start PostgreSQL Container

```bash
# The omnia_postgres container should already be running
# If not, start it with:
podman run -d --name omnia_postgres \
  -e POSTGRES_DB=build_stream_db \
  -e POSTGRES_USER=admin \
  -e POSTGRES_PASSWORD=dell1234 \
  -p 5432:5432 \
  -v /opt/postgres/data:/var/lib/postgresql/data \
  -v /opt/log/postgres:/var/log/postgresql \
  docker.io/library/postgres:16

# Check if container is running
podman ps | grep omnia_postgres

# Wait for database to be ready (if just started)
sleep 10
```

## 2. Run Database Migrations

```bash
# Set DATABASE_URL environment variable
export DATABASE_URL="postgresql://admin:dell1234@localhost:5432/build_stream_db"

# Run Alembic migrations
cd /opt/omnia/windsurf/build_stream_venu_oim/build_stream
python -m alembic upgrade head

# Verify tables were created
podman exec -it omnia_postgres psql -U admin -d build_stream_db -c "\dt"
```

## 3. Run the Application in Production Mode

```bash
# Set ENV to prod to use SQL repositories
export ENV=prod
export DATABASE_URL="postgresql://admin:dell1234@localhost:5432/build_stream_db"

# Start the application
python main.py
```

## 4. Test with curl

```bash
# Create a job
curl -X POST "http://localhost:8000/api/v1/jobs" \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: test-client" \
  -d '{
    "catalog_digest": "sha256:abc123",
    "idempotency_key": "test-key-123"
  }'

# Note the jobId from response, then retrieve it
curl -X GET "http://localhost:8000/api/v1/jobs/{jobId}" \
  -H "X-Client-ID: test-client"
```

## 5. Manual Database Verification

Connect to the database and inspect the data:

```bash
# Connect to PostgreSQL
podman exec -it omnia_postgres psql -U admin -d build_stream_db

# List all tables
\dt

# Check jobs table
SELECT job_id, client_id, request_client_id, job_state, created_at, version, tombstoned 
FROM jobs 
ORDER BY created_at DESC;

# Check stages for a specific job
SELECT job_id, stage_name, stage_state, attempt, started_at, ended_at, error_code 
FROM job_stages 
WHERE job_id = 'YOUR_JOB_ID_HERE'
ORDER BY stage_name;

## 6. Running Integration Tests

```bash
# Run all integration tests (uses pytest.ini configuration)
python -m pytest tests/integration/infra/db/

# Or set environment variable manually
export TEST_DATABASE_URL="postgresql://admin:dell1234@localhost:5432/build_stream_db"
python -m pytest tests/integration/infra/db/test_sql_repositories.py

# Run manual test script
export DATABASE_URL="postgresql://admin:dell1234@localhost:5432/build_stream_db"
python test_postgres_integration.py
```

## 7. Additional Queries

```bash
# Check idempotency records
SELECT idempotency_key, job_id, client_id, created_at, expires_at 
FROM idempotency_keys 
ORDER BY created_at DESC;

# Check audit events
SELECT event_id, job_id, event_type, correlation_id, client_id, timestamp, details
FROM audit_events 
WHERE job_id = 'YOUR_JOB_ID_HERE'
ORDER BY timestamp;
```

## 8. Database Schema Inspection

```bash
# Check indexes
\di

# Check table schemas
\d jobs
\d job_stages
\d idempotency_keys
\d audit_events

# Exit psql
\q
```

## 6. Test Optimistic Locking

```bash
# First, get a job
JOB_ID=$(curl -s -X POST "http://localhost:8000/api/v1/jobs" \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: test-client" \
  -d '{"catalog_digest": "sha256:def456", "idempotency_key": "test-key-456"}' | \
  jq -r '.jobId')

# Try to update with wrong version (should fail)
curl -X PATCH "http://localhost:8000/api/v1/jobs/$JOB_ID" \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: test-client" \
  -H "If-Match: 999" \
  -d '{"job_state": "FAILED"}'
```

## 7. Run Integration Tests

```bash
# With running container
export TEST_DATABASE_URL="postgresql://build_stream:build_stream@localhost:5432/build_stream"

# Run integration tests
python -m pytest tests/integration/infra/db/test_sql_repositories.py -v
```

## 8. Cleanup

```bash
# Stop and remove container
docker stop build-stream-test-db
docker rm build-stream-test-db

# Or to keep data but stop container
docker stop build-stream-test-db
```

## 9. Common Queries for Debugging

```sql
-- Find all jobs for a client
SELECT * FROM jobs WHERE client_id = 'test-client';

-- Find all stages in a specific state
SELECT * FROM job_stages WHERE stage_state = 'FAILED';

-- Find expired idempotency keys
SELECT * FROM idempotency_keys WHERE expires_at < NOW();

-- Count audit events by type
SELECT event_type, COUNT(*) FROM audit_events GROUP BY event_type;

-- Check for orphaned stages (should be none due to FK)
SELECT s.* FROM job_stages s LEFT JOIN jobs j ON s.job_id = j.job_id WHERE j.job_id IS NULL;

-- Verify cascade delete worked
BEGIN;
DELETE FROM jobs WHERE job_id = 'test-job-id';
SELECT COUNT(*) FROM job_stages WHERE job_id = 'test-job-id';  -- Should be 0
ROLLBACK;
```

## 10. Performance Testing

```sql
-- Create test data
INSERT INTO jobs (job_id, client_id, request_client_id, job_state, created_at, updated_at, version, tombstoned)
SELECT 
    gen_random_uuid()::text,
    'perf-test-client',
    'req-' || gen_random_uuid()::text,
    'CREATED',
    NOW(),
    NOW(),
    1,
    false
FROM generate_series(1, 10000);

-- Check query performance
EXPLAIN ANALYZE SELECT * FROM jobs WHERE client_id = 'perf-test-client' ORDER BY created_at DESC LIMIT 100;

EXPLAIN ANALYZE SELECT * FROM jobs WHERE tombstoned = false AND created_at > NOW() - INTERVAL '1 day';
```
