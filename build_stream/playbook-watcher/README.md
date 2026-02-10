# Playbook Watcher Service

This directory contains the playbook watcher service that monitors the playbook queue for Build Stream operations.

## Files

- `playbook_watcher_service.py` - The main Python service that monitors the queue and executes playbooks
- `playbook-watcher.service` - Systemd service unit file for running the service on the host

## Deployment

The service is deployed to `/opt/omnia/services/` on the omnia host and runs as a systemd service.

## Service Configuration

The service is configured with the following environment variables:
- `PLAYBOOK_QUEUE_BASE` - Base directory for the playbook queue (default: `/opt/omnia/playbook_queue`)
- `POLL_INTERVAL_SECONDS` - How often to check for new jobs (default: 2)
- `MAX_CONCURRENT_JOBS` - Maximum number of concurrent playbook executions (default: 5)
- `DEFAULT_TIMEOUT_MINUTES` - Default timeout for playbook execution (default: 30)
- `LOG_LEVEL` - Logging level (default: INFO)

## Queue Structure

The service monitors the following directories:
- `requests/` - New playbook requests are placed here
- `processing/` - Jobs currently being executed
- `results/` - Completed job results
- `archive/requests/` - Archived request files
- `archive/results/` - Archived result files
