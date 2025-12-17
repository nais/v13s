# River Job Queue

## Understanding River

v13s uses [River](https://riverqueue.com/) for asynchronous job processing. River is a job queue system built on PostgreSQL that provides:

- **Reliability**: Jobs are stored in PostgreSQL with transactional guarantees
- **Observability**: Built-in job tracking and metrics
- **Concurrency Control**: Per-queue worker pools with configurable max workers
- **Retries**: Automatic retry with exponential backoff
- **UI**: Web interface for monitoring jobs (available at `/riverui` on the internal HTTP server)

## Job Types

The system uses River for several types of jobs:

- **AddWorkload**: Register a new workload in the system (10 workers)
- **GetAttestation**: Fetch attestation from container registry (15 workers)
- **UploadAttestation**: Upload SBOM to vulnerability source (10 workers)
- **FinalizeAttestation**: Complete attestation processing (10 workers)
- **DeleteWorkload**: Remove workload from tracking (3 workers)
- **RemoveFromSource**: Clean up workload from vulnerability source (3 workers)

Each job type has its own queue configuration defined in `internal/manager/workload_manager.go`.

## Updating River Schema

When upgrading River or needing to update the database schema:

1. **Generate the migration SQL**:
   ```bash
   river migrate-get --line main --all --up > internal/database/river_schema/river_schema.sql
   ```

2. **Update the migration version** in `internal/job/client.go`:
   ```go
   const RiverMigrationVersion = 6  // Update this to the new version
   ```

3. **Test the migration**: The migration runs automatically on startup. Check logs for migration messages.

The River schema is stored in `internal/database/river_schema/river_schema.sql` and is automatically applied when the application starts.

## Monitoring Jobs

Access the River UI at `http://localhost:8080/riverui` when running locally to monitor job status, view errors, and inspect job details.
