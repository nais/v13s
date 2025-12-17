# Architecture

v13s consists of several key components:

- **API Server**: gRPC server exposing vulnerability and management services
- **Kubernetes Informers**: Watch workloads across multiple clusters
- **Workload Manager**: Orchestrates workload registration and vulnerability tracking via River job queue
- **Updater**: Periodically syncs vulnerability data from external sources
- **River Job Queue**: Handles asynchronous job processing for workload operations
- **PostgreSQL Database**: Stores workload metadata, vulnerability data, and job state
- **CLI**: Command-line interface for querying vulnerability data

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         v13s System                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  K8s Cluster │    │  K8s Cluster │    │  K8s Cluster │      │
│  │    dev       │    │    prod      │    │    ...       │      │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘      │
│         │                   │                    │              │
│         └───────────────────┼────────────────────┘              │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │   K8s Informers │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│                    ┌────────▼────────┐                          │
│                    │ Workload Queue  │                          │
│                    └────────┬────────┘                          │
│                             │                                    │
│         ┌───────────────────┴───────────────────┐               │
│         │                                       │               │
│  ┌──────▼──────┐                      ┌────────▼────────┐      │
│  │  Workload   │◄────────────────────►│  River Job      │      │
│  │  Manager    │                      │  Queue          │      │
│  └──────┬──────┘                      └────────┬────────┘      │
│         │                                      │               │
│         │                             ┌────────▼────────┐      │
│         │                             │  PostgreSQL     │      │
│         │                             │  Database       │      │
│  ┌──────▼──────┐                      └────────▲────────┘      │
│  │  Updater    │                               │               │
│  └──────┬──────┘                               │               │
│         │                                      │               │
│         │      ┌──────────────────────┐        │               │
│         └─────►│  DependencyTrack     │────────┘               │
│                │  (or other sources)  │                        │
│                └──────────────────────┘                        │
│                                                                  │
│  ┌──────────────┐                      ┌────────────────┐      │
│  │  gRPC API    │                      │  Internal HTTP │      │
│  │  Server      │                      │  (metrics,     │      │
│  │              │                      │   RiverUI)     │      │
│  └──────▲───────┘                      └────────────────┘      │
│         │                                                       │
└─────────┼───────────────────────────────────────────────────────┘
          │
    ┌─────▼─────┐
    │    CLI    │
    └───────────┘
```

## How It Works

### Workload Registration

1. **Discovery**: Kubernetes informers watch for Deployment and NaisJob resources across configured clusters
2. **Event Processing**: When a workload is created/updated, it's added to the workload event queue
3. **Job Creation**: The Workload Manager creates a River job to process the workload
4. **Attestation Retrieval**: A worker job fetches the container image attestation from the registry
5. **Attestation Upload**: The attestation (SBOM) is uploaded to the vulnerability source (DependencyTrack)
6. **Tracking**: The workload and image are registered in the database for ongoing vulnerability monitoring

### Vulnerability Data Updates

1. **Scheduled Updates**: The Updater runs on a configurable schedule (default: every 4 hours)
2. **Image Selection**: Images marked for resync or newly added are selected for updates
3. **Fetching**: Vulnerability data is fetched from the configured source in batches
4. **Database Updates**: CVEs, vulnerabilities, and summary data are upserted into the database
5. **State Management**: Image states are updated to track sync status (initialized, resync, updated, failed, etc.)

### Data Flow

```
Workload Event → WorkloadManager → River Jobs → Workers
                                                    │
                                                    ├─► AddWorkload
                                                    ├─► GetAttestation
                                                    ├─► UploadAttestation
                                                    ├─► FinalizeAttestation
                                                    └─► DeleteWorkload

Updater Schedule → MarkForResync → FetchVulnerabilities → BatchUpdate → Database
                                                                            │
                                                                            ├─► images
                                                                            ├─► vulnerabilities
                                                                            ├─► cve
                                                                            └─► vulnerability_summary
```

The system maintains several scheduled tasks:
- **Image Resync** (every 4 hours): Marks and resyncs image vulnerability data
- **Mark Untracked** (every 20 minutes): Identifies images with no SBOMs
- **Mark Unused** (every 30 minutes): Marks images that are no longer in use by any workload
- **Daily Summary Refresh** (daily at 4:30 AM CEST): Updates materialized views for reporting
- **MTTF Calculation** (daily at 5:00 AM CEST): Calculates Mean Time to Fix metrics
