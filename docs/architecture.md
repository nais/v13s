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

### Suppression Forwarding to v0s

While v13s remains the writer, `SUPPRESSION_FORWARDING_ENABLED` forwards each suppression,
assessment edit and unsuppression to v0s in the same namespace, after the source rows are
written. v13s re-reads the persisted rows for the image name, versionless package and
vulnerability with its aliases, including other package versions and rows that no longer
suppress. They must agree on whether they suppress, and on state and actor, or nothing is
forwarded. Differing reason texts are merged into one, each labelled with its package versions,
newest first. Chainguard `CGA-*` advisories are sent with the upstream IDs their OSV record names for
the same package, unless it is withdrawn or names more than one ID of a kind, since v0s only knows
the upstream IDs. Rows under an advisory and under its upstream IDs are checked together, from
either side. `in_triage` and `resolved` become `accepted_risk`; `not_set` and
assessments without reason text or actor are not forwarded. v0s applies the assessment to
every workload currently running the image name, keeping the source actor and update time.

Forwarding is best effort and bounded by `SUPPRESSION_FORWARDING_TIMEOUT`. It never changes the
result of the suppression request. Every forward is logged with its image name, package key,
vulnerability ID, source update time and outcome, without actors or reasons, and counted in
`nais_v13s_suppression_forwards_total{outcome}`. Successful forwards also log `acknowledged_at`.

Delivery is not guaranteed. There is no outbox or retry: a crash between the source write and
the call loses the forward without a log, and failed or blocked forwards must be repaired by
hand from current source rows. Concurrent or out-of-order changes are not ordered, and deletes
leave no tombstone. Workloads that start running an image name later inherit nothing until the
next change. Existing suppressions are migrated separately, with the same forwarder.

Cutover: migrate existing suppressions and repair what is reported, enable v0s writes in nais/api,
which also rejects writes to v13s, then disable forwarding. Disabling forwarding does not remove
what was forwarded.

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
- **MTTF Calculation** (daily at 5:00 AM CEST): Calculates Mean Time to Fix metrics. Each history point is a cumulative snapshot per severity: it averages the fix duration of every unique vulnerability period fixed by that snapshot date. `fixed_count` is the corresponding cumulative count, not only vulnerabilities fixed that day. A `since` filter uses the snapshot date by default; with `since_type = fixed`, it instead filters on fix date before aggregation.
