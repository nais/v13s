# v13s

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE.md)

**v13s** (vulnerabilities) is a Kubernetes-native vulnerability management system that provides a streamlined, workload-focused API for retrieving and tracking container image vulnerability data from multiple sources.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [How It Works](#how-it-works)
  - [Workload Registration](#workload-registration)
  - [Vulnerability Data Updates](#vulnerability-data-updates)
  - [Data Flow](#data-flow)
- [API](#api)
  - [Vulnerabilities Service](#vulnerabilities-service)
  - [Management Service](#management-service)
- [Building and Running Locally](#building-and-running-locally)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  - [Running the API](#running-the-api)
  - [Running the CLI](#running-the-cli)
- [Configuration](#configuration)
- [River Job Queue](#river-job-queue)
  - [Understanding River](#understanding-river)
  - [Updating River Schema](#updating-river-schema)
- [CLI Usage](#cli-usage)
- [Development](#development)
  - [Testing](#testing)
  - [Code Generation](#code-generation)
  - [Linting and Checks](#linting-and-checks)
- [Versioning](#versioning)
- [Contributing](#contributing)

## Overview

v13s continuously monitors Kubernetes workloads (Deployments, NaisJobs) across multiple clusters, automatically tracking container images and their associated vulnerabilities. It provides both a gRPC API and CLI for querying vulnerability data, making it easy to integrate security insights into your development and operations workflows.

## Architecture

v13s consists of several key components:

- **API Server**: gRPC server exposing vulnerability and management services
- **Kubernetes Informers**: Watch workloads across multiple clusters
- **Workload Manager**: Orchestrates workload registration and vulnerability tracking via River job queue
- **Updater**: Periodically syncs vulnerability data from external sources
- **River Job Queue**: Handles asynchronous job processing for workload operations
- **PostgreSQL Database**: Stores workload metadata, vulnerability data, and job state
- **CLI**: Command-line interface for querying vulnerability data

### Component Diagram

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

## Features

- **Multi-cluster workload tracking**: Automatically discovers and tracks workloads across multiple Kubernetes clusters
- **Automated vulnerability scanning**: Integrates with vulnerability sources (e.g., DependencyTrack) to fetch CVE data
- **Attestation verification**: Validates container image attestations using Sigstore/Cosign
- **Historical tracking**: Maintains vulnerability history and calculates metrics like Mean Time to Fix (MTTF)
- **gRPC API**: High-performance API for querying vulnerabilities by workload, image, or cluster
- **CLI tool**: User-friendly command-line interface for vulnerability analysis
- **Job queue**: Asynchronous job processing using River for reliable workload operations
- **Observability**: OpenTelemetry instrumentation with Prometheus metrics and Jaeger tracing

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
- **Mark Untracked** (every 20 minutes): Identifies images no longer in use
- **Mark Unused** (every 30 minutes): Marks images that haven't been seen recently
- **Daily Summary Refresh** (daily at 4:30 AM CEST): Updates materialized views for reporting
- **MTTF Calculation** (daily at 5:00 AM CEST): Calculates Mean Time to Fix metrics

## API

v13s exposes two gRPC services:

### Vulnerabilities Service

Provides read-only access to vulnerability data:

- **GetWorkloadVulnerabilities**: Get vulnerabilities for a specific workload
- **GetImageVulnerabilities**: Get vulnerabilities for a container image
- **GetVulnerabilitySummary**: Get aggregated vulnerability counts
- **GetWorkloadMTTF**: Get Mean Time to Fix metrics for workloads
- **ListWorkloads**: List all tracked workloads with filtering
- **ListImages**: List all tracked images with filtering

### Management Service

Administrative operations:

- **RegisterWorkload**: Manually register a workload for tracking
- **UnregisterWorkload**: Remove a workload from tracking
- **TriggerUpdate**: Force an immediate update of vulnerability data
- **GetJobStatus**: Check the status of background jobs

See the [protobuf definitions](pkg/api/vulnerabilities) for detailed API schemas.

## Building and Running Locally

### Prerequisites

- **Go 1.25.5+**
- **Docker** and **Docker Compose**
- **mise** (for task automation, optional but recommended)
- **PostgreSQL 15+** (provided via docker-compose)

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/nais/v13s.git
   cd v13s
   ```

2. **Start local dependencies**:
   ```bash
   docker compose up -d
   ```

   This starts:
   - PostgreSQL database (port 4002)
   - Adminer (database UI, port 4003)
   - Local Docker registry (port 4004)
   - Prometheus (port 9090)
   - Pushgateway (port 9091)
   - Jaeger (port 16686, optional with `--profile tracing`)

3. **Configure environment**:
   ```bash
   cp .env.sample .env
   # Edit .env with your configuration
   ```

   Key environment variables:
   - `DATABASE_URL`: PostgreSQL connection string
   - `TENANT`: Your tenant/environment name (e.g., dev-nais)
   - `KUBERNETES_CLUSTERS`: Comma-separated list of clusters to watch
   - `DEPENDENCYTRACK_URL`, `DEPENDENCYTRACK_USERNAME`, `DEPENDENCYTRACK_PASSWORD`: Vulnerability source configuration

### Running the API

Using Make:
```bash
make local
```

Or manually:
```bash
# Build the API
mise run build:api
# Or
go build -o bin/api ./cmd/api

# Run the API
./bin/api
```

The API will be available at `localhost:50051` (gRPC) and `localhost:8080` (internal HTTP with metrics and RiverUI).

### Running the CLI

Install the CLI:
```bash
make install-cli
# Or
go build -C ./pkg/cli -o ${GOBIN}/vulnz
```

Use the CLI:
```bash
# List workloads
vulnz list workloads --cluster dev --namespace my-app

# Get vulnerabilities for a workload
vulnz get workload --cluster dev --namespace my-app --name my-deployment

# Get vulnerabilities for an image
vulnz get image --name ghcr.io/myorg/myapp --tag v1.2.3
```

## Configuration

Configuration is done via environment variables. See [`.env.sample`](.env.sample) for all available options.

### Core Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDR` | gRPC server address | `localhost:50051` |
| `INTERNAL_LISTEN_ADDR` | Internal HTTP server address | `localhost:8080` |
| `DATABASE_URL` | PostgreSQL connection URL | Required |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` |
| `LOG_FORMAT` | Log format (text, json) | `text` |

### Kubernetes Settings

| Variable | Description |
|----------|-------------|
| `TENANT` | Tenant/environment identifier |
| `KUBERNETES_CLUSTERS` | Comma-separated list of clusters to monitor |
| `KUBERNETES_SELF_CLUSTER` | Name of the cluster running v13s (optional) |

### Vulnerability Source

| Variable | Description |
|----------|-------------|
| `DEPENDENCYTRACK_URL` | DependencyTrack API URL |
| `DEPENDENCYTRACK_USERNAME` | DependencyTrack username |
| `DEPENDENCYTRACK_PASSWORD` | DependencyTrack password |

### Observability

| Variable | Description |
|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint |
| `PROMETHEUS_METRICS_PUSHGATEWAY_ENDPOINT` | Prometheus pushgateway URL (optional) |

## River Job Queue

### Understanding River

v13s uses [River](https://riverqueue.com/) for asynchronous job processing. River is a robust job queue system built on PostgreSQL that provides:

- **Reliability**: Jobs are stored in PostgreSQL with transactional guarantees
- **Observability**: Built-in job tracking and metrics
- **Concurrency Control**: Per-queue worker pools with configurable max workers
- **Retries**: Automatic retry with exponential backoff
- **UI**: Web interface for monitoring jobs (available at `/riverui` on the internal HTTP server)

The system uses River for several types of jobs:

- **AddWorkload**: Register a new workload in the system
- **GetAttestation**: Fetch attestation from container registry
- **UploadAttestation**: Upload SBOM to vulnerability source
- **FinalizeAttestation**: Complete attestation processing
- **DeleteWorkload**: Remove workload from tracking
- **RemoveFromSource**: Clean up workload from vulnerability source

Each job type has its own queue configuration with specific worker limits (e.g., 10 workers for AddWorkload, 15 for GetAttestation).

### Updating River Schema

When upgrading River or needing to update the database schema:

1. **Generate the migration SQL**:
   ```bash
   river migrate-get --line main --all --up > internal/database/river_schema/river_schema.sql
   ```

2. **Update the migration version** in `internal/job/client.go`:
   ```go
   const RiverMigrationVersion = 6  // Update this to the new version
   ```

3. **Test the migration**:
   ```bash
   # The migration runs automatically on startup
   # Check logs for migration messages
   ```

The River schema is stored in `internal/database/river_schema/river_schema.sql` and is automatically applied when the application starts.

## CLI Usage

The v13s CLI (`vulnz`) provides a convenient interface for querying vulnerability data:

### List Commands

```bash
# List all workloads
vulnz list workloads

# Filter by cluster and namespace
vulnz list workloads --cluster dev --namespace my-app

# List images
vulnz list images --limit 50
```

### Get Commands

```bash
# Get workload vulnerabilities
vulnz get workload --cluster dev --namespace my-app --name my-deployment

# Get image vulnerabilities
vulnz get image --name ghcr.io/myorg/myapp --tag v1.2.3

# Get vulnerability summary
vulnz get summary --cluster dev --namespace my-app --name my-deployment

# Get MTTF metrics
vulnz get mttf --cluster dev --namespace my-app
```

### Find Commands

```bash
# Find workloads affected by a CVE
vulnz find cve CVE-2024-1234

# Find workloads using a specific package
vulnz find package --name lodash --version 4.17.20
```

### Management Commands

```bash
# Trigger an update for specific images
vulnz management trigger-update

# Register a workload manually
vulnz management register-workload --cluster dev --namespace my-app --name my-deployment
```

## Development

### Testing

```bash
# Run unit tests
make test

# Run integration tests (requires Docker)
make test-integration

# Run all tests
make test-all

# Generate coverage report
make test-coverage
```

### Code Generation

The project uses code generation for several components:

```bash
# Generate all (protobuf, SQL queries, mocks)
make generate

# Generate protobuf definitions
make generate-proto

# Generate SQL query code (using sqlc)
make generate-sql

# Generate mocks (using mockery)
make generate-mocks
```

### Linting and Checks

```bash
# Run all checks
make check

# Individual checks
make vet           # Go vet
make fmt           # Go fmt
make staticcheck   # Staticcheck
make vulncheck     # Govulncheck
make deadcode      # Deadcode
make goimport      # Goimports
make helm-lint     # Helm chart linting
```

### Database Management

```bash
# Refresh local database (delete and recreate)
make refresh-db

# Connect to a remote database proxy (for debugging)
make connect-db TENANT=nav
```

## Versioning

This project uses [Semantic Versioning](https://semver.org/). Version tags (e.g., v1.0.0) are applied to releases.

### Client Package Versioning

The client package in `pkg/api` is designed to be imported with a specific version. Users should pin to a specific version tag for stability:

```bash
# Install a specific version
go get github.com/nais/v13s@v1.0.0
```

Then import normally in your Go code:

```go
import "github.com/nais/v13s/pkg/api/vulnerabilities"
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`make check test`)
5. Commit your changes with clear messages
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Notes

- Use `goimports` for formatting
- Follow existing code patterns
- Add tests for new functionality
- Update documentation as needed
- Keep dependencies up to date

## Notes/TODOs

* Consider adding a separate go.mod in the pkg directory to not expose all our dependencies to the users. This will also
  allow us to have a cleaner go.mod file in the root directory.
  Add a replace directive in the main go.mod file to point to the local path of the pkg directory so it doesn't fetch
  the package from the internet. See github.com/nais/api for an example.
* Should we create a new row for each workload or do a update? If we do create we have a history of all workloads and
  images tags. If we do a update we only have the latest image tag for each workload. We still have the history of all
  images tags in the image table.

