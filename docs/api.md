# API Documentation

v13s exposes gRPC services defined in [pkg/api/vulnerabilities/schemas](../pkg/api/vulnerabilities/schemas).
in two main services: `Vulnerabilities` and `Management`.

There is a client interface available at [pkg/api/vulnerabilities/client.go](../pkg/api/vulnerabilities/client.go) for easy programmatic access.

## Vulnerabilities Service

The Vulnerabilities service provides access to vulnerability data.

### List Operations

List operations retrieve collections of vulnerability-related data based on various filters, e.g.:

- `ListVulnerabilities`: List all vulnerabilities for the given filters (cluster, namespace, workload, workload_type)
- `ListVulnerabilitySummaries`: List all workloads with their vulnerability summaries for the given filters (cluster, namespace, workload, workload_type)
- `ListVulnerabilitiesForImage`: List vulnerabilities for a specific container image
- ... and more.

See the interface [pkg/api/vulnerabilities/client.go](../pkg/api/vulnerabilities/client.go) definitions for the full list of available operations.

### Get Operations

Get operations retrieve specific vulnerability data, and typically return one item, e.g.:

- `GetVulnerabilitySummary`: Get aggregated vulnerability counts for filters (cluster, namespace, workload, workload_type)
- `GetVulnerabilitySummaryTimeSeries`: Get vulnerability summary over time
- `GetVulnerabilitySummaryForImage`: Get vulnerability summary for a container image
- `GetVulnerabilityById`: Get a specific vulnerability by ID
- `GetVulnerability`: Get vulnerability details
- `GetCve`: Get CVE details

See the interface [pkg/api/vulnerabilities/client.go](../pkg/api/vulnerabilities/client.go) definitions for the full list of available operations.

### Suppress Operations

- `SuppressVulnerability`: Suppress a vulnerability

## Management Service

The Management service provides administrative operations.

- `RegisterWorkload`: Manually register a workload for tracking
- `GetWorkloadStatus`: Get the status of workloads (workload state, image state, etc.)
- `GetWorkloadJobs`: Get River jobs associated with a workload
- `Resync`: Trigger a resync of workload vulnerability data
- `DeleteWorkload`: Remove a workload from tracking

## API Usage

See the [CLI usage documentation](cli-usage.md) for how to interact with the API using the command-line client.

For programmatic access, see the interface [pkg/api/vulnerabilities/client.go](../pkg/api/vulnerabilities/client.go) and the [protobuf definitions](../pkg/api/vulnerabilities/schemas) for detailed request/response schemas.
