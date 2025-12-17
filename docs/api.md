# API Documentation

v13s exposes two gRPC services defined in [pkg/api/vulnerabilities/schemas](../pkg/api/vulnerabilities/schemas).

## Vulnerabilities Service

The Vulnerabilities service provides access to vulnerability data.

### List Operations

- `ListVulnerabilities`: List all vulnerabilities for the given filters (cluster, namespace, workload, workload_type)
- `ListVulnerabilitySummaries`: List all workloads with their vulnerability summaries for the given filters (cluster, namespace, workload, workload_type)
- `ListVulnerabilitiesForImage`: List vulnerabilities for a specific container image
- `ListSuppressedVulnerabilities`: List suppressed vulnerabilities
- `ListSeverityVulnerabilitiesSince`: List vulnerabilities by severity since a given date
- `ListWorkloadsForVulnerabilityById`: List workloads affected by a specific vulnerability ID
- `ListWorkloadsForVulnerability`: List workloads affected by a vulnerability
- `ListMeanTimeToFixTrendBySeverity`: List MTTF trends by severity
- `ListWorkloadMTTFBySeverity`: List workload MTTF by severity

### Get Operations

- `GetVulnerabilitySummary`: Get aggregated vulnerability counts for filters (cluster, namespace, workload, workload_type)
- `GetVulnerabilitySummaryTimeSeries`: Get vulnerability summary over time
- `GetVulnerabilitySummaryForImage`: Get vulnerability summary for a container image
- `GetVulnerabilityById`: Get a specific vulnerability by ID
- `GetVulnerability`: Get vulnerability details
- `GetCve`: Get CVE details

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

See the [CLI usage documentation](cli-usage.md) for examples of how to interact with the API using the command-line client.

For programmatic access, see the [protobuf definitions](../pkg/api/vulnerabilities/schemas) for detailed request/response schemas.
