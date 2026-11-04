# API Documentation

v13s exposes gRPC services defined in [pkg/api/vulnerabilities/schemas](../pkg/api/vulnerabilities/schemas).
in two main services: `Vulnerabilities` and `Management`.

There is a client interface available at [pkg/api/vulnerabilities/client.go](../pkg/api/vulnerabilities/client.go) for easy programmatic access.

## Vulnerabilities Service

The Vulnerabilities service provides access to vulnerability data.

### List Operations

List operations retrieve collections of vulnerability-related data based on various filters, e.g.:

- `ListVulnerabilitySummaries`: List all workloads with their vulnerability summaries for the given filters (cluster, namespace, workload, workload_type), SBOM statuses and user labels. Label filters match user labels only; a filter without a value matches any workload that has the key.
- `ListVulnerabilitiesForImage`: List vulnerabilities for a specific container image
- ... and more.

See the interface [pkg/api/vulnerabilities/client.go](../pkg/api/vulnerabilities/client.go) definitions for the full list of available operations.

### Get Operations

Get operations retrieve specific vulnerability data, and typically return one item, e.g.:

- `GetVulnerabilitySummary`: Get aggregated vulnerability counts for filters (cluster, namespace, workload, workload_type)
- `GetVulnerabilitySummaryTimeSeries`: Get vulnerability summary over time
- `GetVulnerabilitySummaryForImage`: Get vulnerability summary for a container image
- `GetVulnerabilityById`: Get a specific vulnerability by ID
- `GetCve`: Get CVE details

See the interface [pkg/api/vulnerabilities/client.go](../pkg/api/vulnerabilities/client.go) definitions for the full list of available operations.

### Generated CVE explanations

Only `GetCve` populates `Cve.explanation`, and only when `CVE_EXPLANATIONS_VISIBLE=true`.
Clients must render `summary` and `action` as plain text, label them as AI-generated and show `source_urls`.
The explanation is general advisory guidance, not a reachability assessment or a version-specific upgrade recommendation.
Package upgrade information still comes from `Vulnerability.fix_version`.

Generation is disabled by default (`UPDATER_EXPLAIN_CVES_ENABLED=false`).
When enabled, the updater uses only public CISA catalog fields for KEV CVEs on active workloads.
No package, image, workload or DependencyTrack data is sent to the model.
CVEs without a current public CISA entry are skipped.

Configure `LLM_VERTEX_PROJECT`, `LLM_VERTEX_REGION` (an EU region) and `LLM_MODEL` (a Gemini model ID).
The model must support structured output in that region. Authentication uses application default credentials
from workload identity; the service account needs Vertex access, and the project needs the Vertex API enabled.
The chart permits HTTPS egress to that regional endpoint only when generation is enabled.
IAM and API enablement must be provisioned separately.

`UPDATER_EXPLAIN_CVES_MAX_PER_RUN` limits calls including retries (default `200`),
`UPDATER_EXPLAIN_CVES_CONCURRENCY` defaults to `2`, and `LLM_MAX_OUTPUT_TOKENS` defaults to `400`.
The default schedule is `0 9 * * *` (`UPDATER_EXPLAIN_CVES_CRON`).
Changed source inputs or prompt versions trigger regeneration; outdated explanations are hidden on a failed attempt.
Disable generation to stop new calls, and disable visibility to hide stored explanations.
Neither action deletes stored data or reverses data already sent to Vertex.
Evaluate output quality and approve data handling before enabling generation or visibility.

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
