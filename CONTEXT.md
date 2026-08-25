# CONTEXT

## Glossary

- **Workload**: a Kubernetes Deployment or Job tracked by v13s.
- **Image**: the container image used by a workload.
- **SBOM**: the attestation uploaded for an image.
- **Vulnerability summary**: the per-image or per-workload count of vulnerabilities and risk data.
- **Updater**: the part that syncs vulnerability data from external sources.
- **Workload resync**: an operation that marks selected Workload and Image records for resync, enqueues Workload processing, and may trigger one updater cycle.
- **Workload manager**: the part that reacts to workload changes and enqueues jobs.
- **DependencyTrack**: the external source used to upload SBOMs and fetch findings.
- **KEV**: the CISA Known Exploited Vulnerabilities catalog.
- **OSV**: the Open Source Vulnerabilities source.
- **River job**: an async job handled through River.

## Rules

- Use the glossary terms exactly.
- Prefer one term for one concept.
- If a new term appears often, add it here.
