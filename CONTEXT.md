# CONTEXT

## Glossary

- **Workload**: a Kubernetes Deployment or Job tracked by v13s.
- **Image**: the container image used by a workload.
- **SBOM**: the attestation uploaded for an image.
- **Vulnerability summary**: the per-image or per-workload count of vulnerabilities and risk data.
- **Priority**: the operational threat tier of a CVE or workload — `HIGH`, `ELEVATED`, or `MONITOR` in the API.
- **Risk tier**: the database representation of Priority, an integer where lower is more severe (`2` = `HIGH`, `3` = `ELEVATED`, `4` = `MONITOR`). Stored as `cve.priority` and `vulnerability_summary.top_risk_tier`. Tier `1` is reserved (formerly `ACT_NOW`) and never produced by v13s.
- **Updater**: the part that syncs vulnerability data from external sources.
- **Workload resync**: an operation that marks selected Workload and Image records for resync, enqueues Workload processing, and may trigger one updater cycle.
- **Workload manager**: the part that reacts to workload changes and enqueues jobs.
- **DependencyTrack**: the external source used to upload SBOMs and fetch findings.
- **KEV**: known exploited vulnerabilities, merged from the CISA and ENISA catalogs (and VulnCheck KEV when enabled); `cve_kev_source` holds one row per CVE and catalog with that catalog's ransomware claim, and `cve.has_kev_entry`/`cve.known_ransomware_use` are derived from it (ransomware when any catalog's last listing says so). KEV entries are never cleared: a CVE stays KEV, with its last ransomware claim, even if its catalog drops it or the source fails or is disabled (hide unwanted findings with suppression). To retire a source for good, delete its `cve_kev_source` rows; the next KEV sync recomputes the flags. `vulnerability_summary.kev_count` is the per-image count of findings in it — a signal, not a priority tier.
- **OSV**: the Open Source Vulnerabilities source.
- **River job**: an async job handled through River.

## Rules

- Use the glossary terms exactly.
- Prefer one term for one concept.
- If a new term appears often, add it here.
