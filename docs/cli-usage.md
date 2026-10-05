# CLI Usage

The v13s CLI (`vulnz`) provides an interface for querying vulnerability data.

## Installation

```bash
make install-cli
```

## Configuration

Set the following environment variables or create a `.env` file:

```bash
VULNERABILITIES_URL=localhost:50051
SERVICE_ACCOUNT=v13s-sa@
SERVICE_ACCOUNT_AUDIENCE=vulnz
```

## Filtering by priority

v13s assigns each finding an operational priority: `high`, `elevated`, or `monitor`
(see the glossary in `CONTEXT.md`). `--priority` filters `list` and `get` commands
to an exact tier:

```bash
vulnz list vulns --priority high
vulnz list summary --priority elevated
```

Passing `--priority` with a value other than `high`, `elevated`, or `monitor` is
rejected. The materialized `KEV` column in `list summary` output is the per-workload
count of findings listed in a KEV catalogue (CISA, ENISA, and optionally VulnCheck), a signal rather than a priority tier.
KEV entries are never cleared, so the count also includes findings from a catalogue that has since been disabled.

## Ordering

`--order <field>` sorts results; append `:desc` for descending order, e.g.
`--order kev_count:desc`. Within a priority, results are ordered by fix
availability, then EPSS, CVSS, age, and CVE id, so cursor pagination stays stable.
