# CLI Usage

The v13s CLI (`vulnz`) provides an interface for querying vulnerability data.

## Installation

```bash
make install-cli
# Or
go build -C ./pkg/cli -o ${GOBIN}/vulnz
```

## Configuration

Set the following environment variables or create a `.env` file:

```bash
VULNERABILITIES_URL=localhost:50051
SERVICE_ACCOUNT=v13s-sa@
SERVICE_ACCOUNT_AUDIENCE=vulnz
```

## List Commands

```bash
# List all workloads
vulnz list workloads

# Filter by cluster and namespace
vulnz list workloads --cluster dev --namespace my-app

# List images
vulnz list images --limit 50
```

## Get Commands

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

## Find Commands

```bash
# Find workloads affected by a CVE
vulnz find cve CVE-2024-1234

# Find workloads using a specific package
vulnz find package --name lodash --version 4.17.20
```

## Management Commands

```bash
# Trigger an update for specific images
vulnz management trigger-update

# Register a workload manually
vulnz management register-workload --cluster dev --namespace my-app --name my-deployment
```
