# v13s

v13s monitors Kubernetes workloads across multiple clusters and tracks container image vulnerabilities from external sources like DependencyTrack.

## What it does

- Watches Kubernetes Deployments and NaisJobs across clusters
- Fetches and verifies container image attestations (SBOMs)
- Syncs vulnerability data from external sources
- Provides gRPC API and CLI for querying vulnerability information
- Tracks vulnerability history and calculates Mean Time to Fix (MTTF)

## Documentation

- [Architecture](docs/architecture.md) - System components and data flow
- [API](docs/api.md) - gRPC service documentation
- [Development](docs/development.md) - Local setup, building, and testing
- [CLI Usage](docs/cli-usage.md) - Command-line interface examples
- [River Job Queue](docs/river.md) - Job queue system and schema updates

## Quick Start

```bash
# Start dependencies
docker compose up -d

# Configure
cp .env.sample .env
# Edit .env with your settings

# Build and run
make local
```

API available at:
- gRPC: `localhost:50051`
- Internal HTTP (metrics, RiverUI): `localhost:8080`

See [development documentation](docs/development.md) for detailed setup instructions.

## Client Package

```bash
go get github.com/nais/v13s/pkg/api@v1.0.0
```

```go
import "github.com/nais/v13s/pkg/api/vulnerabilities"
```

## License

[Apache 2.0](LICENSE.md)

