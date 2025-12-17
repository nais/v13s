# Development Guide

## Prerequisites

- **Go 1.25.5+**
- **Docker** and **Docker Compose**
- **mise** (for task automation)
- **PostgreSQL 15+** (provided via docker-compose)

## Local Setup

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

## Running the API

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

## Running the CLI

See [CLI Usage](cli-usage.md) for installation and usage instructions.

## Testing

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

## Code Generation

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

## Linting and Checks

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

## Database Management

```bash
# Refresh local database (delete and recreate)
make refresh-db

# Connect to a remote database proxy (for debugging)
make connect-db TENANT=nav
```

## Configuration

Configuration is done via environment variables. See [`.env.sample`](../.env.sample) for all available options.

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
