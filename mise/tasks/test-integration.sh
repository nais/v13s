#!/usr/bin/env bash
#MISE description="Run integration tests (requires Docker)"
set -euo pipefail

go test -v -count=1 -tags integration_test \
  github.com/nais/v13s/internal/api/grpcvulnerabilities \
  github.com/nais/v13s/internal/updater
