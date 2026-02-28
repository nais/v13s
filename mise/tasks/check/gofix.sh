#!/usr/bin/env bash
set -euo pipefail

echo "Running go fix..."
find . -name go.mod -execdir go fix -x ./... \;

echo "Running goimports..."
find . -type f -name '*.go' \
  ! -path './internal/sources/dependencytrack/client/*' \
  ! -path './internal/database/sql/*' \
  ! -name '*.pb.go' \
  -exec go run golang.org/x/tools/cmd/goimports@latest -w {} +