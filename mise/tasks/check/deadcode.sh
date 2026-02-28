#!/usr/bin/env bash
#MISE description="Run deadcode for root and pkg/cli modules"
set -euo pipefail

echo "Running deadcode in root module..."
# Run deadcode in the root module with the existing filter
go run golang.org/x/tools/cmd/deadcode@latest -filter "pkg/api/vulnerabilities/options" -test ./...

echo "Running deadcode in pkg/cli module..."
cd pkg/cli
go run golang.org/x/tools/cmd/deadcode@latest -test ./...

