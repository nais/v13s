#!/usr/bin/env bash
#MISE description="Run staticcheck for all modules"
set -euo pipefail

# Build staticcheck from the root module so every module uses its pinned golang.org/x/tools.
staticcheck="$(go tool -n honnef.co/go/tools/cmd/staticcheck)"

# Root module
echo "Running staticcheck in root module..."
"$staticcheck" ./...

# CLI module
echo "Running staticcheck in pkg/cli module..."
(cd pkg/cli && "$staticcheck" ./...)

# API module
echo "Running staticcheck in pkg/api module..."
(cd pkg/api && "$staticcheck" ./...)
