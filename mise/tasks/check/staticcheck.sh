#!/usr/bin/env bash
#MISE description="Run staticcheck for all modules"
set -euo pipefail

# Root module
echo "Running staticcheck in root module..."
go run honnef.co/go/tools/cmd/staticcheck@latest ./...

# CLI module
echo "Running staticcheck in pkg/cli module..."
(cd pkg/cli && go run honnef.co/go/tools/cmd/staticcheck@latest ./...)

# API module
echo "Running staticcheck in pkg/api module..."
(cd pkg/api && go run honnef.co/go/tools/cmd/staticcheck@latest ./...)
