#!/usr/bin/env bash
#MISE description="Run gosec"
set -euo pipefail

# Build gosec from the root module so every module uses its pinned golang.org/x/tools.
gosec="$(go tool -n github.com/securego/gosec/v2/cmd/gosec)"

# Run gosec for the main module
"$gosec" --exclude-generated -terse --exclude-dir=pkg/cli ./...

# Run gosec separately for pkg/cli (separate Go module)
(cd pkg/cli && "$gosec" --exclude-generated -terse ./...)

# Run gosec separatly for pkg/api (separate Go module)
(cd pkg/api && "$gosec" --exclude-generated -terse ./...)
