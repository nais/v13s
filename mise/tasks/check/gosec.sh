#!/usr/bin/env bash
#MISE description="Run gosec"
set -euo pipefail

# Run gosec for the main module
go tool github.com/securego/gosec/v2/cmd/gosec --exclude-generated -terse --exclude-dir=pkg/cli ./...

# Run gosec separately for pkg/cli (separate Go module)
(cd pkg/cli && go run github.com/securego/gosec/v2/cmd/gosec@latest --exclude-generated -terse ./...)
