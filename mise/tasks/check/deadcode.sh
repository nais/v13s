#!/usr/bin/env bash
#MISE description="Run deadcode"
set -euo pipefail

go run golang.org/x/tools/cmd/deadcode@latest -filter "pkg/api/vulnerabilities/options" -test ./...
