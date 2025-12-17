#!/usr/bin/env bash
#MISE description="Run deadcode"
set -euo pipefail

go tool golang.org/x/tools/cmd/deadcode -filter "pkg/api/vulnerabilities/options" -test ./...
