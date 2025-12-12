#!/usr/bin/env bash
#MISE description="Run gosec"
set -euo pipefail

go run github.com/securego/gosec/v2/cmd/gosec@latest --exclude G404,G101,G115,G402 --exclude-generated -terse ./...
