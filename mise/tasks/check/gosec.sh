#!/usr/bin/env bash
#MISE description="Run gosec"
set -euo pipefail

go tool github.com/securego/gosec/v2/cmd/gosec --exclude G404,G101,G115,G402 --exclude-generated -terse ./...
