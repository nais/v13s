#!/usr/bin/env bash
#MISE description="Run staticcheck"
set -euo pipefail

go run honnef.co/go/tools/cmd/staticcheck@latest -f=stylish  ./...
