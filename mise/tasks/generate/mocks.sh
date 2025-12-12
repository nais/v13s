#!/usr/bin/env bash
#MISE description="Generate mocks"
set -euo pipefail

find internal pkg -type f -name "mock_*.go" -delete
go run github.com/vektra/mockery/v2 --config ./.configs/mockery.yaml
find internal pkg -type f -name "mock_*.go" -exec go run mvdan.cc/gofumpt@latest -w {} \;
