#!/usr/bin/env bash
#MISE description="Generate protobuf code"
set -euo pipefail

protoc \
  -I pkg/api/vulnerabilities/schemas/ \
  ./pkg/api/vulnerabilities/schemas/*.proto \
  --go_out=. \
  --go-grpc_out=.
