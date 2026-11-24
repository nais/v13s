#!/usr/bin/env bash
#MISE description="Generate the v0s client from the vendored proto"
set -euo pipefail

proto=v0s/v1/v0s.proto
pkg=github.com/nais/v13s/internal/suppressionforwarding/v0sapi
protoc -I third_party/v0s "$proto" \
  --go_out=internal/suppressionforwarding/v0sapi \
  --go_opt=module="$pkg" \
  --go_opt=M"$proto"="$pkg;v0sapi" \
  --go-grpc_out=internal/suppressionforwarding/v0sapi \
  --go-grpc_opt=module="$pkg" \
  --go-grpc_opt=M"$proto"="$pkg;v0sapi"
