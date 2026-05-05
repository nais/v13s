#!/usr/bin/env bash
#MISE description="Run goimports"
set -euo pipefail

echo "Running goimports..."
unformatted=$(find . -type f -name '*.go' \
  ! -name '*.pb.go' \
  -exec go tool golang.org/x/tools/cmd/goimports -l {} +)

if [[ -n "$unformatted" ]]; then
  echo "goimports found files needing changes — please run 'goimports -w' locally and commit the changes:" >&2
  echo "$unformatted" >&2
  exit 1
fi
