#!/usr/bin/env bash
#MISE description="Run go fix"
set -euo pipefail

echo "Running go fix..."

# Snapshot checksums of all .go files before running go fix
before=$(find . -name '*.go' -exec md5 -q {} + 2>/dev/null || find . -name '*.go' -exec md5sum {} + 2>/dev/null)

go fix ./...

# Snapshot checksums after
after=$(find . -name '*.go' -exec md5 -q {} + 2>/dev/null || find . -name '*.go' -exec md5sum {} + 2>/dev/null)

if [[ "$before" != "$after" ]]; then
  echo "go fix modified files — please run 'go fix ./...' locally and commit the changes" >&2
  exit 1
fi
