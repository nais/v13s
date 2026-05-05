#!/usr/bin/env bash
#MISE description="Run go fix"
set -euo pipefail

echo "Running go fix..."

# Produce a sorted, filename-associated checksum list for all .go files.
# md5sum (Linux) emits "<hash>  <file>"; md5 -r (macOS) emits the same format.
# Both branches are piped through sort -k2 so traversal order never affects the
# comparison.
checksums() {
  { find . -name '*.go' -exec md5sum {} + 2>/dev/null \
      || find . -name '*.go' -exec md5 -r {} + 2>/dev/null; \
  } | sort -k2
}

before=$(checksums)

find . -name go.mod -execdir go fix ./... \;

after=$(checksums)

if [[ "$before" != "$after" ]]; then
  echo "go fix modified files — please run 'go fix ./...' locally and commit the changes" >&2
  exit 1
fi
