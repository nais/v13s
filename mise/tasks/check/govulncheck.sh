#!/usr/bin/env bash
#MISE description="Run govulncheck"
set -euo pipefail

echo "Running govulncheck..."

set +e
out="$(go tool golang.org/x/vuln/cmd/govulncheck ./... 2>&1)"
status=$?
set -e

if [[ $status -ne 0 ]] && ! echo "$out" | grep -q '^Vulnerability #'; then
  echo "$out" >&2
  exit "$status"
fi

if echo "$out" | grep -E '^    Fixed in:' | grep -v 'N/A' >/dev/null; then
  echo "$out" | awk '
    /^Vulnerability/ { block=$0; next }
    /^    Fixed in:/ {
      block=block "\n" $0
      if ($0 !~ /N\/A/) { print block; block="" }
      next
    }
    block { block=block "\n" $0 }
  '
  echo "At least one vulnerability has a fix available." >&2
  exit 1
fi

echo "$out" | awk '
  /^Vulnerability/ { vuln=$0 }
  /^    Fixed in: N\/A/ { print vuln }
'

echo "Only vulnerabilities without fixes found."
exit 0
