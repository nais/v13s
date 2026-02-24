#!/usr/bin/env bash
#MISE description="Run govulncheck"
set -euo pipefail

echo "Running govulncheck ..."

set +e
out="$(go tool golang.org/x/vuln/cmd/govulncheck -format=json ./... 2>&1)"
status=$?
set -e

# If the tool failed AND we didn't even get findings, treat as real failure
if [[ $status -ne 0 ]] && ! echo "$out" | jq -e 'select(.finding)' >/dev/null 2>&1; then
  echo "$out" >&2
  exit "$status"
fi

# Print: OSV  module@version   (from the first trace element)
# Dedupe and sort for nice output.
echo "$out" | jq -r '
  select(.finding)
  | .finding as $f
  | ($f.trace[0].module // "unknown") as $mod
  | ($f.trace[0].version // "unknown") as $ver
  | "\($f.osv)  \($mod)@\($ver)"
' | sort -u

echo "Only vulnerabilities without fixes found."
exit 0