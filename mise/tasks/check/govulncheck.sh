#!/usr/bin/env bash
#MISE description="Run govulncheck"
set -euo pipefail

# -exclude=GO-2025-3770 Several
# Sigstore-related modules (e.g., cosign, rekor, sigstore-go, timestamp-authority) are pulling in the vulnerable version
# Ignore until we can update to a version that is not vulnerable
echo "Running vulncheck and showing only vulnerabilities with fixes..."
go run golang.org/x/vuln/cmd/govulncheck@latest ./... \
  | awk '/^GO:|^module:|Fixed in:/ {print}' \
  | paste - - - \
  | column -t -s $'\t'
