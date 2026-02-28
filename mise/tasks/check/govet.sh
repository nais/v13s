#!/usr/bin/env bash
#MISE description="Run go vet (all modules)"
set -euo pipefail

echo "Running go vet for all modules..."
# For each go.mod, run go vet ./... in that directory
find . -name go.mod -execdir go vet ./... \;
