#!/usr/bin/env bash
set -euo pipefail

echo "Running go fix..."
find . -name go.mod -execdir go fix ./... \;
