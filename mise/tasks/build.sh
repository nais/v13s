#!/usr/bin/env bash
#MISE description="Build the Nais CLI binary"
set -euo pipefail

go build -o bin/api ./cmd/api