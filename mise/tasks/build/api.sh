#!/usr/bin/env bash
#MISE description="Build the v13s api binary"
set -euo pipefail

go build -o bin/api ./cmd/api