#!/usr/bin/env bash
#MISE description="Build the v13s cli binary"
set -euo pipefail

go build -C ./pkg/cli -o ../../bin/vulnz