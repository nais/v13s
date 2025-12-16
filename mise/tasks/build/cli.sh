#!/usr/bin/env bash
#MISE description="Build the v13s cli binary"
set -euo pipefail

go -C ./pkg/cli build -o ../../bin/vulnz