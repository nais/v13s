#!/usr/bin/env bash
#MISE description="Run tests"
set -euo pipefail

go test -v --race --cover --coverprofile=cover.out ./...
