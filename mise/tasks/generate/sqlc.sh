#!/usr/bin/env bash
#MISE description="Generate sqlc code"
set -euo pipefail

go run github.com/sqlc-dev/sqlc/cmd/sqlc generate -f .configs/sqlc.yaml
go run github.com/sqlc-dev/sqlc/cmd/sqlc vet -f .configs/sqlc.yaml
