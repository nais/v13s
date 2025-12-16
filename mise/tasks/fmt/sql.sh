#!/usr/bin/env bash
#MISE description="Format sql files using pg_format"
set -euo pipefail

DIR="${1:-.}"

./scripts/goose-function-precommit-hook.sh "$DIR" || {
  echo "Goose migration check failed. Aborting format."
  exit 1
}

find "$DIR" -type f -name '*.sql' -print -exec pg_format -U 2 -i -k --no-space-function {} \;
echo "this commands is disabled temporarily due to pg_format issues on migrations"