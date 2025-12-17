#!/usr/bin/env bash
#MISE description="Format sql files using pg_format"
set -euo pipefail

DIR="${1:-.}"

./scripts/goose-function-precommit-hook.sh "$DIR" || {
  echo "Goose migration check failed. Aborting format."
  exit 1
}

find "$DIR" \
  -type d -name river_schema -prune -o \
  -type f -name '*.sql' -print \
  -exec pg_format -i -c ./.configs/pg_format.conf {} \;
#  -exec pg_format -U 2 -i -k --no-space-function {} \;
