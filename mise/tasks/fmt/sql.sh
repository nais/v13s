#!/usr/bin/env bash
#MISE description="Format sql files using pg_format"
set -euo pipefail

DIR="${1:-.}"
#find "$DIR" -type f -name '*.sql' -print -exec pg_format -i -k --no-space-function {} \;
echo "this commands is disabled temporarily due to pg_format issues on migrations"