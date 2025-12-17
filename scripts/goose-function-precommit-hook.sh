#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: $0 <folder> [folder ...]" >&2
  exit 2
fi

fail=0

while IFS= read -r -d '' file; do
  # Only care about files that define functions / DO blocks
  if ! grep -Eqi '\bCREATE[[:space:]]+(OR[[:space:]]+REPLACE[[:space:]]+)?FUNCTION\b|^[[:space:]]*DO[[:space:]]+\$' "$file"; then
    continue
  fi

  # Must be a goose migration
  if ! grep -qi '^[[:space:]]*--[[:space:]]*+goose[[:space:]]\+Up' "$file"; then
    echo "$file defines a function but is missing '-- +goose Up', skipping ..."
    continue
  fi

  # Must have StatementBegin
  if ! grep -qi '^[[:space:]]*--[[:space:]]*+goose[[:space:]]\+StatementBegin' "$file"; then
    echo "❌ Goose migration defines a function but is missing '-- +goose StatementBegin':"
    echo "   $file"
    fail=1
  fi

  if ! grep -qi '^[[:space:]]*--[[:space:]]*+goose[[:space:]]\+StatementEnd' "$file"; then
      echo "❌ Goose migration defines a function but is missing '-- +goose StatementEnd':"
      echo "   $file"
      fail=1
  fi

done < <(find "$@" -type f -name '*.sql' -print0)

exit "$fail"
