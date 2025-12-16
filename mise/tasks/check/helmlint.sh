#!/usr/bin/env bash
#MISE description="Run helmlint"
set -euo pipefail

helm lint --strict ./charts
