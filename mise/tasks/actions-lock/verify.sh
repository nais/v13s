#!/usr/bin/env bash
#MISE description="Verify GitHub Actions workflow dependencies against actions.lock"
set -euo pipefail

gh actions-lock --verify
