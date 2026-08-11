#!/bin/sh
# Standalone idempotent PATH-shim installer for reach-guard.
# Usage: scripts/install_shims.sh [--dry-run]
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec "$DIR/.venv/bin/reach-guard" shims install "$@"
