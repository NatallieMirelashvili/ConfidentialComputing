#!/usr/bin/env bash
# Description: Sync project sources and launch the OP-TEE QEMU target.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"

if [[ ! -d "$OPTEE_WORKSPACE/build" ]]; then
  echo "Missing OP-TEE build directory in $OPTEE_WORKSPACE" >&2
  echo "Run scripts/bootstrap.sh and scripts/build.sh first." >&2
  exit 1
fi

"$ROOT_DIR/scripts/sync-project.sh"

cd "$OPTEE_WORKSPACE/build"

if [[ -z "${TMUX:-}" ]]; then
  exec tmux new-session -s "${QEMU_TMUX_SESSION:-optee-qemu}" "cd '$OPTEE_WORKSPACE/build' && make run-only NcCns=1"
fi

exec make run-only NcCns=1
