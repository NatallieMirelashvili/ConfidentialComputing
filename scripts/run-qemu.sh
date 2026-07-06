#!/usr/bin/env bash
# Description: Sync project sources and launch the OP-TEE QEMU target.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
PROJECT_EDGE_BINARY="${PROJECT_EDGE_BINARY:-optee_example_confidential_iot_edge}"

if [[ ! -d "$OPTEE_WORKSPACE/build" ]]; then
  echo "Missing OP-TEE build directory in $OPTEE_WORKSPACE" >&2
  echo "Run scripts/bootstrap.sh and scripts/build.sh first." >&2
  exit 1
fi

"$ROOT_DIR/scripts/sync-project.sh"

cd "$OPTEE_WORKSPACE/build"

echo "After QEMU boots, log in to the Normal World console as root and run:"
echo "  $PROJECT_EDGE_BINARY"

if [[ -z "${TMUX:-}" ]]; then
  exec tmux new-session -s "${QEMU_TMUX_SESSION:-optee-qemu}" "cd '$OPTEE_WORKSPACE/build' && make run-only NcCns=1"
fi

exec make run-only NcCns=1
