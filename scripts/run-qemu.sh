#!/usr/bin/env bash
# Description: Sync project sources and launch the OP-TEE QEMU target.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
PROJECT_EDGE_BINARY="${PROJECT_EDGE_BINARY:-optee_example_confidential_iot_edge}"
# Attach a virtio NIC with QEMU user-mode (SLIRP) networking so the guest can
# reach the machine running QEMU at 10.0.2.2 (see docs/QEMU_NETWORKING.md).
# Note: if QEMU runs inside a container (e.g. docker-shell.sh), 10.0.2.2 is the
# container, not the host - start the container with --network host to reach a
# server on the host, or use run-project.sh which does this automatically.
QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--netdev user,id=net0 -device virtio-net-pci,netdev=net0}"

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
  exec tmux new-session -s "${QEMU_TMUX_SESSION:-optee-qemu}" "cd '$OPTEE_WORKSPACE/build' && make run-only NcCns=1 QEMU_EXTRA_ARGS='$QEMU_EXTRA_ARGS'"
fi

exec make run-only NcCns=1 QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS"
