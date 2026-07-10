#!/usr/bin/env bash
# Description: Launch QEMU and run the project edge-device client automatically.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
PROJECT_EDGE_BINARY="${PROJECT_EDGE_BINARY:-optee_example_confidential_iot_edge}"
QEMU_TMUX_SESSION="${QEMU_TMUX_SESSION:-optee-project}"
QEMU_CONTINUE_DELAY="${QEMU_CONTINUE_DELAY:-3}"
QEMU_LOGIN_TIMEOUT="${QEMU_LOGIN_TIMEOUT:-120}"
QEMU_SHELL_TIMEOUT="${QEMU_SHELL_TIMEOUT:-30}"
IMAGE_NAME="${IMAGE_NAME:-confidential-computing-optee:latest}"
# QEMU_INSTANCE lets several devices run concurrently: it derives a distinct
# gdbstub port (qemu_v8.mk otherwise hardcodes -s -> tcp::1234, colliding
# across instances - see scripts/sync-project.sh) and distinct serial-console
# ports per instance, plus a distinct default device_id.
QEMU_INSTANCE="${QEMU_INSTANCE:-0}"
QEMU_PORT_OFFSET=$(( QEMU_INSTANCE * 10 ))
QEMU_NW_PORT="${QEMU_NW_PORT:-$(( 54320 + QEMU_PORT_OFFSET ))}"
QEMU_SW_PORT="${QEMU_SW_PORT:-$(( 54321 + QEMU_PORT_OFFSET ))}"
QEMU_GDB_PORT="${QEMU_GDB_PORT:-$(( 1234 + QEMU_PORT_OFFSET ))}"
DEVICE_ID="${DEVICE_ID:-iot-edge-$(printf '%02d' $((QEMU_INSTANCE + 1)))}"
SERVER_HOST="${SERVER_HOST:-10.0.2.2}"
SERVER_PORT="${SERVER_PORT:-9100}"
PROJECT_PROVISION_SCRIPT="${PROJECT_PROVISION_SCRIPT:-provision-device.sh}"
QEMU_PROVISION_TIMEOUT="${QEMU_PROVISION_TIMEOUT:-120}"
# Attach a virtio NIC with QEMU user-mode (SLIRP) networking so the guest can
# reach the machine running QEMU at 10.0.2.2 (see docs/QEMU_NETWORKING.md).
# Injected into the generated build via qemu_v8.mk's QEMU_BASE_ARGS += $(QEMU_EXTRA_ARGS).
QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--netdev user,id=net0 -device virtio-net-pci,netdev=net0}"

if [[ -z "${IN_OPTEE_DOCKER:-}" && -z "${SKIP_DOCKER:-}" && -f "$ROOT_DIR/docker/Dockerfile" ]] &&
   command -v docker >/dev/null 2>&1; then
  # --network host: QEMU runs inside this container, so SLIRP's 10.0.2.2 points
  # at the container's network stack; host networking makes that the real host,
  # where the CC_Server device listener (:9000) runs.
  docker_args=(--rm --platform linux/amd64 --user "$(id -u):$(id -g)"
    --network host
    -e HOME=/tmp
    -e IN_OPTEE_DOCKER=1
    -e QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS"
    -e PROJECT_EDGE_BINARY="$PROJECT_EDGE_BINARY"
    -e QEMU_TMUX_SESSION="$QEMU_TMUX_SESSION"
    -e QEMU_CONTINUE_DELAY="$QEMU_CONTINUE_DELAY"
    -e QEMU_LOGIN_TIMEOUT="$QEMU_LOGIN_TIMEOUT"
    -e QEMU_SHELL_TIMEOUT="$QEMU_SHELL_TIMEOUT"
    -e QEMU_INSTANCE="$QEMU_INSTANCE"
    -e QEMU_NW_PORT="$QEMU_NW_PORT"
    -e QEMU_SW_PORT="$QEMU_SW_PORT"
    -e QEMU_GDB_PORT="$QEMU_GDB_PORT"
    -e DEVICE_ID="$DEVICE_ID"
    -e SERVER_HOST="$SERVER_HOST"
    -e SERVER_PORT="$SERVER_PORT"
    -e PROJECT_PROVISION_SCRIPT="$PROJECT_PROVISION_SCRIPT"
    -e QEMU_PROVISION_TIMEOUT="$QEMU_PROVISION_TIMEOUT"
    -v "$ROOT_DIR:/workspace/ConfidentialComputing"
    -w /workspace/ConfidentialComputing)

  if [[ -t 0 && -t 1 ]]; then
    docker_args=(-it "${docker_args[@]}")
  fi

  exec docker run "${docker_args[@]}" "$IMAGE_NAME" ./scripts/run-project.sh
fi

if [[ ! -d "$OPTEE_WORKSPACE/build" ]]; then
  echo "Missing OP-TEE build directory in $OPTEE_WORKSPACE" >&2
  echo "Run scripts/bootstrap.sh and scripts/build-project.sh first." >&2
  exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required for the automated project run." >&2
  exit 1
fi

"$ROOT_DIR/scripts/sync-project.sh"

wait_for_pane_text() {
  local target="$1"
  local pattern="$2"
  local timeout="$3"
  local elapsed=0

  while (( elapsed < timeout )); do
    if tmux capture-pane -pt "$target" -S -200 2>/dev/null | grep -Eq "$pattern"; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  return 1
}

if tmux has-session -t "$QEMU_TMUX_SESSION" 2>/dev/null; then
  echo "Attaching to existing tmux session: $QEMU_TMUX_SESSION"
  if [[ -n "${TMUX:-}" ]]; then
    exec tmux switch-client -t "$QEMU_TMUX_SESSION"
  fi
  exec tmux attach-session -t "$QEMU_TMUX_SESSION"
fi

tmux new-session -d -s "$QEMU_TMUX_SESSION" -n qemu \
  "cd '$OPTEE_WORKSPACE/build' && make run-only NcCns=1 QEMU_EXTRA_ARGS='$QEMU_EXTRA_ARGS' QEMU_NW_PORT=$QEMU_NW_PORT QEMU_SW_PORT=$QEMU_SW_PORT QEMU_GDB_PORT=$QEMU_GDB_PORT; printf '\nQEMU exited. Press Enter to close this pane.'; read -r _"

(
  sleep "$QEMU_CONTINUE_DELAY"
  tmux send-keys -t "$QEMU_TMUX_SESSION:0" c C-m 2>/dev/null || true

  for _ in $(seq 1 60); do
    if tmux list-windows -t "$QEMU_TMUX_SESSION" -F '#I' 2>/dev/null | grep -qx '1'; then
      break
    fi
    sleep 1
  done

  tmux select-window -t "$QEMU_TMUX_SESSION:1" 2>/dev/null || true

  if ! wait_for_pane_text "$QEMU_TMUX_SESSION:1.0" "buildroot login:" "$QEMU_LOGIN_TIMEOUT"; then
    tmux display-message -t "$QEMU_TMUX_SESSION" \
      "Timed out waiting for Buildroot login prompt"
    exit 0
  fi

  tmux send-keys -t "$QEMU_TMUX_SESSION:1.0" root C-m 2>/dev/null || true

  if ! wait_for_pane_text "$QEMU_TMUX_SESSION:1.0" "(^|[[:space:]])# ?$" "$QEMU_SHELL_TIMEOUT"; then
    tmux display-message -t "$QEMU_TMUX_SESSION" \
      "Timed out waiting for root shell prompt"
    exit 0
  fi

  # The fTPM device node isn't necessarily usable the instant the shell prompt
  # appears - observed delay exceeds 30s, and isn't tied to any specific
  # action (running the edge binary first doesn't matter). Rather than guess
  # a fixed settle time, retry provision-device.sh itself (safe: it's `set -e`,
  # so a failed attempt leaves no partial /etc/confidential_iot state) until
  # it succeeds or the budget below runs out.
  tmux send-keys -t "$QEMU_TMUX_SESSION:1.0" \
    "i=0; rc=1; while [ \$i -lt 90 ]; do $PROJECT_PROVISION_SCRIPT '$DEVICE_ID' '$SERVER_HOST' '$SERVER_PORT'; rc=\$?; [ \$rc -eq 0 ] && break; i=\$((i+5)); sleep 5; done; echo CIOT_PROVISION_DONE=\$rc" C-m 2>/dev/null || true

  if ! wait_for_pane_text "$QEMU_TMUX_SESSION:1.0" "CIOT_PROVISION_DONE=" "$QEMU_PROVISION_TIMEOUT"; then
    tmux display-message -t "$QEMU_TMUX_SESSION" \
      "Timed out waiting for provision-device.sh to finish"
    exit 0
  fi

  tmux display-message -t "$QEMU_TMUX_SESSION" \
    "Provisioned $DEVICE_ID - see the enrollment record above to submit via POST /api/devices/register"

  tmux send-keys -t "$QEMU_TMUX_SESSION:1.0" "$PROJECT_EDGE_BINARY" C-m 2>/dev/null || true
) &

echo "Started QEMU tmux session: $QEMU_TMUX_SESSION (instance $QEMU_INSTANCE, device_id $DEVICE_ID)"
echo "The script will wait for the login prompt, log in as root, provision $DEVICE_ID, and run: $PROJECT_EDGE_BINARY"

if [[ -n "${TMUX:-}" ]]; then
  exec tmux switch-client -t "$QEMU_TMUX_SESSION"
fi

exec tmux attach-session -t "$QEMU_TMUX_SESSION"
