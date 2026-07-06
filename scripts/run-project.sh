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

if [[ -z "${IN_OPTEE_DOCKER:-}" && -z "${SKIP_DOCKER:-}" && -f "$ROOT_DIR/docker/Dockerfile" ]] &&
   command -v docker >/dev/null 2>&1; then
  docker_args=(--rm --platform linux/amd64 --user "$(id -u):$(id -g)"
    -e HOME=/tmp
    -e IN_OPTEE_DOCKER=1
    -e PROJECT_EDGE_BINARY="$PROJECT_EDGE_BINARY"
    -e QEMU_TMUX_SESSION="$QEMU_TMUX_SESSION"
    -e QEMU_CONTINUE_DELAY="$QEMU_CONTINUE_DELAY"
    -e QEMU_LOGIN_TIMEOUT="$QEMU_LOGIN_TIMEOUT"
    -e QEMU_SHELL_TIMEOUT="$QEMU_SHELL_TIMEOUT"
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
  "cd '$OPTEE_WORKSPACE/build' && make run-only NcCns=1; printf '\nQEMU exited. Press Enter to close this pane.'; read -r _"

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

  tmux send-keys -t "$QEMU_TMUX_SESSION:1.0" "$PROJECT_EDGE_BINARY" C-m 2>/dev/null || true
) &

echo "Started QEMU tmux session: $QEMU_TMUX_SESSION"
echo "The script will wait for the login prompt, log in as root, and run: $PROJECT_EDGE_BINARY"

if [[ -n "${TMUX:-}" ]]; then
  exec tmux switch-client -t "$QEMU_TMUX_SESSION"
fi

exec tmux attach-session -t "$QEMU_TMUX_SESSION"
