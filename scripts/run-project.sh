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
# Chardev backend for the sensor_link PTA's secure UART2 (see
# scripts/sync-project.sh's virt-uart2.patch application and
# project/patches/virt-uart2.patch) - this is where the external
# sensor_daemon process (started below, before QEMU launches) connects, as
# if plugging a serial cable into a port only Secure World can read.
QEMU_SENSOR_PORT="${QEMU_SENSOR_PORT:-$(( 54322 + QEMU_PORT_OFFSET ))}"
DEVICE_ID="${DEVICE_ID:-iot-edge-$(printf '%02d' $((QEMU_INSTANCE + 1)))}"
SERVER_HOST="${SERVER_HOST:-10.0.2.2}"
SERVER_PORT="${SERVER_PORT:-9100}"
# Management server's admin API port (POST /api/devices/register), for the
# device's own self-registration (see edge_device.c's edge_register_with_server()) -
# distinct from SERVER_PORT above, the device-facing attestation port.
API_PORT="${API_PORT:-8000}"
PROJECT_PROVISION_SCRIPT="${PROJECT_PROVISION_SCRIPT:-provision-device.sh}"
QEMU_PROVISION_TIMEOUT="${QEMU_PROVISION_TIMEOUT:-120}"
# Attach a virtio NIC with QEMU user-mode (SLIRP) networking so the guest can
# reach the machine running QEMU at 10.0.2.2 (see docs/QEMU_NETWORKING.md).
# Injected into the generated build via qemu_v8.mk's QEMU_BASE_ARGS += $(QEMU_EXTRA_ARGS).
QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--netdev user,id=net0 -device virtio-net-pci,netdev=net0}"

# --- Fresh device on a detected rebuild (server-key TOFU reset) -------------
# The device pins the server's identity public key on first use (TOFU) and is
# then locked to it (docs/HANDOFF_serverAuthentication.md). A rebuild can
# rotate the server's identity key, which would permanently lock a pinned
# device out. So when scripts/build.sh's build stamp changes, wipe this
# instance's persistent disk to a FRESH DEVICE: empty secure storage means a
# new Attestation Key AND a fresh server-key TOFU on the next attestation.
# A plain relaunch or a guest 'reboot' (unchanged stamp) keeps everything.
#
# Done here, HOST-side before the Docker re-exec, so the registry reset below
# has CC_Server's Python env; deleting the disk image only needs its path, and
# the in-Docker block further down recreates + formats a blank disk if missing.
# A fresh disk means a new AK, and the server rejects a known device_id that
# re-registers with a different key (409, docs/SELF_REGISTRATION_IMPLEMENTATION.md
# §6), so drop the stale registry entry too (then restart CC_Server).
if [[ -z "${IN_OPTEE_DOCKER:-}" ]]; then
  _reset_state_dir="${DEVICE_STATE_DIR:-$ROOT_DIR/.device-state}"
  _reset_tag="iot-edge-$(printf '%02d' $((QEMU_INSTANCE + 1)))"
  _reset_disk="$_reset_state_dir/$_reset_tag.img"
  _reset_stamp="$_reset_state_dir/$_reset_tag.build-stamp"
  if [[ -f "$ROOT_DIR/.build-stamp" ]]; then
    _current_stamp="$(cat "$ROOT_DIR/.build-stamp")"
    _stored_stamp=""
    [[ -f "$_reset_stamp" ]] && _stored_stamp="$(cat "$_reset_stamp")"
    # Only wipe when a *previous* stamp was recorded and differs - never on the
    # first run after adopting this feature (that would gratuitously drop an
    # already-working pinned device).
    if [[ -f "$_reset_disk" && -n "$_stored_stamp" && "$_stored_stamp" != "$_current_stamp" ]]; then
      echo "run-project: rebuild detected for $DEVICE_ID (build stamp changed) ->" >&2
      echo "             wiping to a fresh device: new Attestation Key + fresh server TOFU pin." >&2
      rm -f "$_reset_disk"
      # Benign non-zero exit if the id wasn't enrolled; real removals print
      # their own 'restart CC_Server' reminder.
      "$ROOT_DIR/scripts/reset-device-registry.sh" "$DEVICE_ID" || true
    fi
    mkdir -p "$_reset_state_dir"
    printf '%s' "$_current_stamp" > "$_reset_stamp"
  fi
fi

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
    -e QEMU_SENSOR_PORT="$QEMU_SENSOR_PORT"
    -e DEVICE_ID="$DEVICE_ID"
    -e SERVER_HOST="$SERVER_HOST"
    -e SERVER_PORT="$SERVER_PORT"
    -e API_PORT="$API_PORT"
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

# Persistent per-instance virtual disk so the fTPM's REE-FS secure storage
# (/var/lib/tee, mounted by S29tee-storage before tee-supplicant starts)
# survives a QEMU reboot and the device's Attestation Key doesn't have to be
# re-provisioned/re-registered every run. See docs/HANDOFF_persistentAK.md.
# Computed here (not in the QEMU_EXTRA_ARGS default above) so the path is
# always correct for wherever QEMU actually runs: this script re-execs itself
# inside Docker above, and $ROOT_DIR resolves to the container's bind-mounted
# path in that case, the host path otherwise.
DEVICE_STATE_DIR="${DEVICE_STATE_DIR:-$ROOT_DIR/.device-state}"
DEVICE_DISK_IMG="${DEVICE_DISK_IMG:-$DEVICE_STATE_DIR/iot-edge-$(printf '%02d' $((QEMU_INSTANCE + 1))).img}"
mkdir -p "$DEVICE_STATE_DIR"
if [[ ! -f "$DEVICE_DISK_IMG" ]]; then
  # Pre-format on the host (native x86_64 e2fsprogs, no cross-compilation
  # needed) rather than in the guest: the Buildroot rootfs has no mkfs.ext4,
  # and cross-building e2fsprogs pulls in a broken util-linux/util-linux-libs
  # dependency split in this Buildroot snapshot. mkfs.ext4 can format a plain
  # regular file directly, no loop device required.
  truncate -s 64M "$DEVICE_DISK_IMG"
  mkfs.ext4 -q -F "$DEVICE_DISK_IMG"
fi
QEMU_EXTRA_ARGS="$QEMU_EXTRA_ARGS -drive if=none,file=$DEVICE_DISK_IMG,format=raw,id=hd1 -device virtio-blk-device,drive=hd1"

# Sensor Module pairing secret, host-side copy (see scripts/pair-sensor.sh
# and sensor_module/sensor_daemon.c's --secret). Same per-instance naming
# convention as DEVICE_DISK_IMG above.
SENSOR_SECRET_FILE="${SENSOR_SECRET_FILE:-$DEVICE_STATE_DIR/iot-edge-$(printf '%02d' $((QEMU_INSTANCE + 1))).sensor-secret}"
SENSOR_DAEMON_BIN="${SENSOR_DAEMON_BIN:-$ROOT_DIR/project/optee_examples/confidential_iot/sensor_module/sensor_daemon}"

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

# Generate/reuse the Sensor Module pairing secret and start sensor_daemon
# listening BEFORE QEMU launches: QEMU's 3rd -serial backend
# (QEMU_SENSOR_PORT) connects out to it as a TCP client at machine-init time,
# not lazily on first UART access - if nothing is listening yet, QEMU fails
# to start at all ("Failed to connect ... Connection refused"). Pushing the
# secret into the TA itself (over the guest console) still has to wait for
# login, below - only the daemon *process* needs to be up this early.
SENSOR_SECRET_B64=$("$ROOT_DIR/scripts/pair-sensor.sh" "$SENSOR_SECRET_FILE")
if [[ -x "$SENSOR_DAEMON_BIN" ]]; then
  "$SENSOR_DAEMON_BIN" --port "$QEMU_SENSOR_PORT" --secret "$SENSOR_SECRET_FILE" \
    >"$DEVICE_STATE_DIR/iot-edge-$(printf '%02d' $((QEMU_INSTANCE + 1))).sensor-daemon.log" 2>&1 &
else
  echo "sensor_daemon not built at $SENSOR_DAEMON_BIN - run scripts/build-project.sh" >&2
  exit 1
fi

tmux new-session -d -s "$QEMU_TMUX_SESSION" -n qemu \
  "cd '$OPTEE_WORKSPACE/build' && make run-only NcCns=1 QEMU_EXTRA_ARGS='$QEMU_EXTRA_ARGS' QEMU_NW_PORT=$QEMU_NW_PORT QEMU_SW_PORT=$QEMU_SW_PORT QEMU_GDB_PORT=$QEMU_GDB_PORT QEMU_SENSOR_PORT=$QEMU_SENSOR_PORT; printf '\nQEMU exited. Press Enter to close this pane.'; read -r _"

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
    "i=0; rc=1; while [ \$i -lt 90 ]; do ADMIN_PORT='$API_PORT' $PROJECT_PROVISION_SCRIPT '$DEVICE_ID' '$SERVER_HOST' '$SERVER_PORT'; rc=\$?; [ \$rc -eq 0 ] && break; i=\$((i+5)); sleep 5; done; echo CIOT_PROVISION_DONE=\$rc" C-m 2>/dev/null || true

  if ! wait_for_pane_text "$QEMU_TMUX_SESSION:1.0" "CIOT_PROVISION_DONE=" "$QEMU_PROVISION_TIMEOUT"; then
    tmux display-message -t "$QEMU_TMUX_SESSION" \
      "Timed out waiting for provision-device.sh to finish"
    exit 0
  fi

  tmux display-message -t "$QEMU_TMUX_SESSION" \
    "Provisioned $DEVICE_ID - see the enrollment record above to submit via POST /api/devices/register"

  # Push the Sensor Module's pre-shared secret (generated/reused and already
  # serving over sensor_daemon before QEMU even started, see above) into the
  # TA's secure storage over the guest console - no shared filesystem with
  # the host exists, so the base64 secret travels as a command-line argument
  # (see main.c's --provision-sensor-secret mode). Idempotent on the TA side,
  # so re-running this is harmless if the secret was already provisioned.
  tmux send-keys -t "$QEMU_TMUX_SESSION:1.0" \
    "$PROJECT_EDGE_BINARY --provision-sensor-secret '$SENSOR_SECRET_B64'; echo CIOT_PAIR_DONE=\$?" C-m 2>/dev/null || true

  if ! wait_for_pane_text "$QEMU_TMUX_SESSION:1.0" "CIOT_PAIR_DONE=" "$QEMU_PROVISION_TIMEOUT"; then
    tmux display-message -t "$QEMU_TMUX_SESSION" \
      "Timed out waiting for sensor pairing to finish"
    exit 0
  fi

  tmux send-keys -t "$QEMU_TMUX_SESSION:1.0" "$PROJECT_EDGE_BINARY" C-m 2>/dev/null || true
) &

echo "Started QEMU tmux session: $QEMU_TMUX_SESSION (instance $QEMU_INSTANCE, device_id $DEVICE_ID)"
echo "The script will wait for the login prompt, log in as root, provision $DEVICE_ID, and run: $PROJECT_EDGE_BINARY"

if [[ -n "${TMUX:-}" ]]; then
  exec tmux switch-client -t "$QEMU_TMUX_SESSION"
fi

exec tmux attach-session -t "$QEMU_TMUX_SESSION"
