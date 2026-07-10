#!/usr/bin/env bash
# Description: Wait for a booting/booted QEMU device's provisioning
# enrollment record and register it with the Management Server automatically
# - so you don't have to manually copy the printed JSON and curl it yourself
# every time you run scripts/run-project.sh.
#
# Usage:
#   scripts/register-device.sh [QEMU_TMUX_SESSION] [API_HOST] [API_PORT]
#
# All three can also be set as env vars. Defaults match run-project.sh's own
# QEMU_TMUX_SESSION default and the project's documented server defaults
# (see docs/QEMU_NETWORKING.md); override API_PORT to whatever you actually
# started the Management Server on (e.g. 8100, if 8000 is already taken by
# someone else's server on this host).
set -euo pipefail

QEMU_TMUX_SESSION="${1:-${QEMU_TMUX_SESSION:-optee-project}}"
API_HOST="${2:-${API_HOST:-127.0.0.1}}"
API_PORT="${3:-${API_PORT:-8000}}"
TIMEOUT="${REGISTER_TIMEOUT:-180}"

echo "Looking for a QEMU container running tmux session '$QEMU_TMUX_SESSION'..." >&2
CID=""
for id in $(docker ps --filter "ancestor=confidential-computing-optee:latest" --format "{{.ID}}"); do
  if docker exec "$id" tmux has-session -t "$QEMU_TMUX_SESSION" 2>/dev/null; then
    CID="$id"
    break
  fi
done

if [[ -z "$CID" ]]; then
  echo "No running QEMU container has a tmux session named '$QEMU_TMUX_SESSION'." >&2
  echo "Is scripts/run-project.sh still running? Check QEMU_TMUX_SESSION matches what you launched it with." >&2
  exit 1
fi
echo "Found container $CID" >&2

echo "Waiting for the enrollment record (up to ${TIMEOUT}s)..." >&2
elapsed=0
record=""
while (( elapsed < TIMEOUT )); do
  record="$(docker exec "$CID" tmux capture-pane -pt "$QEMU_TMUX_SESSION:1.0" -S -500 -J 2>/dev/null \
    | grep -o '{"device_id".*}' | tail -1 || true)"
  [[ -n "$record" ]] && break
  sleep 3
  elapsed=$((elapsed + 3))
done

if [[ -z "$record" ]]; then
  echo "Timed out waiting for an enrollment record in the QEMU pane." >&2
  exit 1
fi

device_id="$(printf '%s' "$record" | grep -o '"device_id":"[^"]*"' | cut -d'"' -f4)"
echo "Captured enrollment record for device_id=$device_id" >&2

response="$(curl -sk -X POST "https://$API_HOST:$API_PORT/api/devices/register" \
  -H "Content-Type: application/json" \
  -d "$record")"

echo "$response"
if grep -q '"ok":true' <<<"$response"; then
  echo "Registered $device_id." >&2
else
  echo "Registration failed for $device_id - see response above." >&2
  exit 1
fi
