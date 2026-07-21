#!/usr/bin/env bash
# One-time pairing between a Sensor Module and one Edge Device: generates a
# single random pre-shared secret and makes it available to both
# consumers of it, neither of which is a git-tracked source file:
#
#   1. The raw 32-byte secret is written to $SECRET_FILE, which
#      sensor_daemon (this project's Sensor Module companion process, see
#      sensor_module/sensor_daemon.c) reads at startup via --secret.
#   2. This script prints the SAME secret, base64-encoded, to stdout - the
#      caller (scripts/run-project.sh) is expected to deliver that string
#      into the guest (there is no shared filesystem with the host) and run
#      `optee_example_confidential_iot_edge --provision-sensor-secret
#      <base64>` there, which pushes it into the confidential_iot TA's
#      secure storage (see ta_provision_sensor_secret in trusted_app.c).
#
# Idempotent: if $SECRET_FILE already exists, its contents are reused
# instead of minting a new secret - the TA side is independently idempotent
# too (ta_provision_sensor_secret refuses to overwrite an already-stored
# secret), so re-running this must not desync the two sides by generating a
# fresh value only one of them would receive.
#
# Usage: pair-sensor.sh <secret-file-path>

set -euo pipefail

SECRET_FILE="${1:?usage: pair-sensor.sh <secret-file-path>}"

if [[ ! -s "$SECRET_FILE" ]]; then
  umask 077
  head -c 32 /dev/urandom > "$SECRET_FILE"
fi

base64 -w0 "$SECRET_FILE"
