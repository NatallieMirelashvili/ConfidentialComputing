#!/usr/bin/env bash
# Burns a pre-shared secret into a Sensor Module, once.
#
# Writes a single random 32-byte secret to $SECRET_FILE, which sensor_daemon
# (this project's Sensor Module companion process, see
# sensor_module/sensor_daemon.c) reads at startup via --secret. That file
# stands in for a key programmed into the sensor's secure element at
# manufacture: on real hardware it would live in fuses or a secure element and
# never touch a general-purpose OS, which QEMU has no equivalent for.
#
# The secret is NOT printed and NOT delivered to the device. The Edge Device
# starts with no copy at all and pulls one from the Sensor Module over the
# secure UART, which Normal World cannot address (see
# ta_provision_sensor_secret in trusted_app.c and
# PTA_SENSOR_LINK_CMD_FETCH_SECRET). That is the whole reason this script has
# only one consumer now: previously it printed the secret base64 for
# run-project.sh to type into the guest as a command-line argument, exposing
# the plaintext to the untrusted Normal World on every boot.
#
# Idempotent: if $SECRET_FILE already exists, it is left alone. Minting a fresh
# value would desync the sensor from any device already paired to it, and the
# file must survive a device rebuild for exactly that reason - the device is
# what gets reset, not the sensor.
#
# Usage: pair-sensor.sh <secret-file-path>

set -euo pipefail

SECRET_FILE="${1:?usage: pair-sensor.sh <secret-file-path>}"

if [[ ! -s "$SECRET_FILE" ]]; then
  umask 077
  head -c 32 /dev/urandom > "$SECRET_FILE"
  echo "pair-sensor: burned a new sensor secret into $SECRET_FILE" >&2
else
  echo "pair-sensor: reusing the sensor secret already in $SECRET_FILE" >&2
fi
