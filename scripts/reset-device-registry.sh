#!/usr/bin/env bash
# Description: Remove stale device_registry.json entries so a "fresh device"
# test run (e.g. after `rm -f .device-state/iot-edge-NN.img` to force a new
# Attestation Key) doesn't get stuck retrying attestation forever - see
# docs/SELF_REGISTRATION_IMPLEMENTATION.md §6 for why this is needed.
#
# Usage:
#   scripts/reset-device-registry.sh iot-edge-10 [iot-edge-11 ...]
#   scripts/reset-device-registry.sh --all
#   scripts/reset-device-registry.sh --list
#
# If CC_Server is currently running, restart it afterward - DeviceRegistry
# loads device_registry.json once at startup and never reloads.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR/CC_Server" && exec python3 -m server.reset_registry "$@"
