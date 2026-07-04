#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
MANIFEST_SOURCE="$ROOT_DIR/manifests/locked-qemu_v8.xml"

if [[ ! -f "$MANIFEST_SOURCE" ]]; then
  echo "Missing locked manifest: $MANIFEST_SOURCE" >&2
  exit 1
fi

mkdir -p "$OPTEE_WORKSPACE"
cd "$OPTEE_WORKSPACE"

if [[ ! -d .repo ]]; then
  repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
fi

cp "$MANIFEST_SOURCE" .repo/manifests/locked-qemu_v8.xml
repo init -m locked-qemu_v8.xml
repo sync -j"$(nproc)"

"$ROOT_DIR/scripts/sync-project.sh"

echo "OP-TEE workspace is ready at $OPTEE_WORKSPACE"
