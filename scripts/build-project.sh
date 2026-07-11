#!/usr/bin/env bash
# Description: One-command project build for the OP-TEE/QEMU workspace.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
IMAGE_NAME="${IMAGE_NAME:-confidential-computing-optee:latest}"

if [[ -z "${IN_OPTEE_DOCKER:-}" && -z "${SKIP_DOCKER:-}" && -f "$ROOT_DIR/docker/Dockerfile" ]] &&
   command -v docker >/dev/null 2>&1; then
  exec docker run --rm \
    --platform linux/amd64 \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e IN_OPTEE_DOCKER=1 \
    -v "$ROOT_DIR:/workspace/ConfidentialComputing" \
    -w /workspace/ConfidentialComputing \
    "$IMAGE_NAME" \
    ./scripts/build-project.sh
fi

"$ROOT_DIR/scripts/sync-project.sh"

# libcurl is force-cleaned too: it can already be cached from an earlier
# bootstrap as a transitive dependency of tpm2-tools/opensc (built with
# whatever BR2_PACKAGE_LIBCURL_* suboptions were in effect back then).
# Buildroot's per-package system only checks .stamp_* files, not whether a
# package's Kconfig suboptions changed - so enabling BR2_PACKAGE_LIBCURL_CURL
# / _MBEDTLS in project/buildroot/packages.conf silently has no effect on an
# already-built libcurl until it's force-rebuilt like this.
rm -rf \
  "$OPTEE_WORKSPACE/optee_ftpm/out" \
  "$OPTEE_WORKSPACE/trusted-firmware-a/build" \
  "$OPTEE_WORKSPACE/out-br/build/optee_client_ext-1.0" \
  "$OPTEE_WORKSPACE/out-br/build/optee_os_ext-1.0" \
  "$OPTEE_WORKSPACE/out-br/build/optee_examples_ext-1.0" \
  $OPTEE_WORKSPACE/out-br/build/libcurl-* \
  "$OPTEE_WORKSPACE/out-br/per-package/optee_client_ext" \
  "$OPTEE_WORKSPACE/out-br/per-package/optee_os_ext" \
  "$OPTEE_WORKSPACE/out-br/per-package/optee_examples_ext" \
  "$OPTEE_WORKSPACE/out-br/per-package/libcurl"

exec "$ROOT_DIR/scripts/build.sh"
