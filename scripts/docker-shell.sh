#!/usr/bin/env bash
# Description: Start an interactive shell inside the OP-TEE Docker build environment.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-confidential-computing-optee:latest}"

exec docker run --rm -it \
  --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "$ROOT_DIR:/workspace/ConfidentialComputing" \
  -w /workspace/ConfidentialComputing \
  "$IMAGE_NAME" \
  /bin/bash
