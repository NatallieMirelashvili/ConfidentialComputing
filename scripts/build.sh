#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"

if [[ ! -d "$OPTEE_WORKSPACE/build" ]]; then
  echo "Missing OP-TEE build directory in $OPTEE_WORKSPACE" >&2
  echo "Run scripts/bootstrap.sh first." >&2
  exit 1
fi

"$ROOT_DIR/scripts/sync-project.sh"

cd "$OPTEE_WORKSPACE/build"
make -f toolchain.mk toolchains

if [[ -f "$OPTEE_WORKSPACE/toolchains/rust/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$OPTEE_WORKSPACE/toolchains/rust/.cargo/env"
fi

make -j"$(nproc)"

