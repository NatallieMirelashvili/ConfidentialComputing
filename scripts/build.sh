#!/usr/bin/env bash
# Description: Sync project sources and build the OP-TEE workspace.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"

if [[ ! -d "$OPTEE_WORKSPACE/build" ]]; then
  echo "Missing OP-TEE build directory in $OPTEE_WORKSPACE" >&2
  echo "Run scripts/bootstrap.sh first." >&2
  exit 1
fi

"$ROOT_DIR/scripts/sync-project.sh"

# Export tracked Buildroot package selections (BR2_* lines) so the OP-TEE
# makefiles fold them into Buildroot's generated .config (see the comment in
# project/buildroot/packages.conf for how this works).
while IFS= read -r br2_line; do
  case "$br2_line" in
    BR2_*=*) export "${br2_line?}" ;;
  esac
done < "$ROOT_DIR/project/buildroot/packages.conf"

cd "$OPTEE_WORKSPACE/build"
make -f toolchain.mk toolchains

if [[ -f "$OPTEE_WORKSPACE/toolchains/rust/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$OPTEE_WORKSPACE/toolchains/rust/.cargo/env"
fi

make -j"$(nproc)"

# Stamp this build so scripts/run-project.sh can tell a genuine rebuild apart
# from a plain relaunch/guest-reboot. On the next run, a device whose disk was
# built against an older stamp is wiped to a fresh device (new AK + fresh
# server-key TOFU) - the server's identity key may have rotated on rebuild,
# and a pinned device would otherwise be locked out. See
# docs/HANDOFF_serverAuthentication.md and docs/ATTESTATION_DESIGN.md. A new,
# unique value each successful build is all that's needed.
printf '%s.%s\n' "$(date +%s)" "$RANDOM" > "$ROOT_DIR/.build-stamp"
echo "build stamp: $(cat "$ROOT_DIR/.build-stamp")"
