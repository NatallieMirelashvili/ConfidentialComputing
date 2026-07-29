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

# Project-private TA signing key, replacing OP-TEE's shipped default (whose private
# half is committed upstream, so root could re-sign a tampered TA). See keys/README.md
# and docs/HANDOFF_taIdentityBinding.md Part A.
#
# Exported rather than passed per-make because THREE builds must agree on it:
#   - the OP-TEE core, which bakes TA_PUBLIC_KEY = $(TA_SIGN_KEY) into ta_pub_key.c,
#     i.e. the in-core load-time verifier (optee_os mk/config.mk, core/sub.mk);
#   - the ta_dev_kit export, which copies the key for the TA builds (optee_os ta/ta.mk);
#   - every TA link step, which signs the .ta with it (optee_os ta/link.mk).
# All three read it with `?=`, which defers to an environment-origin value, so one
# export reaches optee_os, the fTPM, optee_examples_ext and optee_test_ext with no
# makefile patching. Setting it in a single TA's Makefile would break the others:
# ta.mk only copies default.pem into the dev kit when TA_SIGN_KEY is literally
# keys/default_ta.pem, so every TA that still defaulted would lose its signing key.
#
# A mismatch (core baked with key X, a TA signed with key Y) is a SILENT build success
# in which every TA then fails to load at runtime - hence verify-ta-signing.sh below.
export TA_SIGN_KEY="$ROOT_DIR/keys/ciot_ta.pem"

if [[ ! -f "$TA_SIGN_KEY" ]]; then
  echo "Missing TA signing key: $TA_SIGN_KEY" >&2
  echo "See keys/README.md - regenerate with: openssl genrsa -out '$TA_SIGN_KEY' 4096" >&2
  exit 1
fi

cd "$OPTEE_WORKSPACE/build"
make -f toolchain.mk toolchains

if [[ -f "$OPTEE_WORKSPACE/toolchains/rust/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$OPTEE_WORKSPACE/toolchains/rust/.cargo/env"
fi

make -j"$(nproc)"

# Assert the core's baked-in verifier key and the TA's signature are the SAME key.
# Runs before the stamp so a mismatched build is never recorded as good.
"$ROOT_DIR/scripts/verify-ta-signing.sh"

# Stamp this build so scripts/run-project.sh can tell a genuine rebuild apart
# from a plain relaunch/guest-reboot. On the next run, a device whose disk was
# built against an older stamp is wiped to a fresh device (new AK + fresh
# server-key TOFU) - the server's identity key may have rotated on rebuild,
# and a pinned device would otherwise be locked out. See
# docs/HANDOFF_serverAuthentication.md and docs/ATTESTATION_DESIGN.md. A new,
# unique value each successful build is all that's needed.
printf '%s.%s\n' "$(date +%s)" "$RANDOM" > "$ROOT_DIR/.build-stamp"
echo "build stamp: $(cat "$ROOT_DIR/.build-stamp")"
