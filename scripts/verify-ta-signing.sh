#!/usr/bin/env bash
# Description: Assert the OP-TEE core and the confidential_iot TA were built with the
# same project-private TA signing key.
#
# Why this exists: TA_SIGN_KEY feeds two independent halves of the build - the core
# bakes the PUBLIC key into ta_pub_key.c (the load-time verifier), and each TA link
# step SIGNS the .ta with the private key. If they disagree, the build still succeeds
# and every TA silently fails to load at runtime, which looks like anything but a key
# problem. Both checks below are mechanical (regenerate + compare, and verify the real
# signature); neither greps a build log.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
TA_SIGN_KEY="${TA_SIGN_KEY:-$ROOT_DIR/keys/ciot_ta.pem}"
TA_UUID="${TA_UUID:-7d9f6d20-5f11-4d0c-9a17-61c9c91c0001}"

OPTEE_OS="$OPTEE_WORKSPACE/optee_os"
CORE_PUB_C="$OPTEE_OS/out/arm/core/ta_pub_key.c"
TA_FILE="$OPTEE_WORKSPACE/out-br/target/lib/optee_armtz/$TA_UUID.ta"

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -f "$TA_SIGN_KEY" ]] || fail "signing key not found: $TA_SIGN_KEY (see keys/README.md)"

# --- 1. The CORE baked OUR public key into its verifier ------------------------------
# Regenerate ta_pub_key.c from our key with the very script core/sub.mk uses, then diff
# byte-for-byte against what the core actually compiled in.
[[ -f "$CORE_PUB_C" ]] || fail "core public key not built: $CORE_PUB_C (run scripts/build.sh)"

expected_pub_c="$(mktemp)"
trap 'rm -f "$expected_pub_c"' EXIT

python3 "$OPTEE_OS/scripts/pem_to_pub_c.py" \
  --prefix ta_pub_key --key "$TA_SIGN_KEY" --out "$expected_pub_c"

if ! diff -q "$expected_pub_c" "$CORE_PUB_C" >/dev/null; then
  echo "The OP-TEE core was built with a DIFFERENT TA public key than" >&2
  echo "  $TA_SIGN_KEY" >&2
  echo "Every TA signed with that key will fail to load. Rebuild the core:" >&2
  echo "  rm -rf '$OPTEE_OS/out' && scripts/build.sh" >&2
  fail "core ta_pub_key.c does not match $TA_SIGN_KEY"
fi
echo "ok: OP-TEE core verifier is built from $(basename "$TA_SIGN_KEY")"

# --- 2. The installed TA is SIGNED with the same key ---------------------------------
[[ -f "$TA_FILE" ]] || fail "TA not built: $TA_FILE (run scripts/build.sh)"

if ! python3 "$OPTEE_OS/scripts/sign_encrypt.py" verify \
     --uuid "$TA_UUID" --key "$TA_SIGN_KEY" --in "$TA_FILE" >/dev/null; then
  echo "The confidential_iot TA is not signed with" >&2
  echo "  $TA_SIGN_KEY" >&2
  echo "It is probably still signed with OP-TEE's default key. Force a TA rebuild:" >&2
  echo "  rm -rf '$OPTEE_WORKSPACE/out-br/build/optee_examples_ext-1.0'" >&2
  echo "  rm -rf '$OPTEE_WORKSPACE/out-br/per-package/optee_examples_ext'" >&2
  echo "  scripts/build.sh" >&2
  fail "TA signature does not verify against $TA_SIGN_KEY"
fi
echo "ok: confidential_iot TA is signed with $(basename "$TA_SIGN_KEY")"

echo "TA signing verified: core verifier and TA signature share one project-private key."
