#!/usr/bin/env bash
# Description: Sync the project's OP-TEE example sources into the local OP-TEE workspace.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPTEE_WORKSPACE="${OPTEE_WORKSPACE:-$ROOT_DIR/.optee-workspace}"
PROJECT_EXAMPLES="$ROOT_DIR/project/optee_examples"

if [[ ! -d "$OPTEE_WORKSPACE/optee_examples" ]]; then
  echo "Missing OP-TEE checkout: $OPTEE_WORKSPACE/optee_examples" >&2
  echo "Run scripts/bootstrap.sh first." >&2
  exit 1
fi

rsync -a --delete \
  --exclude '.git/' \
  --exclude '.idea/' \
  --exclude 'cmake-build-*/' \
  "$PROJECT_EXAMPLES/" \
  "$OPTEE_WORKSPACE/optee_examples/"

# The confidential_iot Host CA links against mbedtls/cjson (enabled via
# project/buildroot/packages.conf). Buildroot builds with
# BR2_PER_PACKAGE_DIRECTORIES, where a package only sees the staging trees
# of its *declared* dependencies - so optee_examples_ext must list both, or
# their headers/libs are invisible (and the build order unguaranteed). The
# package .mk lives in the generated, git-ignored build repo, so re-apply
# the dependency here on every sync, idempotently.
EXAMPLES_MK="$OPTEE_WORKSPACE/build/br-ext/package/optee_examples_ext/optee_examples_ext.mk"
if [[ -f "$EXAMPLES_MK" ]] && ! grep -q '^OPTEE_EXAMPLES_EXT_DEPENDENCIES = .* mbedtls cjson' "$EXAMPLES_MK"; then
  sed -i 's/^OPTEE_EXAMPLES_EXT_DEPENDENCIES = .*/& mbedtls cjson/' "$EXAMPLES_MK"
fi

# qemu_v8.mk hardcodes `-s` (QEMU shorthand for `-gdb tcp::1234`) with no
# variable backing, so a 2nd concurrent QEMU instance fails with "Failed to
# find an available port" before ever reaching QEMU_NW_PORT/QEMU_SW_PORT
# (which are already overridable). Parameterize it via QEMU_GDB_PORT
# (default 1234, i.e. identical to today's implicit value when unset). The
# file lives in the generated, git-ignored build repo, so re-apply on every
# sync, idempotently.
QEMU_V8_MK="$OPTEE_WORKSPACE/build/qemu_v8.mk"
if [[ -f "$QEMU_V8_MK" ]] && ! grep -q '^QEMU_GDB_PORT ?= 1234' "$QEMU_V8_MK"; then
  sed -i '/^QEMU_RUN_ARGS = \$(QEMU_BASE_ARGS) \$(QEMU_SCMI_ARGS)/i QEMU_GDB_PORT ?= 1234' "$QEMU_V8_MK"
  sed -i 's/-s -S -serial/-gdb tcp::$(QEMU_GDB_PORT) -S -serial/' "$QEMU_V8_MK"
fi

# Measured boot, link 1 of 3 (TF-A). By default qemu_v8.mk builds TF-A with no
# MEASURED_BOOT, so TF-A never produces/hands off the TCG event log and the
# fTPM has nothing to replay - PCR sha256:0 stays at its all-zero reset value.
# Enable it: MEASURED_BOOT=1 pulls in the event-log driver + qemu_measured_boot.c
# (which measures every boot image into PCR_0). On qemu this works WITHOUT
# TRUSTED_BOARD_BOOT - plat/qemu/qemu/platform.mk still includes crypto_mod.c +
# mbedtls_crypto.mk for the hashing, so the only extra requirement is
# MBEDTLS_DIR (qemu also auto-generates its own ROT key, so no ROT_KEY needed).
# Generated build repo file, so re-apply on every sync, idempotently.
if [[ -f "$QEMU_V8_MK" ]] && ! grep -q '^TF_A_FLAGS += MEASURED_BOOT=1' "$QEMU_V8_MK"; then
  sed -i '/^TF_A_FLAGS_BL32_OPTEE  = BL32=/i TF_A_FLAGS += MEASURED_BOOT=1 EVENT_LOG_LEVEL=20 TPM_HASH_ALG=sha256 MBEDTLS_DIR=$(ROOT)/mbedtls' "$QEMU_V8_MK"
fi

# Measured boot, link 2 of 3 (OP-TEE core). CFG_CORE_TPM_EVENT_LOG makes core
# read the event log TF-A handed off (via TOS_FW_CONFIG / the arm,tpm_event_log
# DT node) and forward it to the fTPM TA, which replays it to extend the PCRs.
# It needs the device tree, hence CFG_DT=y (mirrors fvp.mk's measured-boot
# block). Link 3 (fTPM CFG_TA_MEASURED_BOOT via MEASURED_BOOT_FTPM) is already
# on in qemu_v8.mk. Generated build repo file, so re-apply idempotently.
if [[ -f "$QEMU_V8_MK" ]] && ! grep -q 'CFG_CORE_TPM_EVENT_LOG=y' "$QEMU_V8_MK"; then
  sed -i '/^OPTEE_OS_COMMON_FLAGS += DEBUG=\$(DEBUG) CFG_ARM_GICV3=\$(GICV3)/a OPTEE_OS_COMMON_FLAGS += CFG_DT=y CFG_CORE_TPM_EVENT_LOG=y' "$QEMU_V8_MK"
fi

echo "Project sources synced into $OPTEE_WORKSPACE/optee_examples"
