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

# Measured boot, topology switch (FF-A / S-EL1 SPMC). The default opteed
# topology cannot deliver TF-A's TCG event log to the fTPM on this QEMU setup
# (OP-TEE core logs "TPM: Fail to find TPM node" and PCR sha256:0 stays all-zero
# - see docs/DESIGN.md). Under SPMC_AT_EL=1, OP-TEE runs as the S-EL1 SPMC and
# reads the log from the TOS_FW_CONFIG manifest DT via get_manifest_dt(); TF-A
# hands the log off there via the tfa-tos-fw-config-eventlog.patch applied
# below. Flipping the qemu_v8.mk default (a single source of truth read by both
# scripts/build.sh and the run scripts' `make run-only`) keeps the built FIP and
# the launch topology in lockstep - a mismatch would fail to boot. Do NOT use
# SEL0_SPS=y for this (it also drags in Trusted-Services test SPs). Generated
# build repo file, so re-apply on every sync, idempotently.
if [[ -f "$QEMU_V8_MK" ]] && ! grep -q '^SPMC_AT_EL ?= 1' "$QEMU_V8_MK"; then
  sed -i 's/^SPMC_AT_EL ?= n$/SPMC_AT_EL ?= 1/' "$QEMU_V8_MK"
fi

# 3rd QEMU serial backend for the confidential_iot sensor_link PTA's secure
# UART2 (see project/patches/virt-uart2.patch): serial_hd(0)/(1) already map
# to NW/SW consoles positionally, so a 3rd `-serial` arg becomes serial_hd(2)
# - exactly the UART2 QEMU only maps into secure_sysmem. QEMU_SENSOR_PORT
# mirrors QEMU_GDB_PORT/QEMU_NW_PORT/QEMU_SW_PORT's own override convention.
# Generated build repo file, so re-apply on every sync, idempotently.
if [[ -f "$QEMU_V8_MK" ]] && ! grep -q '^QEMU_SENSOR_PORT ?= 54322' "$QEMU_V8_MK"; then
  sed -i '/^QEMU_GDB_PORT ?= 1234/i QEMU_SENSOR_PORT ?= 54322' "$QEMU_V8_MK"
  sed -i 's/-serial tcp:127.0.0.1:\$(QEMU_SW_PORT) /-serial tcp:127.0.0.1:$(QEMU_SW_PORT) -serial tcp:127.0.0.1:$(QEMU_SENSOR_PORT) /' "$QEMU_V8_MK"
fi

# Apply the confidential_iot sensor_link PTA's secure UART2 QEMU machine-model
# patch (VIRT_UART2: new secure-only PL011 at 0x090c0000, IRQ SPI 10 - see
# docs and the patch file itself for rationale). The qemu/ checkout is a real
# git repo under the git-ignored workspace, so `git apply` with a
# --reverse --check idempotency guard is more robust here than sed for a
# multi-line C change: it applies once and is a no-op on every later sync.
QEMU_SRC="$OPTEE_WORKSPACE/qemu"
UART2_PATCH="$ROOT_DIR/project/patches/virt-uart2.patch"
if [[ -d "$QEMU_SRC" && -f "$UART2_PATCH" ]]; then
  if ! git -C "$QEMU_SRC" apply --reverse --check "$UART2_PATCH" 2>/dev/null; then
    git -C "$QEMU_SRC" apply "$UART2_PATCH"
  fi
fi

# Measured boot, TF-A TOS_FW_CONFIG event-log handoff for the S-EL1 SPMC
# topology (see the SPMC_AT_EL=1 flip above). Upstream TF-A leaves
# qemu_set_tos_fw_info() an empty FIXME stub for SPD=spmd, so the fTPM never
# receives the event log and PCR sha256:0 stays all-zero even under FF-A. This
# patch implements it: it writes the arm,tpm_event_log node (compatible +
# tpm_event_log_sm_addr + tpm_event_log_size) into the TOS_FW_CONFIG manifest
# DTB that OP-TEE core reads. trusted-firmware-a is a real git repo under the
# git-ignored workspace, so git apply with a --reverse --check idempotency
# guard, exactly like the UART2 patch above.
TF_A_SRC="$OPTEE_WORKSPACE/trusted-firmware-a"
TFA_MBOOT_PATCH="$ROOT_DIR/project/patches/tfa-tos-fw-config-eventlog.patch"
if [[ -d "$TF_A_SRC" && -f "$TFA_MBOOT_PATCH" ]]; then
  if ! git -C "$TF_A_SRC" apply --reverse --check "$TFA_MBOOT_PATCH" 2>/dev/null; then
    git -C "$TF_A_SRC" apply "$TFA_MBOOT_PATCH"
  fi
fi

# sensor_link PTA: copy the tracked sources into the git-ignored optee_os
# checkout (plain `cp`, naturally idempotent - unlike the QEMU patch above,
# these are whole new files with no upstream content to conflict with).
OPTEE_OS_SRC="$OPTEE_WORKSPACE/optee_os"
OPTEE_OS_EXT="$ROOT_DIR/project/optee_os_ext"
if [[ -d "$OPTEE_OS_SRC" && -d "$OPTEE_OS_EXT" ]]; then
  cp "$OPTEE_OS_EXT/core/pta/sensor_link.c" "$OPTEE_OS_SRC/core/pta/sensor_link.c"
  cp "$OPTEE_OS_EXT/lib/libutee/include/pta_sensor_link.h" \
    "$OPTEE_OS_SRC/lib/libutee/include/pta_sensor_link.h"

  # Build it only when explicitly enabled (CFG_SENSOR_LINK_PTA), matching this
  # sub.mk's existing srcs-$(CFG_*) convention - sensor_link.c hardcodes a
  # QEMU-virt-specific MMIO address (see the file itself), so it must not be
  # unconditionally built into every OP-TEE platform.
  PTA_SUB_MK="$OPTEE_OS_SRC/core/pta/sub.mk"
  if [[ -f "$PTA_SUB_MK" ]] && ! grep -q 'sensor_link.c' "$PTA_SUB_MK"; then
    sed -i '/^srcs-\$(CFG_HWRNG_PTA) += hwrng.c/a srcs-$(CFG_SENSOR_LINK_PTA) += sensor_link.c' "$PTA_SUB_MK"
  fi
fi

# Enable CFG_SENSOR_LINK_PTA for this project's qemu build (see above for why
# it's opt-in rather than srcs-y). Generated build repo file, re-apply
# idempotently, same anchor as the measured-boot CFG_DT/CFG_CORE_TPM_EVENT_LOG
# patch above.
if [[ -f "$QEMU_V8_MK" ]] && ! grep -q 'CFG_SENSOR_LINK_PTA=y' "$QEMU_V8_MK"; then
  sed -i '/^OPTEE_OS_COMMON_FLAGS += DEBUG=\$(DEBUG) CFG_ARM_GICV3=\$(GICV3)/a OPTEE_OS_COMMON_FLAGS += CFG_SENSOR_LINK_PTA=y' "$QEMU_V8_MK"
fi

echo "Project sources synced into $OPTEE_WORKSPACE/optee_examples"
