#!/bin/sh
# One-time device provisioning: create the TPM Endorsement Key (EK) and
# Attestation Key (AK) inside the fTPM, persist the AK to a fixed handle,
# capture a PCR baseline, and write /etc/confidential_iot/device.conf so
# edge_device.c (Host CA) knows which AK handle to use at runtime.
#
# Run this once, from the Normal World shell, after first boot:
#   provision-device.sh [device_id] [server_host] [server_port]
# ADMIN_PORT (env, default 8000) is written to device.conf as admin_port -
# the management server's admin API port, used by edge_device.c to
# self-register (distinct from server_port, the device-facing port).
#
# Prints the enrollment record (JSON) and saves it to
# $CONF_DIR/enrollment.json, which edge_device.c submits itself to
# POST /api/devices/register (see CC_Server/server/app_server.py) - no human
# step required. Idempotent: gated on whether the AK already exists at
# AK_HANDLE in the fTPM (not on /etc/confidential_iot, which lives on the
# ephemeral initrd) - so on a build with the persistent /var/lib/tee disk
# (see docs/HANDOFF_persistentAK.md), a reboot just reprints the existing
# record instead of minting a new AK.
#
# NOTE: exact tpm2-tools flags below should be checked against
# `tpm2_createek --help` / `tpm2_createak --help` / `tpm2_readpublic --help`
# on the real target image (tpm2-tools 5.7) - this could not be executed
# from the planning environment to verify.

set -e

CONF_DIR=/etc/confidential_iot
CONF_FILE="$CONF_DIR/device.conf"
AK_HANDLE=0x8101000A

DEVICE_ID="${1:-iot-edge-01}"
SERVER_HOST="${2:-127.0.0.1}"
SERVER_PORT="${3:-9000}"

# Security-relevant runtime artifacts measured into PCR0 each boot (see
# software_measure_pcr0). Fixed order => deterministic PCR value.
MEASURE_ARTIFACTS="/lib/optee_armtz/7d9f6d20-5f11-4d0c-9a17-61c9c91c0001.ta /usr/bin/optee_example_confidential_iot_edge"

# Software measured-boot stand-in. On this QEMU/opteed topology, firmware
# measured boot does NOT deliver the TCG event log to the fTPM: TF-A never
# populates the `arm,tpm_event_log` node in the device tree OP-TEE core reads
# (core logs "TPM: Fail to find TPM node"), so the fTPM has nothing to replay
# and PCR sha256:0 would stay at its all-zero reset value - a degenerate
# attestation baseline that cannot distinguish a tampered image. As a stand-in
# we extend PCR0 once per boot with the SHA-256 of the artifacts above, giving a
# PCR0 that is non-zero, identical across reboots of the same image, and
# different if either artifact is tampered.
#
# SECURITY CAVEAT: this runs in Normal World, so unlike real measured boot it is
# NOT hardware-rooted - a Normal-World attacker could extend the "good" hashes
# while running tampered code. On real hardware the TF-A -> OP-TEE -> fTPM chain
# provides this with a hardware root of trust; this stand-in exists only because
# that chain is not wired end-to-end under QEMU. See docs/ATTESTATION_DESIGN.md.
software_measure_pcr0() {
	# Idempotent within a boot: only extend while PCR0 is still all-zero. A
	# second call in the same boot (the provisioning retry loop, or the "already
	# provisioned" reprint path) sees a non-zero PCR0 and does nothing, so the
	# value stays deterministic. If the fTPM isn't ready yet, tpm2_pcrread
	# yields no match, we skip, and the createek/pcrread below fail and get
	# retried - by the time provisioning succeeds, PCR0 has been extended.
	if ! tpm2_pcrread sha256:0 2>/dev/null | grep -q '0x0\{64\}'; then
		return 0
	fi
	for artifact in $MEASURE_ARTIFACTS; do
		[ -f "$artifact" ] || continue
		h=$(sha256sum "$artifact" | cut -d' ' -f1)
		tpm2_pcrextend "0:sha256=$h"
	done
}

# Prints the enrollment record and also saves it to $CONF_DIR/enrollment.json
# so edge_device.c (Host CA) can self-register it via
# POST /api/devices/register without a human re-deriving it (see
# edge_register_with_server() in edge_device.c).
print_enrollment_record() {
	ak_pub_b64=$(base64 -w0 "$CONF_DIR/ak.pem")
	pcr_text=$(tpm2_pcrread sha256:0 2>&1)
	pcr_json=$(printf '%s' "$pcr_text" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s\\n", $0}')

	record=$(printf '{"device_id":"%s","ak_pub_pem_b64":"%s","expected_pcr":"%s","pcr_bank":"sha256:0"}' \
		"$DEVICE_ID" "$ak_pub_b64" "$pcr_json")

	printf '%s\n' "$record"
	printf '%s' "$record" > "$CONF_DIR/enrollment.json"
}

# Extend PCR0 before any baseline read or quote, on every invocation (guarded to
# run at most once per boot), so both the enrollment baseline captured below and
# the edge binary's later quote observe the same measured value.
software_measure_pcr0

mkdir -p "$CONF_DIR"
cd "$CONF_DIR"

# tpm2_readpublic only reads - it never creates state - so this is a safe,
# side-effect-free probe for "does the AK already exist" (true on every boot
# after the first, once /var/lib/tee is persisted; always false without it).
if tpm2_readpublic -c "$AK_HANDLE" -f pem -o ak.pem 2>/dev/null; then
	echo "AK already persisted at $AK_HANDLE (survived reboot). Enrollment record:" >&2
else
	tpm2_createek -c ek.ctx -G ecc -u ek.pub
	tpm2_createak -C ek.ctx -c ak.ctx -G ecc -g sha256 -s ecdsa -u ak.pub -n ak.name
	tpm2_evictcontrol -C o -c ak.ctx "$AK_HANDLE"
	tpm2_readpublic -c ak.ctx -f pem -o ak.pem

	echo "Provisioned. Submit this enrollment record to the management server" >&2
	echo "(POST /api/devices/register) before running optee_example_confidential_iot_edge:" >&2
fi

cat > "$CONF_FILE" <<EOF
device_id=$DEVICE_ID
server_host=$SERVER_HOST
server_port=$SERVER_PORT
ak_handle=$AK_HANDLE
admin_port=${ADMIN_PORT:-8000}
EOF

print_enrollment_record
