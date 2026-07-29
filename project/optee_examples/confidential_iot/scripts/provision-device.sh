#!/bin/sh
# One-time device provisioning: create the TPM Endorsement Key (EK) and
# Attestation Key (AK) inside the fTPM, persist the AK to a fixed handle,
# mint the TA's own sealed identity keypair, capture a PCR baseline, and write
# /etc/confidential_iot/device.conf so edge_device.c (Host CA) knows which AK
# handle to use at runtime.
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
# Installed alongside this script into the same bindir (see CMakeLists.txt), so
# it is on PATH. Used to mint/export the TA's sealed identity public key.
EDGE_BIN="${EDGE_BIN:-optee_example_confidential_iot_edge}"

DEVICE_ID="${1:-iot-edge-01}"
SERVER_HOST="${2:-127.0.0.1}"
SERVER_PORT="${3:-9000}"

# NOTE: PCR sha256:0 is now populated by REAL, firmware-rooted measured boot -
# TF-A measures every boot image (BL31/BL32=OP-TEE/BL33) into the TCG event log,
# hands it to OP-TEE (running as the S-EL1 SPMC) via TOS_FW_CONFIG, and the fTPM
# replays it into the PCRs before Linux userspace ever runs. See docs/DESIGN.md
# and the FF-A topology switch + tfa-tos-fw-config-eventlog.patch wired up in
# scripts/sync-project.sh. The old Normal-World software_measure_pcr0() stand-in
# (which hashed the .ta/edge binaries from userspace) has been removed: it was
# not hardware-rooted - a compromised OS could extend the good hashes while
# running tampered code. The enrollment baseline below just reads whatever the
# firmware already measured.

# Prints the enrollment record and also saves it to $CONF_DIR/enrollment.json
# so edge_device.c (Host CA) can self-register it via
# POST /api/devices/register without a human re-deriving it (see
# edge_register_with_server() in edge_device.c).
print_enrollment_record() {
	ak_pub_b64=$(base64 -w0 "$CONF_DIR/ak.pem")

	# The TA's OWN identity public key - the third attestation leg. The AK
	# proves which device this is and PCR0 proves the firmware, but neither
	# says the genuine TA did the crypto: the AK belongs to the fTPM and the
	# quote is assembled by the untrusted Host, so root could bypass the TA
	# entirely and still produce a valid-looking quote. Signing each session
	# with a key that was generated inside the TA and never leaves it is what
	# closes that. Minted and sealed (bound to $DEVICE_ID) on the first call,
	# re-exported unchanged afterwards, so this is safe on every boot.
	# See docs/HANDOFF_taIdentityBinding.md.
	#
	# Reads device.conf for its device_id, so it must run AFTER that file is
	# written - it is, print_enrollment_record is called last.
	if ! ta_pub_b64=$("$EDGE_BIN" --provision-ta-identity); then
		echo "TA identity provisioning failed (is tee-supplicant running?)" >&2
		return 1
	fi

	pcr_text=$(tpm2_pcrread sha256:0 2>&1)
	pcr_json=$(printf '%s' "$pcr_text" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s\\n", $0}')

	record=$(printf '{"device_id":"%s","ak_pub_pem_b64":"%s","ta_pub_b64":"%s","expected_pcr":"%s","pcr_bank":"sha256:0"}' \
		"$DEVICE_ID" "$ak_pub_b64" "$ta_pub_b64" "$pcr_json")

	printf '%s\n' "$record"
	printf '%s' "$record" > "$CONF_DIR/enrollment.json"
}

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
