#ifndef CONFIDENTIAL_IOT_TA_H
#define CONFIDENTIAL_IOT_TA_H

#define TA_CONFIDENTIAL_IOT_UUID \
	{ 0x7d9f6d20, 0x5f11, 0x4d0c, \
		{ 0x9a, 0x17, 0x61, 0xc9, 0xc9, 0x1c, 0x00, 0x01 } }

/*
 * Sensor Module <-> Device authentication (Secure Element HMAC-SHA256
 * challenge-response). Invoked once per boot by the Host CA. The TA records
 * the "sensor is authentic" verdict in its session state; PROCESS/PROTECT
 * below refuse to run until it has succeeded. Currently the TA side is a
 * stub that always succeeds (the real challenge-response is a separate work
 * item), but the gating is already enforced so wiring the real check in
 * later needs no change on the callers.
 *
 * in:  none (stub); out: none.
 */
#define TA_CONFIDENTIAL_IOT_CMD_AUTHENTICATE_SENSOR		0



#define TA_CONFIDENTIAL_IOT_CMD_PROCESS_SENSOR_DATA		1

/*
 * Protect (AES-256-GCM encrypt) one sensor-data message under the session key
 * derived by HANDSHAKE_COMPLETE. A per-session, monotonically increasing
 * sequence number is authenticated as the GCM AAD (8-byte big-endian) and
 * returned so the server can enforce inner-session anti-replay: it rejects any
 * message whose seq it has already accepted. Because the seq is bound by the
 * GCM tag, an attacker cannot renumber a captured message to slip a replay
 * past that check without breaking authentication. (This is distinct from GCM
 * nonce uniqueness, which the fresh random 96-bit nonce below still provides.)
 *
 * in:  params[0].memref = the plaintext sensor data.
 * out: params[1].memref = the 12-byte GCM nonce the TA generates.
 *      params[2].memref = ciphertext ‖ tag (16-byte tag appended after the ciphertext).
 *      params[3].value.a = sequence number authenticated for this message.
 */
#define TA_CONFIDENTIAL_IOT_CMD_PROTECT_SENSOR_DATA		2

/*
 * Handshake phase 1 (Device -> Server attestation + key exchange).
 *
 * Repurposed from the original "generate attestation evidence" stub: the TA
 * itself never talks to the fTPM or the network. It only generates a fresh
 * ephemeral ECDH keypair and returns the public half; the Host CA is the one
 * that gets that public key quoted by the fTPM (a separate TA) and ships the
 * quote to the server. This keeps the actual session secret (the ECDH
 * private key, and later the derived AES key) inside this TA's memory for
 * its entire lifetime - it never crosses into Normal World or into the fTPM.
 *
 * The TA also computes the handshake transcript hash
 * SHA-256(nonce || server_ecdh_pub || device_ecdh_pub) via the TEE Internal
 * Core API and returns it, so the Host CA can pass it straight to tpm2_quote
 * as qualifying data without needing any Normal-World hash implementation.
 *
 * in:  params[1].memref = nonce issued by the server (variable length)
 *      params[2].memref = server ephemeral ECDH public key (65-byte point)
 * out: params[0].memref = device ephemeral ECDH public key
 *      (65-byte uncompressed SEC1 point: 0x04 || X || Y)
 *      params[3].memref = 32-byte SHA-256 transcript hash
 */
#define TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE	3

/*
 * Handshake phase 2, called only after the server has confirmed the
 * attestation quote (attest_result.ok == true).
 *
 * in:  params[0].memref = server ephemeral ECDH public key (65-byte point)
 *      params[1].memref = nonce (the same nonce the server issued and that
 *      was quoted by the fTPM), used as the HKDF salt so the session key is
 *      cryptographically bound to this specific attested session.
 * out: none - the derived AES-256 session key is stored in TA session state
 *      for subsequent TA_CONFIDENTIAL_IOT_CMD_PROTECT_SENSOR_DATA calls.
 */
#define TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE		4

#define TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE			65
#define TA_CONFIDENTIAL_IOT_SESSION_KEY_SIZE			32
#define TA_CONFIDENTIAL_IOT_TRANSCRIPT_HASH_SIZE		32
/* Anti-replay sequence number authenticated as GCM AAD: 8-byte big-endian.
 * Must match the server's seq.to_bytes(8, "big") in attested_network.py. */
#define TA_CONFIDENTIAL_IOT_SEQ_AAD_SIZE			8
#define TA_CONFIDENTIAL_IOT_HKDF_INFO		"CC-IOT-1 device-aead"

#endif /* CONFIDENTIAL_IOT_TA_H */
