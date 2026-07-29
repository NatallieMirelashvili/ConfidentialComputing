#ifndef CONFIDENTIAL_IOT_TA_H
#define CONFIDENTIAL_IOT_TA_H

#define TA_CONFIDENTIAL_IOT_UUID \
	{ 0x7d9f6d20, 0x5f11, 0x4d0c, \
		{ 0x9a, 0x17, 0x61, 0xc9, 0xc9, 0x1c, 0x00, 0x01 } }

/*
 * Sensor Module <-> Device authentication: a real HMAC-SHA256
 * challenge-response against the sensor's provisioned pre-shared secret
 * (see CMD_PROVISION_SENSOR_SECRET below). Invoked once per boot by the Host
 * CA, which passes no parameters and never sees the challenge or response -
 * the TA generates the challenge, relays it to the Sensor Module over the
 * sensor_link PTA's secure UART2 (Secure World only, see
 * docs/ARCHITECTURE.md), and verifies the reply itself via
 * TEE_MACCompareFinal(). READ_AND_PROTECT below refuses to run until this
 * has succeeded (sess->sensor_authenticated).
 *
 * in:  none; out: none. Result reflects whether authentication succeeded
 *      (TEE_SUCCESS) or not (TEE_ERROR_MAC_INVALID / TEE_ERROR_COMMUNICATION
 *      / TEE_ERROR_BAD_STATE if no secret has been provisioned yet).
 */
#define TA_CONFIDENTIAL_IOT_CMD_AUTHENTICATE_SENSOR		0

/*
 * Read one sensor reading and protect (AES-256-GCM encrypt) it under the
 * session key derived by HANDSHAKE_COMPLETE, in a single call. Collapses the
 * old two-step PROCESS_SENSOR_DATA + PROTECT_SENSOR_DATA into the inverted
 * shape docs/ARCHITECTURE.md calls for: no plaintext input parameter exists
 * at all (the reading is pulled from the sensor_link PTA, entirely inside
 * Secure World) - only ciphertext ever crosses back into the Host.
 *
 * A per-session, monotonically increasing sequence number is authenticated
 * as the GCM AAD (8-byte big-endian) and returned so the server can enforce
 * inner-session anti-replay: it rejects any message whose seq it has already
 * accepted. Because the seq is bound by the GCM tag, an attacker cannot
 * renumber a captured message to slip a replay past that check without
 * breaking authentication. (This is distinct from GCM nonce uniqueness,
 * which the fresh random 96-bit nonce below still provides.)
 *
 * in:  none.
 * out: params[0].memref = the 12-byte GCM nonce the TA generates.
 *      params[1].memref = ciphertext ‖ tag (16-byte tag appended after the ciphertext).
 *      params[2].value.a = sequence number authenticated for this message.
 */
#define TA_CONFIDENTIAL_IOT_CMD_READ_AND_PROTECT		1

/* Retired: the old two-param PROTECT_SENSOR_DATA, folded into
 * TA_CONFIDENTIAL_IOT_CMD_READ_AND_PROTECT above. Command id 2 is
 * intentionally left unassigned rather than reused. */

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
 * The TA ALSO signs this session's ephemeral public key with its own sealed
 * identity key (see CMD 6), which is what proves the key came from the genuine
 * TA rather than from a root-compromised Normal World that bypassed the TA
 * entirely and had the fTPM quote a key of its own (real AK, real PCR0, and
 * until now nothing to tell the difference). See
 * docs/HANDOFF_taIdentityBinding.md - this is the third attestation leg:
 * AK proves the device, PCR0 proves the firmware, ta_sig proves the TA.
 *
 * in:  params[1].memref = nonce issued by the server (variable length, at most
 *      TA_CONFIDENTIAL_IOT_NONCE_MAX bytes)
 *      params[2].memref = server ephemeral ECDH public key (65-byte point)
 * out: params[0].memref = device ephemeral ECDH public key
 *      (65-byte uncompressed SEC1 point: 0x04 || X || Y)
 *      params[3].memref = TA_CONFIDENTIAL_IOT_EVIDENCE_BLOCK_SIZE bytes:
 *        [0 .. 32)  SHA-256 transcript hash (the fTPM quote's qualifying data)
 *        [32 .. 96) TA identity signature, raw r||s, over
 *                   SHA-256(TA_CONFIDENTIAL_IOT_TA_IDENTITY_LABEL || nonce ||
 *                           server_ecdh_pub || device_ecdh_pub || device_id)
 *      Both share one memref because the GP Internal Core API caps a command at
 *      four parameters and all four are already in use. For the same reason
 *      device_id is NOT a parameter: the TA reads it from the identity object it
 *      sealed at provisioning, which also means the Host cannot assert a
 *      different identity per session.
 *
 * Result: TEE_SUCCESS, TEE_ERROR_BAD_STATE (no TA identity sealed yet - run
 * CMD 6 first, or the sealed object is malformed), TEE_ERROR_BAD_PARAMETERS /
 * TEE_ERROR_SHORT_BUFFER (param shape), or a storage/crypto error.
 */
#define TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE	3

/*
 * Handshake phase 2, called only after the server has confirmed the
 * attestation quote (attest_result.ok == true).
 *
 * Before deriving the session key, the TA now AUTHENTICATES THE SERVER
 * (Trust-On-First-Use pinning - see docs/HANDOFF_serverAuthentication.md).
 * It recomputes the labelled transcript digest
 *   SHA-256(TA_CONFIDENTIAL_IOT_SERVER_IDENTITY_LABEL || nonce ||
 *           server_ecdh_pub || device_ecdh_pub)
 * and verifies the presented ECDSA-P256 signature (params[3]) over it:
 *   - First use: no key pinned yet (TEE_ERROR_ITEM_NOT_FOUND on open) -> verify
 *     the signature against the PRESENTED identity key (params[2]); if it
 *     checks out, pin that key in secure storage (TEE_STORAGE_PRIVATE, object
 *     id "ciot.server.pubkey", first-write-wins, no OVERWRITE). A malformed
 *     signature is rejected even on first use (TOFU skips comparison, never
 *     verification).
 *   - Every later use: compare the presented identity key against the pinned
 *     one; any mismatch is rejected immediately (TEE_ERROR_ACCESS_CONFLICT)
 *     without even verifying; on a match, verify the signature against the
 *     pinned key.
 * On any failure the session key is NOT derived (session_key_valid stays
 * false) and the command returns an error - the two-independent-gates rule:
 * a compromised Host cannot skip this because the verdict lives in the TA.
 *
 * in:  params[0].memref = server ephemeral ECDH public key (65-byte point)
 *      params[1].memref = nonce (the same nonce the server issued and that
 *      was quoted by the fTPM), used as the HKDF salt so the session key is
 *      cryptographically bound to this specific attested session.
 *      params[2].memref = server identity public key (65-byte point) - pinned
 *      on first use, required to match thereafter.
 *      params[3].memref = server identity signature over the labelled
 *      transcript (raw r||s, TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE bytes).
 * out: none - the derived AES-256 session key is stored in TA session state
 *      for subsequent TA_CONFIDENTIAL_IOT_CMD_READ_AND_PROTECT calls.
 *
 * Result: TEE_SUCCESS, or TEE_ERROR_SIGNATURE_INVALID (signature does not
 * verify under the applicable identity key), TEE_ERROR_ACCESS_CONFLICT
 * (presented identity key != the pinned one), TEE_ERROR_BAD_PARAMETERS /
 * TEE_ERROR_BAD_FORMAT (param shape / point encoding), or a storage error.
 */
#define TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE		4

/*
 * One-time provisioning of the Sensor Module's pre-shared secret into this
 * TA's secure storage (TEE_STORAGE_PRIVATE, object id "ciot.sensor.psk").
 * Never compiled into source - one device image is shared fleet-wide, so
 * each device+sensor pairing's secret is installed at pairing time by
 * scripts/pair-sensor.sh, mirroring how scripts/provision-device.sh installs
 * the per-device Attestation Key into the fTPM rather than the binary.
 * Idempotent: refuses to overwrite an already-provisioned secret
 * (TEE_ERROR_ACCESS_CONFLICT), matching provision-device.sh's AK-exists gate.
 *
 * in:  params[0].memref = TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE-byte secret.
 * out: none.
 */
#define TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET	5

/*
 * One-time provisioning of this TA's OWN identity keypair (ECDSA P-256),
 * generated INSIDE the TA and sealed in secure storage (TEE_STORAGE_PRIVATE,
 * object id "ciot.ta.identity"). The private half never leaves the TEE; only
 * the public half is ever exported, and that is what the management server
 * pins at registration alongside the AK. See docs/HANDOFF_taIdentityBinding.md.
 *
 * This is what makes the sealed key trustworthy only in combination with the
 * project-private TA signing key (keys/README.md): secure storage is scoped to
 * the TA UUID, so without a private signing key an attacker with root could
 * load a malicious TA carrying this same UUID and read the object.
 *
 * The device_id is sealed ALONGSIDE the keypair and is hashed into every
 * signature this TA produces (see CMD 3), so the binding is immutable rather
 * than asserted by the untrusted Host once per session. It also means a copied
 * secure-storage image cannot be presented under a different device_id.
 *
 * Idempotent for the SAME device_id: a later call just re-exports the stored
 * public point, so provisioning can run on every boot. A call with a DIFFERENT
 * device_id is refused (TEE_ERROR_ACCESS_CONFLICT) - rebinding a device to a
 * new id requires wiping its secure storage.
 *
 * in:  params[0].memref = device_id, 1..TA_CONFIDENTIAL_IOT_DEVICE_ID_MAX
 *      bytes, no NUL terminator. Must be byte-identical to the device_id the
 *      Host sends in attest_response; both come from
 *      /etc/confidential_iot/device.conf (see edge_device.c's g_device_id).
 * out: params[1].memref = TA identity public key, 65-byte uncompressed SEC1
 *      point (0x04 || X || Y).
 *
 * Result: TEE_SUCCESS, TEE_ERROR_ACCESS_CONFLICT (already sealed under a
 * different device_id), TEE_ERROR_BAD_PARAMETERS (param shape or device_id
 * length), TEE_ERROR_SHORT_BUFFER (params[1] smaller than 65 bytes),
 * TEE_ERROR_BAD_STATE (sealed object malformed), or a storage/crypto error.
 */
#define TA_CONFIDENTIAL_IOT_CMD_GENERATE_TA_IDENTITY	6

#define TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE			65
#define TA_CONFIDENTIAL_IOT_SESSION_KEY_SIZE			32
#define TA_CONFIDENTIAL_IOT_TRANSCRIPT_HASH_SIZE		32
/* Server-identity ECDSA-P256 signature: raw r||s, 32+32 bytes. Must match the
 * server's sign_server_identity_raw() output in CC_Server/server/crypto.py. */
#define TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE			64
/* Domain-separation label prefixed into the server-identity transcript digest.
 * Must equal SERVER_IDENTITY_LABEL in CC_Server/server/attestation.py byte for
 * byte (used WITHOUT its NUL terminator - see trusted_app.c). */
#define TA_CONFIDENTIAL_IOT_SERVER_IDENTITY_LABEL	"CC-IOT-1 server-identity"
/* Persistent object (TEE_STORAGE_PRIVATE) holding the pinned 65-byte server
 * identity public key. Written first-write-wins on TOFU bootstrap. */
#define TA_CONFIDENTIAL_IOT_SERVER_PUBKEY_OBJID		"ciot.server.pubkey"
/* Anti-replay sequence number authenticated as GCM AAD: 8-byte big-endian.
 * Must match the server's seq.to_bytes(8, "big") in attested_network.py. */
#define TA_CONFIDENTIAL_IOT_SEQ_AAD_SIZE			8
#define TA_CONFIDENTIAL_IOT_HKDF_INFO		"CC-IOT-1 device-aead"

/* ---- TA identity (docs/HANDOFF_taIdentityBinding.md) ---------------------- */

/* TA-identity ECDSA-P256 signature: raw r||s, 32+32 bytes. The TEE emits
 * exactly this encoding, which is what the server's encode_dss_signature(r, s)
 * expects in CC_Server/server/attestation.py. */
#define TA_CONFIDENTIAL_IOT_TA_SIG_SIZE				64
/* CMD 3's params[3] payload: transcript_hash(32) || ta_sig(64). One memref
 * because the GP API allows only four parameters and all four are in use. */
#define TA_CONFIDENTIAL_IOT_EVIDENCE_BLOCK_SIZE \
	(TA_CONFIDENTIAL_IOT_TRANSCRIPT_HASH_SIZE + \
	 TA_CONFIDENTIAL_IOT_TA_SIG_SIZE)
/* Domain-separation label for the TA-identity signature. "CC-IOT-1" is this
 * protocol's VERSION prefix, not a per-device counter (compare
 * "CC-IOT-1 device-aead" and "CC-IOT-1 server-identity", which are the same
 * version with different purposes); per-device binding comes from the sealed
 * device_id hashed into the pre-image. Must equal TA_IDENTITY_LABEL in
 * CC_Server/server/attestation.py byte for byte - used WITHOUT its NUL
 * terminator, i.e. sizeof(label) - 1, exactly like the server-identity label. */
#define TA_CONFIDENTIAL_IOT_TA_IDENTITY_LABEL	"CC-IOT-1 ta-identity"
/* Persistent object (TEE_STORAGE_PRIVATE) holding the sealed TA identity:
 * the ECDSA P-256 private key plus the device_id it is bound to. Fixed-size
 * blob, first-write-wins (no OVERWRITE flag), layout:
 *   [0  .. 32)  private scalar d  (32B big-endian, left-zero-padded)
 *   [32 .. 64)  public X          (ditto)
 *   [64 .. 96)  public Y          (ditto)
 *   [96]        device_id length, 1..TA_CONFIDENTIAL_IOT_DEVICE_ID_MAX
 *   [97 ..160)  device_id, zero-padded, no NUL
 * No version byte by design: the device's persistent disk is wiped on every
 * rebuild (scripts/run-project.sh), so there is no format to migrate. */
#define TA_CONFIDENTIAL_IOT_TA_IDENTITY_OBJID		"ciot.ta.identity"
/* P-256 scalar/coordinate width, and the offsets derived from it. */
#define TA_CONFIDENTIAL_IOT_EC_SCALAR_SIZE			32
/* Bounded by edge_device.c's g_device_id[64] (63 chars + NUL). */
#define TA_CONFIDENTIAL_IOT_DEVICE_ID_MAX			63
#define TA_CONFIDENTIAL_IOT_TA_IDENTITY_BLOB_SIZE		160
/* Upper bound accepted for the server's attestation nonce, so CMD 3 can copy
 * it out of Host-shared memory before hashing. The server sends 32 bytes
 * (ATTEST_NONCE_LEN in CC_Server/server/constants.py). */
#define TA_CONFIDENTIAL_IOT_NONCE_MAX				64

/* Sensor reading cap: base64(nonce 12 + ciphertext 256 + tag 16) ~= 380
 * bytes, which fits every existing Host-side buffer (ciphertext[512],
 * raw[600], ct_b64[900], main.c's protected_data[512]) unchanged - see
 * edge_device.c. Grow all of those together if this ever needs to grow. */
#define TA_CONFIDENTIAL_IOT_READING_MAX			256
#define TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE			32

#endif /* CONFIDENTIAL_IOT_TA_H */
