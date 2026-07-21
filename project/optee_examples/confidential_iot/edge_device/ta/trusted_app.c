#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdio.h>
#include <string.h>
#include "trusted_app.h"
#include <confidential_iot_ta.h>
#include <pta_sensor_link.h>

/*
 * Read a P-256 coordinate attribute into a fixed 32-byte, left-zero-padded
 * big-endian buffer. GP implementations may return the minimal-length
 * encoding (dropping leading zero bytes), so we can't assume the returned
 * length is always 32.
 */
static TEE_Result read_ec_coordinate(TEE_ObjectHandle obj, uint32_t attr_id,
				     uint8_t out[32])
{
	uint8_t tmp[32] = { 0 };
	size_t len = sizeof(tmp);
	TEE_Result res = TEE_GetObjectBufferAttribute(obj, attr_id, tmp, &len);

	if (res != TEE_SUCCESS)
		return res;
	if (len > 32)
		return TEE_ERROR_BAD_FORMAT;

	TEE_MemFill(out, 0, 32);
	TEE_MemMove(out + (32 - len), tmp, len);
	return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **sess_ctx)
{
	struct confidential_iot_session *sess;

	sess = TEE_Malloc(sizeof(*sess), TEE_MALLOC_FILL_ZERO);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->ecdh_keypair = TEE_HANDLE_NULL;
	sess->session_key_valid = false;
	sess->sensor_authenticated = false;
	sess->send_seq = 0;
	sess->sensor_pta_sess = TEE_HANDLE_NULL;
	sess->sensor_pta_open = false;

	*sess_ctx = sess;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct confidential_iot_session *sess = sess_ctx;

	if (sess->ecdh_keypair != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->ecdh_keypair);
	if (sess->sensor_pta_open)
		TEE_CloseTASession(sess->sensor_pta_sess);

	/* Wipe the whole session (session_key and reading are the sensitive
	 * fields; the rest costs nothing to clear too) before freeing, rather
	 * than naming fields one by one. */
	TEE_MemFill(sess, 0, sizeof(*sess));
	TEE_Free(sess);
}

/*
 * Lazily open (and cache for the TA session's lifetime) a session to the
 * sensor_link PTA - the sole path to the Sensor Module, over a UART only
 * Secure World can address (see docs/ARCHITECTURE.md). Opening it here
 * rather than in TA_OpenSessionEntryPoint means a device that never
 * authenticates a sensor never pays the cost.
 */
static TEE_Result open_sensor_pta(struct confidential_iot_session *sess)
{
	static const TEE_UUID uuid = PTA_SENSOR_LINK_UUID;
	TEE_Result res;

	if (sess->sensor_pta_open)
		return TEE_SUCCESS;

	res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				 &sess->sensor_pta_sess, NULL);
	if (res != TEE_SUCCESS)
		return res;

	sess->sensor_pta_open = true;
	return TEE_SUCCESS;
}

/*
 * Sensor Module <-> Device authentication: the Secure Element's real
 * HMAC-SHA256 challenge-response, per the project spec's normal-operation
 * flow. Called once per boot by the Host CA, which passes no parameters and
 * never sees the challenge or the response - both travel only over the
 * sensor_link PTA's secure UART2, entirely inside Secure World.
 *
 * The pre-shared secret verified against is loaded from this TA's own
 * secure storage (provisioned once via ta_provision_sensor_secret, never
 * compiled into source). The HMAC itself is computed and compared *inside
 * this TA* via TEE_MACCompareFinal() - sensor_authenticated is set true only
 * on a genuine match, never trusting a Host-supplied "it matched" result.
 * ta_read_and_protect below refuses to run while this is false, so a
 * tampered Host CA that skips calling this command (or lies about the
 * result) gains nothing: the data path stays closed.
 */
TEE_Result ta_authenticate_sensor(struct confidential_iot_session *sess,
				  uint32_t __unused param_types,
				  TEE_Param __unused params[4])
{
	TEE_ObjectHandle secret_obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
	TEE_OperationHandle mac_op = TEE_HANDLE_NULL;
	TEE_Attribute key_attr;
	TEE_Result res;
	uint8_t secret[TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE];
	size_t secret_len = sizeof(secret);
	uint8_t challenge[SENSOR_LINK_CHALLENGE_SIZE];
	uint8_t response[SENSOR_LINK_HMAC_SIZE];
	uint32_t err_origin;
	TEE_Param sensor_params[TEE_NUM_PARAMS];

	sess->sensor_authenticated = false;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "ciot.sensor.psk",
					strlen("ciot.sensor.psk"),
					TEE_DATA_FLAG_ACCESS_READ,
					&secret_obj);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE; /* no secret provisioned yet */

	res = TEE_ReadObjectData(secret_obj, secret, secret_len, &secret_len);
	TEE_CloseObject(secret_obj);
	if (res != TEE_SUCCESS || secret_len != sizeof(secret)) {
		TEE_MemFill(secret, 0, sizeof(secret));
		return TEE_ERROR_BAD_STATE;
	}

	res = open_sensor_pta(sess);
	if (res != TEE_SUCCESS)
		goto out_wipe_secret;

	TEE_GenerateRandom(challenge, sizeof(challenge));

	memset(sensor_params, 0, sizeof(sensor_params));
	sensor_params[0].memref.buffer = challenge;
	sensor_params[0].memref.size = sizeof(challenge);
	sensor_params[1].memref.buffer = response;
	sensor_params[1].memref.size = sizeof(response);

	res = TEE_InvokeTACommand(sess->sensor_pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_SENSOR_LINK_CMD_CHALLENGE,
				  TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_MEMREF_OUTPUT,
						  TEE_PARAM_TYPE_NONE,
						  TEE_PARAM_TYPE_NONE),
				  sensor_params, &err_origin);
	if (res != TEE_SUCCESS)
		goto out_wipe_secret;

	res = TEE_AllocateOperation(&mac_op, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, sizeof(secret) * 8);
	if (res != TEE_SUCCESS)
		goto out_wipe_secret;

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
					  sizeof(secret) * 8, &key_obj);
	if (res != TEE_SUCCESS)
		goto out_free_op;

	TEE_InitRefAttribute(&key_attr, TEE_ATTR_SECRET_VALUE, secret,
			     sizeof(secret));
	res = TEE_PopulateTransientObject(key_obj, &key_attr, 1);
	if (res != TEE_SUCCESS)
		goto out_free_key;

	res = TEE_SetOperationKey(mac_op, key_obj);
	if (res != TEE_SUCCESS)
		goto out_free_key;

	TEE_MACInit(mac_op, NULL, 0);
	res = TEE_MACCompareFinal(mac_op, challenge, sizeof(challenge),
				  response, sizeof(response));
	sess->sensor_authenticated = (res == TEE_SUCCESS);

out_free_key:
	TEE_FreeTransientObject(key_obj);
out_free_op:
	TEE_FreeOperation(mac_op);
out_wipe_secret:
	TEE_MemFill(secret, 0, sizeof(secret));
	return res;
}

/*
 * Handshake phase 1: generate a fresh ephemeral ECDH (P-256) keypair for
 * this attestation session and hand back the public half. The private half
 * stays in sess->ecdh_keypair, inside this TA's secure-world memory, until
 * ta_handshake_complete() consumes and discards it.
 *
 * Also computes and returns the handshake transcript hash
 * SHA-256(nonce || server_ecdh_pub || device_ecdh_pub) that the Host CA
 * feeds to the fTPM as the quote's qualifying data. The digest itself is
 * over public data only; it is computed here rather than in the Host so
 * that Normal World never needs its own SHA-256 implementation.
 */
TEE_Result ta_generate_attestation_evidence(struct confidential_iot_session *sess,
					    uint32_t param_types,
					    TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT);
	TEE_Result res;
	TEE_Attribute curve_attr;
	TEE_OperationHandle digest_op = TEE_HANDLE_NULL;
	uint8_t x[32];
	uint8_t y[32];
	uint8_t *out;
	size_t hash_len;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size < TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE)
		return TEE_ERROR_SHORT_BUFFER;
	if (params[2].memref.size != TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[3].memref.size < TA_CONFIDENTIAL_IOT_TRANSCRIPT_HASH_SIZE)
		return TEE_ERROR_SHORT_BUFFER;

	if (sess->ecdh_keypair != TEE_HANDLE_NULL) {
		TEE_FreeTransientObject(sess->ecdh_keypair);
		sess->ecdh_keypair = TEE_HANDLE_NULL;
	}
	sess->session_key_valid = false;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, 256,
					   &sess->ecdh_keypair);
	if (res != TEE_SUCCESS)
		return res;

	TEE_InitValueAttribute(&curve_attr, TEE_ATTR_ECC_CURVE,
				TEE_ECC_CURVE_NIST_P256, 0);

	res = TEE_GenerateKey(sess->ecdh_keypair, 256, &curve_attr, 1);
	if (res != TEE_SUCCESS)
		goto err_free_keypair;

	res = read_ec_coordinate(sess->ecdh_keypair,
				  TEE_ATTR_ECC_PUBLIC_VALUE_X, x);
	if (res != TEE_SUCCESS)
		goto err_free_keypair;

	res = read_ec_coordinate(sess->ecdh_keypair,
				  TEE_ATTR_ECC_PUBLIC_VALUE_Y, y);
	if (res != TEE_SUCCESS)
		goto err_free_keypair;

	out = params[0].memref.buffer;
	out[0] = 0x04; // its a standard prefix for uncompressed EC 
	TEE_MemMove(out + 1, x, 32);
	TEE_MemMove(out + 33, y, 32);
	params[0].memref.size = TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE;

	/*
	 * transcript_hash = SHA-256(nonce || server_ecdh_pub || device_ecdh_pub)
	 * - must match compute_transcript_hash() in the server's
	 * attestation.py byte for byte.
	 */
	res = TEE_AllocateOperation(&digest_op, TEE_ALG_SHA256,
				    TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto err_free_keypair;

	TEE_DigestUpdate(digest_op, params[1].memref.buffer,
			 params[1].memref.size);
	TEE_DigestUpdate(digest_op, params[2].memref.buffer,
			 params[2].memref.size);
	hash_len = params[3].memref.size;
	res = TEE_DigestDoFinal(digest_op, out,
				TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE,
				params[3].memref.buffer, &hash_len);
	TEE_FreeOperation(digest_op);
	if (res != TEE_SUCCESS)
		goto err_free_keypair;
	params[3].memref.size = hash_len;

	return TEE_SUCCESS;

err_free_keypair:
	TEE_FreeTransientObject(sess->ecdh_keypair);
	sess->ecdh_keypair = TEE_HANDLE_NULL;
	return res;
}

/*
 * Server authentication (Trust-On-First-Use), performed before the session key
 * is derived. Verifies the server's per-session identity signature over
 *   SHA-256(label || nonce || server_ecdh_pub || device_ecdh_pub)
 * and, on first use, pins the server's identity public key in secure storage.
 * See docs/HANDOFF_serverAuthentication.md and CMD_HANDSHAKE_COMPLETE's doc in
 * confidential_iot_ta.h. `device_pub` is this session's ephemeral public point
 * (0x04 || X || Y), reconstructed by the caller from sess->ecdh_keypair.
 *
 * Returns TEE_SUCCESS only if the server is authentic. On mismatch with the
 * pinned key returns TEE_ERROR_ACCESS_CONFLICT; on a bad signature returns
 * TEE_ERROR_SIGNATURE_INVALID. Either way the caller must NOT derive the
 * session key.
 */
static TEE_Result authenticate_server(const uint8_t *nonce, size_t nonce_len,
				      const uint8_t *server_ecdh_pub,
				      const uint8_t *device_pub,
				      const uint8_t *server_identity_pub,
				      const uint8_t *sig, size_t sig_len)
{
	static const char label[] = TA_CONFIDENTIAL_IOT_SERVER_IDENTITY_LABEL;
	TEE_Result res;
	TEE_OperationHandle digest_op = TEE_HANDLE_NULL;
	TEE_OperationHandle verify_op = TEE_HANDLE_NULL;
	TEE_ObjectHandle id_key = TEE_HANDLE_NULL;
	TEE_ObjectHandle pinned_obj = TEE_HANDLE_NULL;
	TEE_Attribute id_attrs[3];
	uint8_t digest[TA_CONFIDENTIAL_IOT_TRANSCRIPT_HASH_SIZE];
	uint8_t pinned[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	size_t pinned_len = sizeof(pinned);
	size_t digest_len = sizeof(digest);
	const uint8_t *verify_key = server_identity_pub;
	bool need_pin = false;

	if (sig_len != TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (server_identity_pub[0] != 0x04)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Labelled transcript digest. The label bytes go first (WITHOUT the
	 * NUL terminator) to domain-separate this from the device's own quote
	 * transcript. Must match the server's pre-image byte for byte.
	 */
	res = TEE_AllocateOperation(&digest_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;
	TEE_DigestUpdate(digest_op, label, sizeof(label) - 1);
	TEE_DigestUpdate(digest_op, nonce, nonce_len);
	TEE_DigestUpdate(digest_op, server_ecdh_pub,
			 TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE);
	res = TEE_DigestDoFinal(digest_op, device_pub,
				TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE,
				digest, &digest_len);
	TEE_FreeOperation(digest_op);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * First use vs. subsequent use: is a server key already pinned? On a
	 * match we verify against the *pinned* value read from secure storage;
	 * any mismatch is rejected immediately, without verifying against the
	 * attacker-presented key.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       TA_CONFIDENTIAL_IOT_SERVER_PUBKEY_OBJID,
				       strlen(TA_CONFIDENTIAL_IOT_SERVER_PUBKEY_OBJID),
				       TEE_DATA_FLAG_ACCESS_READ, &pinned_obj);
	if (res == TEE_SUCCESS) {
		res = TEE_ReadObjectData(pinned_obj, pinned, pinned_len,
					 &pinned_len);
		TEE_CloseObject(pinned_obj);
		if (res != TEE_SUCCESS)
			return res;
		if (pinned_len != TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE)
			return TEE_ERROR_BAD_STATE;
		if (TEE_MemCompare(pinned, server_identity_pub,
				   TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE) != 0)
			return TEE_ERROR_ACCESS_CONFLICT;
		verify_key = pinned;
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		need_pin = true; /* TOFU bootstrap: verify first, then pin */
	} else {
		return res;
	}

	/* Verify the signature under the applicable (pinned or presented) key. */
	TEE_InitRefAttribute(&id_attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			     (void *)(verify_key + 1), 32);
	TEE_InitRefAttribute(&id_attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     (void *)(verify_key + 33), 32);
	TEE_InitValueAttribute(&id_attrs[2], TEE_ATTR_ECC_CURVE,
			       TEE_ECC_CURVE_NIST_P256, 0);

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY, 256, &id_key);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_PopulateTransientObject(id_key, id_attrs, 3);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&verify_op, TEE_ALG_ECDSA_P256,
				    TEE_MODE_VERIFY, 256);
	if (res != TEE_SUCCESS)
		goto out;
	res = TEE_SetOperationKey(verify_op, id_key);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AsymmetricVerifyDigest(verify_op, NULL, 0, digest,
					sizeof(digest), (void *)sig, sig_len);
	if (res != TEE_SUCCESS) {
		res = TEE_ERROR_SIGNATURE_INVALID;
		goto out;
	}

	/*
	 * Authenticated. On first use, pin the now-trusted key. First-write-
	 * wins: no TEE_DATA_FLAG_OVERWRITE, and a concurrent create
	 * (TEE_ERROR_ACCESS_CONFLICT) is treated as success.
	 */
	if (need_pin) {
		TEE_ObjectHandle new_obj = TEE_HANDLE_NULL;

		res = TEE_CreatePersistentObject(
			TEE_STORAGE_PRIVATE,
			TA_CONFIDENTIAL_IOT_SERVER_PUBKEY_OBJID,
			strlen(TA_CONFIDENTIAL_IOT_SERVER_PUBKEY_OBJID),
			TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL,
			server_identity_pub,
			TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE, &new_obj);
		if (res == TEE_ERROR_ACCESS_CONFLICT)
			res = TEE_SUCCESS;
		else if (res == TEE_SUCCESS)
			TEE_CloseObject(new_obj);
	}

out:
	TEE_FreeOperation(verify_op);
	TEE_FreeTransientObject(id_key);
	return res;
}

/*
 * Handshake phase 2: given the server's ephemeral ECDH public key and the
 * nonce it issued (already vetted by the server's fTPM-quote check before
 * the Host ever calls this), first AUTHENTICATE THE SERVER (verify + TOFU-pin
 * its identity signature, see authenticate_server above), and only then derive
 * the shared secret and the AES-256 session key. Everything here - the ECDH
 * private key, the raw shared secret, and the derived key - lives and dies
 * inside this TA; only the final protect/unprotect operations ever consume
 * session_key.
 */
TEE_Result ta_handshake_complete(struct confidential_iot_session *sess,
				 uint32_t param_types, TEE_Param params[4])
{
	static const char info[] = TA_CONFIDENTIAL_IOT_HKDF_INFO;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Result res;
	uint8_t *peer;
	uint8_t device_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	uint8_t dx[32];
	uint8_t dy[32];
	TEE_Attribute peer_attrs[2];
	TEE_ObjectHandle shared = TEE_HANDLE_NULL;
	TEE_OperationHandle ecdh_op = TEE_HANDLE_NULL;
	uint8_t shared_bytes[32];
	size_t shared_len = sizeof(shared_bytes);
	TEE_ObjectHandle ikm = TEE_HANDLE_NULL;
	TEE_Attribute ikm_attr;
	TEE_Attribute hkdf_params[3];
	TEE_ObjectHandle okm = TEE_HANDLE_NULL;
	TEE_OperationHandle hkdf_op = TEE_HANDLE_NULL;
	size_t key_len = sizeof(sess->session_key);

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (sess->ecdh_keypair == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;
	if (params[0].memref.size != TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[2].memref.size != TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE ||
	    params[3].memref.size != TA_CONFIDENTIAL_IOT_SERVER_SIG_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	peer = params[0].memref.buffer;
	if (peer[0] != 0x04)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Authenticate the server before deriving anything. Reconstruct this
	 * session's device public point (0x04 || X || Y) from the ephemeral
	 * keypair (still alive - it's consumed in the out: block below) so the
	 * TA can recompute the exact transcript the server signed. On any
	 * failure, goto out: session_key_valid stays false and the single-use
	 * keypair is consumed, forcing a fresh attestation next time.
	 */
	res = read_ec_coordinate(sess->ecdh_keypair, TEE_ATTR_ECC_PUBLIC_VALUE_X, dx);
	if (res != TEE_SUCCESS)
		goto out;
	res = read_ec_coordinate(sess->ecdh_keypair, TEE_ATTR_ECC_PUBLIC_VALUE_Y, dy);
	if (res != TEE_SUCCESS)
		goto out;
	device_pub[0] = 0x04;
	TEE_MemMove(device_pub + 1, dx, 32);
	TEE_MemMove(device_pub + 33, dy, 32);

	res = authenticate_server(params[1].memref.buffer, params[1].memref.size,
				  peer, device_pub, params[2].memref.buffer,
				  params[3].memref.buffer, params[3].memref.size);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&peer_attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			      peer + 1, 32);
	TEE_InitRefAttribute(&peer_attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			      peer + 33, 32);

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, 256, &shared);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&ecdh_op, TEE_ALG_ECDH_P256,
				    TEE_MODE_DERIVE, 256);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(ecdh_op, sess->ecdh_keypair);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_DeriveKey(ecdh_op, peer_attrs, 2, shared);

	res = TEE_GetObjectBufferAttribute(shared, TEE_ATTR_SECRET_VALUE, // ** Shared secret derivation **
					   shared_bytes, &shared_len); // shared_bytes will hold the shared secret
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM, shared_len * 8,
					   &ikm); // IKM = Input Keying Material
	if (res != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&ikm_attr, TEE_ATTR_HKDF_IKM, shared_bytes,
			      shared_len);
	res = TEE_PopulateTransientObject(ikm, &ikm_attr, 1);
	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * Salt = the server's attestation nonce: binds this session key to
	 * the one specific attested session it was issued for. Info label
	 * mirrors the management server's INFO_DEVICE_AEAD constant so both
	 * sides derive the identical key from the identical HKDF context.
	 */
	TEE_InitRefAttribute(&hkdf_params[0], __OPTEE_TEE_ATTR_HKDF_SALT,
			      params[1].memref.buffer, params[1].memref.size);
	TEE_InitRefAttribute(&hkdf_params[1], __OPTEE_ATTR_HKDF_INFO,
			      info, sizeof(info) - 1);
	TEE_InitValueAttribute(&hkdf_params[2], TEE_ATTR_HKDF_OKM_LENGTH,
				sizeof(sess->session_key), 0);

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
					   sizeof(sess->session_key) * 8, &okm);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&hkdf_op, TEE_ALG_HKDF_SHA256_DERIVE_KEY,
				    TEE_MODE_DERIVE, shared_len * 8);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(hkdf_op, ikm);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_DeriveKey(hkdf_op, hkdf_params, 3, okm);

	res = TEE_GetObjectBufferAttribute(okm, TEE_ATTR_SECRET_VALUE,
					   sess->session_key, &key_len);
	if (res == TEE_SUCCESS) {
		sess->session_key_valid = true;
		/* Fresh key => restart the anti-replay counter from zero; the
		 * server does the same for this newly derived key. */
		sess->send_seq = 0;
	}

out:
	TEE_FreeOperation(hkdf_op);
	TEE_FreeTransientObject(okm);
	TEE_FreeTransientObject(ikm);
	TEE_FreeOperation(ecdh_op);
	TEE_FreeTransientObject(shared);
	TEE_MemFill(shared_bytes, 0, sizeof(shared_bytes));

	/* Ephemeral ECDH keypair is single-use: consumed either way. */
	if (sess->ecdh_keypair != TEE_HANDLE_NULL) {
		TEE_FreeTransientObject(sess->ecdh_keypair);
		sess->ecdh_keypair = TEE_HANDLE_NULL;
	}

	return res;
}

/*
 * Pull one framed reading off the sensor_link PTA and format it into
 * sess->reading as the server's expected sample JSON. Payload layout is
 * documented in pta_sensor_link.h: [4B big-endian int32 value][1B
 * unit_len][unit_len ASCII unit].
 */
static TEE_Result read_sensor_reading(struct confidential_iot_session *sess)
{
	uint8_t payload[SENSOR_LINK_READING_MAX];
	TEE_Param sensor_params[TEE_NUM_PARAMS];
	TEE_Result res;
	uint32_t err_origin;
	int32_t value;
	uint8_t unit_len;
	char unit[SENSOR_LINK_READING_UNIT_MAX + 1];
	int len;

	res = open_sensor_pta(sess);
	if (res != TEE_SUCCESS)
		return res;

	memset(sensor_params, 0, sizeof(sensor_params));
	sensor_params[0].memref.buffer = payload;
	sensor_params[0].memref.size = sizeof(payload);

	res = TEE_InvokeTACommand(sess->sensor_pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_SENSOR_LINK_CMD_READ,
				  TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						  TEE_PARAM_TYPE_NONE,
						  TEE_PARAM_TYPE_NONE,
						  TEE_PARAM_TYPE_NONE),
				  sensor_params, &err_origin);
	if (res != TEE_SUCCESS)
		return res;

	if (sensor_params[0].memref.size < SENSOR_LINK_READING_VALUE_SIZE + 1)
		return TEE_ERROR_BAD_FORMAT;

	value = (int32_t)(((uint32_t)payload[0] << 24) |
			   ((uint32_t)payload[1] << 16) |
			   ((uint32_t)payload[2] << 8) |
			   (uint32_t)payload[3]);
	unit_len = payload[SENSOR_LINK_READING_VALUE_SIZE];
	if (unit_len > SENSOR_LINK_READING_UNIT_MAX ||
	    sensor_params[0].memref.size !=
		    (size_t)SENSOR_LINK_READING_VALUE_SIZE + 1 + unit_len)
		return TEE_ERROR_BAD_FORMAT;

	TEE_MemMove(unit, payload + SENSOR_LINK_READING_VALUE_SIZE + 1,
		    unit_len);
	unit[unit_len] = '\0';

	len = snprintf(sess->reading, sizeof(sess->reading),
		       "{\"samples\":[{\"value\":%d,\"unit\":\"%s\"}]}",
		       (int)value, unit);
	if (len < 0 || (size_t)len >= sizeof(sess->reading)) {
		sess->reading_len = 0;
		return TEE_ERROR_OVERFLOW;
	}
	sess->reading_len = (size_t)len;
	return TEE_SUCCESS;
}

/*
 * Read one sensor reading (entirely inside Secure World, over the
 * sensor_link PTA - see read_sensor_reading above) and AES-256-GCM encrypt
 * it under the session key derived in ta_handshake_complete(), in a single
 * call. There is no plaintext input parameter at all: the Host can neither
 * supply nor observe the reading, only the resulting ciphertext.
 *
 * Output layout matches the management server's crypto.aead_encrypt()/
 * aead_decrypt() convention: ciphertext with the 16-byte tag appended; the
 * nonce travels as a separate output.
 *
 * Inner-session anti-replay: a per-session monotonic counter (sess->send_seq)
 * is incremented for every message and authenticated as the GCM AAD (8-byte
 * big-endian), then returned to the Host in params[2].value.a so it can travel
 * on the wire. The server verifies the tag (which binds the seq) and then
 * rejects any seq it has already accepted - so a captured "data" message can't
 * be re-sent within the same session, and an attacker can't renumber it to
 * dodge that check without breaking the tag. (Uniqueness of the GCM *nonce*
 * itself is still handled separately, by the random 96-bit nonce above; the
 * seq is an authenticated ordering label, not the nonce.)
 */
TEE_Result ta_read_and_protect(struct confidential_iot_session *sess,
			       uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_VALUE_OUTPUT,
						 TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Attribute key_attr;
	uint8_t tag[16];
	size_t tag_len = sizeof(tag);
	size_t out_len;
	uint64_t seq;
	uint8_t aad[TA_CONFIDENTIAL_IOT_SEQ_AAD_SIZE];
	int i;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	/*
	 * Two independent preconditions, both enforced here rather than
	 * trusted from the Host: the sensor must have authenticated to this
	 * device (Sensor <-> Device), and the device must have a live attested
	 * session with the server (Device <-> Server). Neither the reading
	 * nor the session key is touched unless both hold.
	 */
	if (!sess->sensor_authenticated)
		return TEE_ERROR_BAD_STATE;
	if (!sess->session_key_valid)
		return TEE_ERROR_BAD_STATE;
	if (params[0].memref.size < 12)
		return TEE_ERROR_SHORT_BUFFER;

	res = read_sensor_reading(sess);
	if (res != TEE_SUCCESS)
		return res;

	if (params[1].memref.size < sess->reading_len + sizeof(tag))
		return TEE_ERROR_SHORT_BUFFER;
	/*
	 * Counter kept within uint32 range so it round-trips faithfully through
	 * params[2].value.a; on exhaustion, refuse rather than wrap (the device
	 * must re-attest, which derives a fresh key and resets the counter).
	 */
	if (sess->send_seq >= 0xffffffffULL)
		return TEE_ERROR_OVERFLOW;
	seq = sess->send_seq + 1;

	/* AAD = seq as 8-byte big-endian. */
	for (i = 0; i < TA_CONFIDENTIAL_IOT_SEQ_AAD_SIZE; i++)
		aad[i] = (uint8_t)(seq >> (8 * (TA_CONFIDENTIAL_IOT_SEQ_AAD_SIZE - 1 - i)));

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &key_obj);
	if (res != TEE_SUCCESS)
		return res;

	TEE_InitRefAttribute(&key_attr, TEE_ATTR_SECRET_VALUE,
			      sess->session_key, sizeof(sess->session_key));
	res = TEE_PopulateTransientObject(key_obj, &key_attr, 1);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, 256);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_SetOperationKey(op, key_obj);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_GenerateRandom(params[0].memref.buffer, 12);
	params[0].memref.size = 12;

	res = TEE_AEInit(op, params[0].memref.buffer, 12, 128, sizeof(aad),
			  sess->reading_len);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_AEUpdateAAD(op, aad, sizeof(aad));

	out_len = params[1].memref.size;
	res = TEE_AEEncryptFinal(op, sess->reading, sess->reading_len,
				  params[1].memref.buffer, &out_len,
				  tag, &tag_len);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_MemMove((uint8_t *)params[1].memref.buffer + out_len, tag, tag_len);
	params[1].memref.size = out_len + tag_len;

	/* Commit the counter only once the message is fully formed, and hand
	 * the seq back so the Host can put it on the wire. */
	sess->send_seq = seq;
	params[2].value.a = (uint32_t)seq;
	params[2].value.b = 0;

out:
	TEE_FreeOperation(op);
	TEE_FreeTransientObject(key_obj);
	return res;
}

/*
 * One-time provisioning of the Sensor Module's pre-shared secret into this
 * TA's secure storage. Never compiled into source - see
 * TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET's doc comment in
 * confidential_iot_ta.h. Idempotent: TEE_CreatePersistentObject without
 * TEE_DATA_FLAG_OVERWRITE fails with TEE_ERROR_ACCESS_CONFLICT if a secret
 * is already stored, which this treats as an expected "already provisioned"
 * outcome rather than an error, mirroring provision-device.sh's AK-exists
 * gate.
 */
TEE_Result ta_provision_sensor_secret(struct confidential_iot_session __unused *sess,
				      uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size != TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, "ciot.sensor.psk",
					 strlen("ciot.sensor.psk"),
					 TEE_DATA_FLAG_ACCESS_WRITE,
					 TEE_HANDLE_NULL,
					 params[0].memref.buffer,
					 params[0].memref.size, &obj);
	if (res == TEE_ERROR_ACCESS_CONFLICT)
		return TEE_SUCCESS; /* already provisioned, idempotent no-op */
	if (res != TEE_SUCCESS)
		return res;

	TEE_CloseObject(obj);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct confidential_iot_session *sess = sess_ctx;

	switch (cmd_id) {
	case TA_CONFIDENTIAL_IOT_CMD_AUTHENTICATE_SENSOR:
		return ta_authenticate_sensor(sess, param_types, params);
	case TA_CONFIDENTIAL_IOT_CMD_READ_AND_PROTECT:
		return ta_read_and_protect(sess, param_types, params);
	case TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE:
		return ta_generate_attestation_evidence(sess, param_types,
							 params);
	case TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE:
		return ta_handshake_complete(sess, param_types, params);
	case TA_CONFIDENTIAL_IOT_CMD_PROVISION_SENSOR_SECRET:
		return ta_provision_sensor_secret(sess, param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
