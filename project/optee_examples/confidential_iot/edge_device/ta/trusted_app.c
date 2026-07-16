#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdio.h>
#include "trusted_app.h"
#include <confidential_iot_ta.h>

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

	*sess_ctx = sess;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct confidential_iot_session *sess = sess_ctx;

	if (sess->ecdh_keypair != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->ecdh_keypair);

	/* Wipe the whole session (session_key and mock_reading are the
	 * sensitive fields; the rest costs nothing to clear too) before
	 * freeing, rather than naming fields one by one. */
	TEE_MemFill(sess, 0, sizeof(*sess));
	TEE_Free(sess);
}

/*
 * Sensor Module <-> Device authentication (the Secure Element's
 * HMAC-SHA256 challenge-response, per the project spec's normal-operation
 * flow). Called once per boot by the Host CA.
 *
 * STUB: the real challenge-response is a separate work item and is out of
 * scope here, so for now this unconditionally succeeds - it just records the          **** NOTICE THAT IT'S A STUB ****
 * "sensor is authentic" verdict in session state.
 *
 * SECURITY NOTE: when the real check is implemented it MUST compute/verify
 * the HMAC *inside this TA* and set sensor_authenticated only on a genuine
 * match - never trust a Host-supplied "it matched" result. The verdict is
 * deliberately stored here and enforced by ta_process_sensor_data /
 * ta_protect_sensor_data below, so a tampered Host CA that skips calling
 * this command cannot get any sensor data protected or forwarded: those
 * commands refuse to run while sensor_authenticated is false.
 */
TEE_Result ta_authenticate_sensor(struct confidential_iot_session *sess,
				  uint32_t __unused param_types,
				  TEE_Param __unused params[4])
{
	sess->sensor_authenticated = true;
	return TEE_SUCCESS;
}

/*
 * Mock sensor value. There is no real sensor in scope yet, so the "reading"
 * produced by ta_process_sensor_data is a monotonically incrementing counter.
 * It lives here, in the TA's secure-world memory, so the value is generated
 * inside the TEE and only ever leaves the device as AES-GCM ciphertext (sealed
 * by ta_protect_sensor_data).
 *
 * It is file-scope (not per-session) on purpose: it should keep climbing across
 * re-attestations within one boot and reset only when the device (and thus this
 * TA instance) restarts. It is distinct from sess->send_seq, which is the
 * per-session anti-replay counter and resets on every new session key.
 *
 * TODO(multi-device): a single static counter is fine while exactly one device
 * uses this TA. For several devices this must become per-session state.
 */
static uint32_t g_mock_value;

/*
 * Produce the current sensor reading into the session. Today that is the mock
 * counter above, formatted as the server's expected sample JSON; a real sensor
 * read would replace the body while keeping the same "build the reading in the
 * TA, then let ta_protect_sensor_data seal it" shape.
 */
TEE_Result ta_process_sensor_data(struct confidential_iot_session *sess,
				  uint32_t __unused param_types,
				  TEE_Param __unused params[4])
{
	int len;

	if (!sess->sensor_authenticated)
		return TEE_ERROR_BAD_STATE;

	g_mock_value++;

	len = snprintf(sess->mock_reading, sizeof(sess->mock_reading),
		       "{\"samples\":[{\"value\":%u,\"unit\":\"count\"}]}",
		       (unsigned)g_mock_value);
	if (len < 0 || (size_t)len >= sizeof(sess->mock_reading)) {
		sess->mock_reading_len = 0;
		return TEE_ERROR_OVERFLOW;
	}
	sess->mock_reading_len = (size_t)len;
	return TEE_SUCCESS;
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
 * Handshake phase 2: given the server's ephemeral ECDH public key and the
 * nonce it issued (already vetted by the server's fTPM-quote check before
 * the Host ever calls this), derive the shared secret and the AES-256
 * session key. Everything here - the ECDH private key, the raw shared
 * secret, and the derived key - lives and dies inside this TA; only the
 * final protect/unprotect operations ever consume session_key.
 */
TEE_Result ta_handshake_complete(struct confidential_iot_session *sess,
				 uint32_t param_types, TEE_Param params[4])
{
	static const char info[] = TA_CONFIDENTIAL_IOT_HKDF_INFO;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	uint8_t *peer;
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

	peer = params[0].memref.buffer;
	if (peer[0] != 0x04)
		return TEE_ERROR_BAD_FORMAT;

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
 * AES-256-GCM encrypt sensor data with the session key derived in
 * ta_handshake_complete(). Output layout matches the management server's
 * crypto.aead_encrypt()/aead_decrypt() convention: ciphertext with the
 * 16-byte tag appended; the nonce travels as a separate output.
 *
 * Inner-session anti-replay: a per-session monotonic counter (sess->send_seq)
 * is incremented for every message and authenticated as the GCM AAD (8-byte
 * big-endian), then returned to the Host in params[3].value.a so it can travel
 * on the wire. The server verifies the tag (which binds the seq) and then
 * rejects any seq it has already accepted - so a captured "data" message can't
 * be re-sent within the same session, and an attacker can't renumber it to
 * dodge that check without breaking the tag. (Uniqueness of the GCM *nonce*
 * itself is still handled separately, by the random 96-bit nonce above; the
 * seq is an authenticated ordering label, not the nonce.)
 */
TEE_Result ta_protect_sensor_data(struct confidential_iot_session *sess,
				  uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_MEMREF_OUTPUT,
						 TEE_PARAM_TYPE_VALUE_OUTPUT);
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
	 * session with the server (Device <-> Server). Neither the plaintext
	 * nor the session key is touched unless both hold.
	 */
	if (!sess->sensor_authenticated)
		return TEE_ERROR_BAD_STATE;
	if (!sess->session_key_valid)
		return TEE_ERROR_BAD_STATE;
	/*
	 * Seal the reading produced in secure world by ta_process_sensor_data
	 * (params[0], the Host-provided plaintext, is intentionally ignored - the
	 * value must originate inside the TA). Requires a reading to be staged.
	 */
	if (sess->mock_reading_len == 0)
		return TEE_ERROR_BAD_STATE;
	if (params[1].memref.size < 12)
		return TEE_ERROR_SHORT_BUFFER;
	if (params[2].memref.size < sess->mock_reading_len + sizeof(tag))
		return TEE_ERROR_SHORT_BUFFER;
	/*
	 * Counter kept within uint32 range so it round-trips faithfully through
	 * params[3].value.a; on exhaustion, refuse rather than wrap (the device
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

	TEE_GenerateRandom(params[1].memref.buffer, 12);
	params[1].memref.size = 12;

	res = TEE_AEInit(op, params[1].memref.buffer, 12, 128, sizeof(aad),
			  sess->mock_reading_len);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_AEUpdateAAD(op, aad, sizeof(aad));

	out_len = params[2].memref.size;
	res = TEE_AEEncryptFinal(op, sess->mock_reading,
				  sess->mock_reading_len,
				  params[2].memref.buffer, &out_len,
				  tag, &tag_len);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_MemMove((uint8_t *)params[2].memref.buffer + out_len, tag, tag_len);
	params[2].memref.size = out_len + tag_len;

	/* Commit the counter only once the message is fully formed, and hand
	 * the seq back so the Host can put it on the wire. */
	sess->send_seq = seq;
	params[3].value.a = (uint32_t)seq;
	params[3].value.b = 0;

out:
	TEE_FreeOperation(op);
	TEE_FreeTransientObject(key_obj);
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct confidential_iot_session *sess = sess_ctx;

	switch (cmd_id) {
	case TA_CONFIDENTIAL_IOT_CMD_AUTHENTICATE_SENSOR:
		return ta_authenticate_sensor(sess, param_types, params);
	case TA_CONFIDENTIAL_IOT_CMD_PROCESS_SENSOR_DATA:
		return ta_process_sensor_data(sess, param_types, params);
	case TA_CONFIDENTIAL_IOT_CMD_PROTECT_SENSOR_DATA:
		return ta_protect_sensor_data(sess, param_types, params);
	case TA_CONFIDENTIAL_IOT_CMD_GENERATE_ATTESTATION_EVIDENCE:
		return ta_generate_attestation_evidence(sess, param_types,
							 params);
	case TA_CONFIDENTIAL_IOT_CMD_HANDSHAKE_COMPLETE:
		return ta_handshake_complete(sess, param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
