#ifndef TRUSTED_APP_H
#define TRUSTED_APP_H

#include <tee_internal_api.h>
#include <confidential_iot_ta.h>

/*
 * Per-session state. Opaque to the Host: allocated in TA_OpenSessionEntryPoint,
 * threaded through as sess_ctx by TA_InvokeCommandEntryPoint, freed in
 * TA_CloseSessionEntryPoint.
 *
 * ecdh_keypair holds the ephemeral ECDH private key between the two
 * handshake phases (generate_attestation_evidence -> handshake_complete).
 * session_key/session_key_valid hold the derived AES-256 session key once
 * the handshake completes, consumed by ta_read_and_protect.
 *
 * sensor_authenticated records whether the attached Sensor Module has proven
 * its identity to this device via a real HMAC-SHA256 challenge-response
 * (ta_authenticate_sensor, run over the sensor_link PTA's secure UART2 -
 * see docs/ARCHITECTURE.md). It is a precondition, enforced inside the TA,
 * for ta_read_and_protect. Keeping the verdict here (rather than trusting
 * the Host to have run the check) is what stops a tampered Host CA from
 * simply skipping sensor authentication: the data-handling command refuses
 * to run while this is false.
 *
 * send_seq is a per-session monotonically increasing message counter used for
 * inner-session anti-replay: ta_read_and_protect increments it for every
 * data message and authenticates it as the AES-GCM AAD, so the server can
 * reject a message whose seq it has already seen. It is reset to 0 each time a
 * new session key is derived (ta_handshake_complete), matching the server,
 * which resets its expected counter for the freshly derived key.
 *
 * reading/reading_len hold the most recent sensor reading, pulled from the
 * sensor_link PTA (never from the Host) by ta_read_and_protect, which then
 * seals exactly these bytes with AES-256-GCM in the same call - the value is
 * generated and encrypted entirely in secure world and only ever leaves the
 * device as ciphertext.
 *
 * sensor_pta_sess/sensor_pta_open cache the TEE_OpenTASession() handle to the
 * sensor_link PTA across the whole TA session lifetime (opened lazily on
 * first use, closed in TA_CloseSessionEntryPoint) rather than reopening it
 * on every call.
 */
struct confidential_iot_session {
	TEE_ObjectHandle ecdh_keypair;
	uint8_t session_key[32];
	bool session_key_valid;
	bool sensor_authenticated;
	uint64_t send_seq;
	char reading[TA_CONFIDENTIAL_IOT_READING_MAX];
	size_t reading_len;
	TEE_TASessionHandle sensor_pta_sess;
	bool sensor_pta_open;
};

TEE_Result ta_authenticate_sensor(struct confidential_iot_session *sess,
				  uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_read_and_protect(struct confidential_iot_session *sess,
			       uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_provision_sensor_secret(struct confidential_iot_session *sess,
				      uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_generate_attestation_evidence(struct confidential_iot_session *sess,
					    uint32_t param_types,
					    TEE_Param params[4]);
TEE_Result ta_handshake_complete(struct confidential_iot_session *sess,
				 uint32_t param_types, TEE_Param params[4]);

#endif /* TRUSTED_APP_H */
