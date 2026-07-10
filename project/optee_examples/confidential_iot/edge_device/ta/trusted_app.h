#ifndef TRUSTED_APP_H
#define TRUSTED_APP_H

#include <tee_internal_api.h>

/*
 * Per-session state. Opaque to the Host: allocated in TA_OpenSessionEntryPoint,
 * threaded through as sess_ctx by TA_InvokeCommandEntryPoint, freed in
 * TA_CloseSessionEntryPoint.
 *
 * ecdh_keypair holds the ephemeral ECDH private key between the two
 * handshake phases (generate_attestation_evidence -> handshake_complete).
 * session_key/session_key_valid hold the derived AES-256 session key once
 * the handshake completes, consumed by ta_protect_sensor_data.
 *
 * sensor_authenticated records whether the attached Sensor Module has proven
 * its identity to this device (Sensor <-> Device challenge-response). It is
 * set only by ta_authenticate_sensor and is a precondition, enforced inside
 * the TA, for ta_process_sensor_data / ta_protect_sensor_data. Keeping the
 * verdict here (rather than trusting the Host to have run the check) is what
 * stops a tampered Host CA from simply skipping sensor authentication: the
 * data-handling commands refuse to run while this is false.
 *
 * send_seq is a per-session monotonically increasing message counter used for
 * inner-session anti-replay: ta_protect_sensor_data increments it for every
 * data message and authenticates it as the AES-GCM AAD, so the server can
 * reject a message whose seq it has already seen. It is reset to 0 each time a
 * new session key is derived (ta_handshake_complete), matching the server,
 * which resets its expected counter for the freshly derived key.
 *
 * mock_reading/mock_reading_len hold the most recent sensor "reading" produced
 * inside the TA by ta_process_sensor_data (currently a mock incrementing
 * counter - see g_mock_value in trusted_app.c). ta_protect_sensor_data seals
 * exactly these bytes with AES-256-GCM, so the value is generated and
 * encrypted entirely in secure world and only leaves the device as ciphertext.
 */
struct confidential_iot_session {
	TEE_ObjectHandle ecdh_keypair;
	uint8_t session_key[32];
	bool session_key_valid;
	bool sensor_authenticated;
	uint64_t send_seq;
	char mock_reading[64];
	size_t mock_reading_len;
};

TEE_Result ta_authenticate_sensor(struct confidential_iot_session *sess,
				  uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_process_sensor_data(struct confidential_iot_session *sess,
				  uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_protect_sensor_data(struct confidential_iot_session *sess,
				  uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_generate_attestation_evidence(struct confidential_iot_session *sess,
					    uint32_t param_types,
					    TEE_Param params[4]);
TEE_Result ta_handshake_complete(struct confidential_iot_session *sess,
				 uint32_t param_types, TEE_Param params[4]);

#endif /* TRUSTED_APP_H */
