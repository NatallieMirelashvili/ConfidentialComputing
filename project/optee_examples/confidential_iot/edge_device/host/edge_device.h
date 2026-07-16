#ifndef EDGE_DEVICE_H
#define EDGE_DEVICE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Opens the persistent TEE Client API context/session (kept open for the
 * whole process lifetime, reused across every edge_call_ta invocation - the
 * TA's per-session state, including the ephemeral ECDH keypair carried
 * between the two handshake phases, lives only as long as the session
 * stays open) and reads this device's local config
 * (device_id / server host+port / TPM AK handle - see
 * scripts/provision-device.sh). Call once, before anything else here.
 */
int edge_device_init(void);
void edge_device_shutdown(void);

/*
 * Triggers Sensor Module <-> Device authentication (the Secure Element's
 * HMAC-SHA256 challenge-response) by invoking the TA's AUTHENTICATE_SENSOR
 * command. Call once per boot, after edge_device_init().
 *
 * This only *triggers* the check - the actual verdict, and its enforcement,
 * live inside the TA (it refuses to protect/forward sensor data until the
 * sensor has authenticated). So a tampered Host that skips this call gains
 * nothing; the data path stays closed. Returns 0 on success.
 */
int edge_authenticate_sensor(void);

int edge_get_sensor_data(char *out, size_t out_size);

/*
 * Invokes the TA's PROCESS_SENSOR_DATA command, which produces the current
 * sensor reading inside the TA (today a mock incrementing counter) and stages
 * it in secure-world session state for the next edge_call_ta(PROTECT...) to
 * seal. Call once per push, before PROTECT. Returns 0 on success.
 */
int edge_process_sensor_data(void);

/*
 * Ensures there is a live attested session with the server, (re)running
 * attestation + handshake if none exists yet or the previous one has expired
 * (device-driven attestation: the device re-attests on expiry rather than the
 * server pulling it). Returns 0 when a valid session is in place.
 */
int edge_ensure_session(void);

/*
 * Drops the server connection and attestation state so the next
 * edge_ensure_session() reconnects and re-attests from scratch. Call after a
 * network/attestation error in the push loop.
 */
void edge_reset_connection(void);

/*
 * Runs the device-side half of remote attestation: connects to the
 * management server's device-facing port, sends "hello", receives
 * "attest_challenge" (nonce + server ephemeral ECDH pubkey), asks our own
 * TA (CMD_GENERATE_ATTESTATION_EVIDENCE) for a fresh ephemeral ECDH pubkey,
 * gets that pubkey quoted by the fTPM over the transcript hash, sends
 * "attest_response", and waits for "attest_result". Leaves the TCP
 * connection open (reused by edge_handshake and
 * edge_send_sensor_data_to_server) and the nonce/server pubkey cached for
 * edge_handshake(). Returns 0 only if attest_result.ok == true.
 */
int edge_attest_to_server(void);

/*
 * Must be called only after edge_attest_to_server() returns 0. Calls our
 * TA's CMD_HANDSHAKE_COMPLETE with the cached server pubkey + nonce so the
 * TA derives and stores the AES-256 session key used by
 * CMD_PROTECT_SENSOR_DATA.
 */
int edge_handshake(void);

/*
 * Sends `protected_data` (a nul-terminated string - see edge_call_ta's
 * PROTECT_SENSOR_DATA output convention below) to the server as a "data"
 * message over the connection opened by edge_attest_to_server().
 */
int edge_send_sensor_data_to_server(const char *protected_data,
				    size_t protected_data_size);

/*
 * Generic wrapper around TEEC_InvokeCommand for our TA.
 *
 * For TA_CONFIDENTIAL_IOT_CMD_PROTECT_SENSOR_DATA specifically: `input` is
 * the plaintext sensor data; `output` receives base64(nonce(12) ||
 * ciphertext || tag(16)), nul-terminated, matching the management server's
 * crypto.aead_decrypt() input convention once split by the caller. This
 * base64-string convention (rather than raw bytes) is deliberate so
 * `strlen(output)` stays a valid length for callers, matching main.c's
 * existing usage.
 */
int edge_call_ta(uint32_t cmd_id, const char *input, size_t input_size,
		 char *output, size_t output_size);

#endif /* EDGE_DEVICE_H */
