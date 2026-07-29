#ifndef EDGE_DEVICE_H
#define EDGE_DEVICE_H

#include <stddef.h>
#include <stdint.h>

#include <confidential_iot_ta.h>

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
 * real HMAC-SHA256 challenge-response, run entirely TA<->sensor_link PTA -
 * see trusted_app.c) by invoking the TA's AUTHENTICATE_SENSOR command. Call
 * once per boot, after edge_device_init().
 *
 * This only *triggers* the check - the actual verdict, and its enforcement,
 * live inside the TA (it refuses to protect/forward sensor data until the
 * sensor has authenticated). So a tampered Host that skips this call gains
 * nothing; the data path stays closed. Returns 0 on success.
 */
int edge_authenticate_sensor(void);

/*
 * One-time provisioning trigger for the Sensor Module's pre-shared secret -
 * see scripts/pair-sensor.sh, which drives this. `secret` must be exactly
 * TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE bytes. Idempotent: re-provisioning
 * an already-provisioned device is a no-op success (see
 * ta_provision_sensor_secret in trusted_app.c).
 */
int edge_provision_sensor_secret(const uint8_t secret[TA_CONFIDENTIAL_IOT_SENSOR_SECRET_SIZE]);

/*
 * One-time provisioning trigger for the TA's OWN identity keypair - see
 * scripts/provision-device.sh, which drives this and puts the returned public
 * key in the enrollment record the server pins alongside the AK. Writes the
 * 65-byte uncompressed SEC1 point (0x04 || X || Y) to `out_pub`.
 *
 * The private half is generated inside the TA and never leaves the TEE; that is
 * the property root cannot defeat, and it is what proves to the server that the
 * genuine TA - not a bypassed Normal World - produced a session's ECDH key.
 *
 * Idempotent: the first call mints and seals the key, later calls re-export the
 * same point, so this is safe to run on every boot. The device_id is taken from
 * device.conf (or CIOT_DEVICE_ID), not from an argument, and is sealed with the
 * key. Re-provisioning under a DIFFERENT device_id fails; rebinding requires
 * wiping the device's secure storage. Returns 0 on success.
 */
int edge_provision_ta_identity(uint8_t out_pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE]);

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
 * "attest_challenge" (nonce + server ephemeral ECDH pubkey + the server's
 * identity pubkey), asks our own TA (CMD_GENERATE_ATTESTATION_EVIDENCE) for a
 * fresh ephemeral ECDH pubkey plus that TA's identity signature over the
 * session, gets the pubkey quoted by the fTPM over the
 * transcript hash, sends "attest_response" (quote + signature + pcr_values +
 * ta_sig), and waits for "attest_result"
 * (which, on success, also carries the server's per-session identity
 * signature). Leaves the TCP connection open (reused by edge_handshake and
 * edge_send_sensor_data_to_server) and the nonce / server ECDH pubkey /
 * server identity pubkey / server signature cached for edge_handshake().
 * Returns 0 only if attest_result.ok == true.
 */
int edge_attest_to_server(void);

/*
 * Must be called only after edge_attest_to_server() returns 0. Calls our TA's
 * CMD_HANDSHAKE_COMPLETE with the cached server ECDH pubkey + nonce, plus the
 * cached server identity pubkey + signature. The TA first authenticates the
 * server (verifies the signature and, on first use, pins the identity key -
 * TOFU) and only then derives and stores the AES-256 session key used by
 * CMD_READ_AND_PROTECT. Returns non-zero (and no session key is derived) if
 * that server-identity check fails.
 */
int edge_handshake(void);

/*
 * Sends `protected_data` (a nul-terminated string - see edge_call_ta's
 * output convention below) to the server as a "data" message over the
 * connection opened by edge_attest_to_server().
 */
int edge_send_sensor_data_to_server(const char *protected_data,
				    size_t protected_data_size);

/*
 * Invokes the TA's CMD_READ_AND_PROTECT: no plaintext input at all (the
 * reading is pulled from the sensor_link PTA entirely inside Secure World -
 * see ta_read_and_protect in trusted_app.c). `output` receives
 * base64(nonce(12) || ciphertext || tag(16)), nul-terminated, matching the
 * management server's crypto.aead_decrypt() input convention once split by
 * the caller. This base64-string convention (rather than raw bytes) is
 * deliberate so `strlen(output)` stays a valid length for callers, matching
 * main.c's existing usage. Call once per push. Returns 0 on success.
 */
int edge_call_ta(char *output, size_t output_size);

#endif /* EDGE_DEVICE_H */
