#include "edge_device.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/base64.h>

#include <confidential_iot_ta.h>

/* Seconds between pushes; override with CIOT_PUSH_INTERVAL. */
#define CIOT_PUSH_INTERVAL_DEFAULT 3

/*
 * One-time pairing mode: `optee_example_confidential_iot_edge
 * --provision-sensor-secret` tells the TA to pull the Sensor Module's
 * pre-shared secret over the secure UART and seal it, then exits.
 *
 * It takes no argument, and that is the point: the secret is burned into the
 * Sensor Module and travels a path this process cannot address, so nothing
 * here - not argv, not this process's memory - ever holds the plaintext.
 * Idempotent, so re-running it on a paired device is a harmless no-op.
 *
 * Lives on this same binary (rather than a separate provisioning tool) so it
 * reuses edge_device_init()'s TEEC session, matching how provision-device.sh
 * drives one binary for AK provisioning.
 */
static int provision_sensor_secret_mode(void)
{
	int ret = 1;

	if (edge_device_init() != 0) {
		fprintf(stderr, "edge_device: init failed\n");
		return 1;
	}

	if (edge_provision_sensor_secret() == 0) {
		printf("edge_device: sensor secret provisioned\n");
		ret = 0;
	} else {
		fprintf(stderr, "edge_device: sensor secret provisioning failed\n");
	}

	edge_device_shutdown();
	return ret;
}

/*
 * One-time provisioning mode: `optee_example_confidential_iot_edge
 * --provision-ta-identity` mints (first call) or re-exports (later calls) this
 * TA's sealed identity public key and prints it base64-encoded to stdout.
 *
 * stdout carries the key AND NOTHING ELSE, because scripts/provision-device.sh
 * captures it with $(...) to build the enrollment record; every human-facing
 * message goes to stderr. Takes no argument - the device_id is read from
 * /etc/confidential_iot/device.conf (see load_config in edge_device.c), which
 * guarantees the identity the TA seals is byte-identical to the one the server
 * looks the key up by.
 */
static int provision_ta_identity_mode(void)
{
	uint8_t pub[TA_CONFIDENTIAL_IOT_ECDH_PUBKEY_SIZE];
	char b64[128];
	size_t olen;
	int ret = 1;

	if (edge_device_init() != 0) {
		fprintf(stderr, "edge_device: init failed\n");
		return 1;
	}

	if (edge_provision_ta_identity(pub) != 0) {
		fprintf(stderr,
			"edge_device: TA identity provisioning failed.\n"
			"             If this device was previously provisioned under a\n"
			"             DIFFERENT device_id, its sealed TA identity is bound to\n"
			"             that id - wipe the device's secure storage to rebind.\n");
		goto out;
	}

	if (mbedtls_base64_encode((unsigned char *)b64, sizeof(b64), &olen,
				   pub, sizeof(pub)) != 0) {
		fprintf(stderr, "edge_device: base64 encoding failed\n");
		goto out;
	}

	printf("%s\n", b64);
	ret = 0;

out:
	edge_device_shutdown();
	return ret;
}

int main(int argc, char *argv[])
{
	/* base64(nonce(12) || ciphertext || tag(16)) needs ~4/3 expansion -
	 * sized with headroom. The reading is produced inside the TA now, so
	 * the Host passes no input to READ_AND_PROTECT at all. */
	char protected_data[512] = { 0 };
	unsigned interval = CIOT_PUSH_INTERVAL_DEFAULT;
	const char *env;
	int ret = 1;

	if (argc == 2 && strcmp(argv[1], "--provision-sensor-secret") == 0)
		return provision_sensor_secret_mode();

	if (argc == 2 && strcmp(argv[1], "--provision-ta-identity") == 0)
		return provision_ta_identity_mode();

	if (edge_device_init() != 0) {
		fprintf(stderr, "edge_device: init failed\n");
		return 1;
	}

	/* Make sure the TA holds the sensor's pre-shared secret before trying to
	 * authenticate with it. On an already-paired device this is a storage
	 * probe inside the TA and puts nothing on the link; on a fresh one (or
	 * after a storage wipe) it pulls the secret from the Sensor Module.
	 * Doing it here rather than relying on the launch script is what
	 * guarantees the pull always precedes the challenge below - the Sensor
	 * Module stops serving the secret once a challenge has succeeded.
	 * Not fatal: the call below reports the same condition more clearly. */
	if (edge_provision_sensor_secret() != 0)
		fprintf(stderr,
			"edge_device: sensor pairing failed; authentication will likely fail\n");

	/* Authenticate the attached sensor to this device, once per boot,
	 * before any sensor data will be handled. The TA enforces this as a
	 * precondition for protecting/forwarding data, so it is not optional
	 * even though the Host is what triggers it. */
	if (edge_authenticate_sensor() != 0) {
		fprintf(stderr, "edge_device: sensor authentication failed\n");
		goto out;
	}

	env = getenv("CIOT_PUSH_INTERVAL");
	if (env) {
		int v = atoi(env);

		if (v > 0)
			interval = (unsigned)v;
	}

	printf("edge_device: starting push loop (interval=%us)\n", interval);

	/*
	 * Run as a daemon: keep a live attested session (re-attesting only when
	 * none exists or the previous one expired - device-driven, not per push)
	 * and push one AES-GCM-sealed reading each interval. The server buffers
	 * these; the UI's "collect" returns them. Runs until the process is
	 * killed (e.g. on reboot).
	 */
	for (;;) {
		if (edge_ensure_session() != 0) {
			fprintf(stderr,
				"edge_device: attestation/session failed; retrying\n");
			edge_reset_connection();
			sleep(interval);
			continue;
		}

		/* TA reads the sensor and seals it with AES-256-GCM, entirely
		 * in secure world, in one call. */
		if (edge_call_ta(protected_data, sizeof(protected_data)) != 0) {
			fprintf(stderr, "edge_device: sensor read/protect failed\n");
			sleep(interval);
			continue;
		}

		if (edge_send_sensor_data_to_server(protected_data,
						    strlen(protected_data)) != 0) {
			fprintf(stderr,
				"edge_device: server send failed; will re-attest\n");
			edge_reset_connection();
			sleep(interval);
			continue;
		}

		printf("edge_device: pushed sensor reading\n");
		sleep(interval);
	}

	ret = 0;   /* not reached - loop exits only via signal */

out:
	edge_device_shutdown();
	return ret;
}
