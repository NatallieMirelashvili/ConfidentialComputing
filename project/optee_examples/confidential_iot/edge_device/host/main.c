#include "edge_device.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <confidential_iot_ta.h>

/* Seconds between pushes; override with CIOT_PUSH_INTERVAL. */
#define CIOT_PUSH_INTERVAL_DEFAULT 3

int main(void)
{
	/* base64(nonce(12) || ciphertext || tag(16)) needs ~4/3 expansion -
	 * sized with headroom. The plaintext is produced inside the TA now, so
	 * the Host only passes a throwaway input buffer to PROTECT. */
	char protected_data[512] = { 0 };
	char ta_in[1] = { 0 };
	unsigned interval = CIOT_PUSH_INTERVAL_DEFAULT;
	const char *env;
	int ret = 1;

	if (edge_device_init() != 0) {
		fprintf(stderr, "edge_device: init failed\n");
		return 1;
	}

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
	 * killed (e.g. on reboot), which is also when the TA's mock counter
	 * resets.
	 */
	for (;;) {
		if (edge_ensure_session() != 0) {
			fprintf(stderr,
				"edge_device: attestation/session failed; retrying\n");
			edge_reset_connection();
			sleep(interval);
			continue;
		}

		/* TA produces the reading (mock counter) in secure world... */
		if (edge_process_sensor_data() != 0) {
			fprintf(stderr, "edge_device: sensor read failed\n");
			sleep(interval);
			continue;
		}

		/* ...and PROTECT seals it with AES-256-GCM before it leaves. */
		if (edge_call_ta(TA_CONFIDENTIAL_IOT_CMD_PROTECT_SENSOR_DATA,
				 ta_in, sizeof(ta_in), protected_data,
				 sizeof(protected_data)) != 0) {
			fprintf(stderr, "edge_device: protect failed\n");
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
