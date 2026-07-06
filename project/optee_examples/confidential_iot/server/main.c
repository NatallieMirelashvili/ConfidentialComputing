/* SPDX-License-Identifier: BSD-2-Clause */
#include "server.h"

#include <stdio.h>
#include <string.h>

#include <attestation.h>

int main(void)
{
	char request[128] = { 0 };
	char report[128] = { 0 };
	const char protected_data[] = "protected:measurement=stub";

	if (server_get_sensor_data(request, sizeof(request)) != 0) {
		fprintf(stderr, "server: failed to create sensor request\n");
		return 1;
	}

	if (create_attestation_report(report, sizeof(report)) != 0) {
		fprintf(stderr, "server: failed to create stub report\n");
		return 1;
	}

	if (server_verify_attestation(report, strlen(report)) != 0) {
		fprintf(stderr, "server: attestation rejected\n");
		return 1;
	}

	if (server_handshake() != 0) {
		fprintf(stderr, "server: handshake failed\n");
		return 1;
	}

	if (server_receive_sensor_data(protected_data,
				       strlen(protected_data)) != 0) {
		fprintf(stderr, "server: failed to receive data\n");
		return 1;
	}

	printf("server: completed stub flow\n");
	return 0;
}
