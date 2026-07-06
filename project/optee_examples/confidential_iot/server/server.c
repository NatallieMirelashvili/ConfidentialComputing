/* SPDX-License-Identifier: BSD-2-Clause */
#include "server.h"

int server_get_sensor_data(char *out, size_t out_size)
{
	return 0;
}

int server_verify_attestation(const char *report, size_t report_size)
{
	return 0;
}

int server_handshake(void)
{
	return 0;
}

int server_receive_sensor_data(const char *protected_data,
			       size_t protected_data_size)
{
	return 0;
}
