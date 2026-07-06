/* SPDX-License-Identifier: BSD-2-Clause */
#include "edge_device.h"

int edge_get_sensor_data(char *out, size_t out_size)
{
	return 0;
}

int edge_attest_to_server(void)
{
	return 0;
}

int edge_handshake(void)
{
	return 0;
}

int edge_send_sensor_data_to_server(const char *protected_data,
				    size_t protected_data_size)
{
	return 0;
}

int edge_call_ta(uint32_t cmd_id, const char *input, size_t input_size,
		 char *output, size_t output_size)
{
	return 0;
}
