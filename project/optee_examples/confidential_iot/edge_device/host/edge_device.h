/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef EDGE_DEVICE_H
#define EDGE_DEVICE_H

#include <stddef.h>
#include <stdint.h>

int edge_get_sensor_data(char *out, size_t out_size);
int edge_attest_to_server(void);
int edge_handshake(void);
int edge_send_sensor_data_to_server(const char *protected_data,
				    size_t protected_data_size);
int edge_call_ta(uint32_t cmd_id, const char *input, size_t input_size,
		 char *output, size_t output_size);

#endif /* EDGE_DEVICE_H */
