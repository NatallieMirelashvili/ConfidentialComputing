/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SERVER_H
#define SERVER_H

#include <stddef.h>

int server_get_sensor_data(char *out, size_t out_size);
int server_verify_attestation(const char *report, size_t report_size);
int server_handshake(void);
int server_receive_sensor_data(const char *protected_data,
			       size_t protected_data_size);

#endif /* SERVER_H */
