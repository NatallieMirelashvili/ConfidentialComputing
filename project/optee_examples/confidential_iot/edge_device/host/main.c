#include "edge_device.h"

#include <stdio.h>
#include <string.h>

#include <confidential_iot_ta.h>

int main(void)
{
	char sensor_data[128] = { 0 };
	char protected_data[160] = { 0 };

	if (edge_attest_to_server() != 0) {
		fprintf(stderr, "edge_device: attestation failed\n");
		return 1;
	}

	if (edge_handshake() != 0) {
		fprintf(stderr, "edge_device: handshake failed\n");
		return 1;
	}

	if (edge_get_sensor_data(sensor_data, sizeof(sensor_data)) != 0) {
		fprintf(stderr, "edge_device: sensor read failed\n");
		return 1;
	}

	if (edge_call_ta(TA_CONFIDENTIAL_IOT_CMD_PROTECT_SENSOR_DATA,
			 sensor_data, strlen(sensor_data), protected_data,
			 sizeof(protected_data)) != 0) {
		fprintf(stderr, "edge_device: TA call failed\n");
		return 1;
	}

	if (edge_send_sensor_data_to_server(protected_data,
					    strlen(protected_data)) != 0) {
		fprintf(stderr, "edge_device: server send failed\n");
		return 1;
	}

	printf("edge_device: completed stub flow\n");
	return 0;
}
