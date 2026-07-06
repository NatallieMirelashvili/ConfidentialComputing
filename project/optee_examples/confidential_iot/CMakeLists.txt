project(optee_example_confidential_iot C)

add_executable(confidential_iot_server
	server/main.c
	server/server.c
	attestation/attestation.c)

target_include_directories(confidential_iot_server
	PRIVATE server
	PRIVATE attestation)

add_executable(optee_example_confidential_iot_edge
	edge_device/host/main.c
	edge_device/host/edge_device.c
	sensor_module/sensor_module.c
	sensor_module/secure_element.c
	attestation/attestation.c)

target_include_directories(optee_example_confidential_iot_edge
	PRIVATE edge_device/host
	PRIVATE sensor_module
	PRIVATE attestation
	PRIVATE edge_device/ta/include)

target_link_libraries(optee_example_confidential_iot_edge PRIVATE teec)

install(TARGETS confidential_iot_server optee_example_confidential_iot_edge
	DESTINATION ${CMAKE_INSTALL_BINDIR})
