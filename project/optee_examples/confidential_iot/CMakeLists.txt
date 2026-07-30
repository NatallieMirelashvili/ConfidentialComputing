project(optee_example_confidential_iot C)

add_executable(optee_example_confidential_iot_edge
	edge_device/host/main.c
	edge_device/host/edge_device.c
	edge_device/host/net.c
	attestation/attestation.c)

target_include_directories(optee_example_confidential_iot_edge
	PRIVATE edge_device/host
	PRIVATE attestation
	PRIVATE edge_device/ta/include)

# mbedcrypto (mbedTLS's crypto-only lib: base64) and cJSON come from the
# Buildroot packages enabled via project/buildroot/packages.conf; the
# Buildroot cmake toolchain file points CMAKE_SYSROOT at the staging tree
# where their headers and libraries are installed.
target_link_libraries(optee_example_confidential_iot_edge
	PRIVATE teec mbedcrypto cjson)

install(TARGETS optee_example_confidential_iot_edge
	DESTINATION ${CMAKE_INSTALL_BINDIR})

# Device-side TA security tests: a deliberately hostile Host CA. It does NOT link
# edge_device.c - it is simulating a compromised Normal World, so it drives the TA
# directly (see tests/host/ta_tests.c). It needs the headers of the two TA test
# fixtures, which live in their own top-level example dirs because the Buildroot
# package builds exactly one TA per dir (*/ta/Makefile).
add_executable(optee_example_confidential_iot_tests
	tests/host/ta_tests.c
	tests/host/crypto_check.c)

target_include_directories(optee_example_confidential_iot_tests
	PRIVATE tests/host
	PRIVATE edge_device/ta/include
	PRIVATE ../ciot_probe_ta/ta/include
	PRIVATE ../ciot_rogue_ta/ta/include)

# mbedcrypto here is the verifying side of the attestation protocol (SHA-256,
# ECDSA-P256, P-256 keygen) - the tests recompute what the management server
# checks, so they can prove the device never produces forgeable evidence without
# a server or a network in the loop.
target_link_libraries(optee_example_confidential_iot_tests
	PRIVATE teec mbedcrypto)

install(TARGETS optee_example_confidential_iot_tests
	DESTINATION ${CMAKE_INSTALL_BINDIR})

install(PROGRAMS scripts/provision-device.sh
	DESTINATION ${CMAKE_INSTALL_BINDIR})

# Must run before /etc/init.d/S30optee (tee-supplicant) so OP-TEE's REE-FS
# secure storage mounts onto the persistent disk first. See
# scripts/S29tee-storage.
install(PROGRAMS scripts/S29tee-storage
	DESTINATION /etc/init.d)

# sensor_module/sensor_daemon.c is intentionally NOT built here: it models a
# physically separate Sensor Module board and runs OUTSIDE this QEMU guest,
# on the physical/dev host - see sensor_module/Makefile (a native, non-cross
# build) and scripts/run-project.sh.
