/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * confidential_iot project: sensor_link PTA.
 *
 * Owns the secure-only UART2 (see project/patches/virt-uart2.patch and
 * scripts/sync-project.sh) that connects Secure World directly to the
 * external Sensor Module process (sensor_module/sensor_daemon.c), which
 * dials in over the UART2 chardev backend - a virtual serial cable. Normal
 * World has no path to this UART at all (its device-tree node is marked
 * "disabled" for the non-secure world, exactly like OP-TEE's own UART1
 * console), so bytes crossing it never transit a Host-owned buffer.
 *
 * Because this PTA runs inside OP-TEE core itself, the confidential_iot TA
 * reaches it via TEE_OpenTASession()/TEE_InvokeTACommand() - an in-process
 * call that never leaves Secure World (see core/kernel/pseudo_ta.c). Only
 * that TA may open a session here; see sensor_link.c's open_session().
 */
#ifndef __PTA_SENSOR_LINK_H
#define __PTA_SENSOR_LINK_H

#define PTA_SENSOR_LINK_UUID { 0x7d9f6d20, 0x5f11, 0x4d0c, \
		{ 0x9a, 0x17, 0x61, 0xc9, 0xc9, 0x1c, 0x00, 0x02 } }

/*
 * UUID of the sole TA allowed to open a session to this PTA - must match
 * TA_CONFIDENTIAL_IOT_UUID in
 * project/optee_examples/confidential_iot/edge_device/ta/include/confidential_iot_ta.h.
 * Duplicated here (rather than shared via #include) because this PTA lives
 * in a separate build tree (optee_os core) with no include path back into
 * the TA's own project sources.
 */
#define SENSOR_LINK_ALLOWED_CALLER_UUID { 0x7d9f6d20, 0x5f11, 0x4d0c, \
		{ 0x9a, 0x17, 0x61, 0xc9, 0xc9, 0x1c, 0x00, 0x01 } }

/*
 * Wire framing over the UART: [1B msg_type][2B length BE][payload].
 * Shared with sensor_module/sensor_daemon.c's own copy of these constants
 * (a plain host binary outside the OP-TEE SDK, so it can't include this
 * header directly).
 */
#define SENSOR_LINK_FRAME_CHALLENGE		0x01 /* device -> sensor */
#define SENSOR_LINK_FRAME_CHALLENGE_RESPONSE	0x02 /* sensor -> device */
#define SENSOR_LINK_FRAME_READING		0x03 /* sensor -> device */
#define SENSOR_LINK_FRAME_HDR_SIZE		3

#define SENSOR_LINK_CHALLENGE_SIZE	32
#define SENSOR_LINK_HMAC_SIZE		32
#define SENSOR_LINK_READING_MAX	256

/*
 * READING frame payload layout (opaque to this PTA, which only relays raw
 * bytes - interpreted by the TA and produced by sensor_daemon.c). The value
 * is a plain signed 32-bit integer (not a float) deliberately: OP-TEE TAs
 * link a minimal libc, and this avoids depending on floating-point printf
 * support inside the TEE. A fractional reading can still round-trip (e.g.
 * scaled by a fixed factor and labeled via unit), but no component in this
 * pipeline needs to parse/format an IEEE-754 value.
 *   [4B big-endian int32 value][1B unit_len][unit_len ASCII unit]
 */
#define SENSOR_LINK_READING_VALUE_SIZE	4
#define SENSOR_LINK_READING_UNIT_MAX	32

/*
 * PTA_SENSOR_LINK_CMD_CHALLENGE - run one HMAC-SHA256 challenge-response
 * round trip with the external Sensor Module over the secure UART.
 *
 * [in]  memref[0] - SENSOR_LINK_CHALLENGE_SIZE-byte challenge (caller
 *                    generated, e.g. via TEE_GenerateRandom)
 * [out] memref[1] - response buffer, >= SENSOR_LINK_HMAC_SIZE bytes; filled
 *                    with the sensor's HMAC-SHA256(secret, challenge) on
 *                    success
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - response received and copied out
 * TEE_ERROR_BAD_PARAMETERS - bad param shapes/sizes
 * TEE_ERROR_COMMUNICATION - no response within the read timeout (sensor
 *                           daemon absent, dead, or link down)
 */
#define PTA_SENSOR_LINK_CMD_CHALLENGE	0

/*
 * PTA_SENSOR_LINK_CMD_READ - read one framed sensor reading.
 *
 * [out] memref[0] - reading payload buffer, <= SENSOR_LINK_READING_MAX
 *                    bytes; filled with the raw payload of one READING frame
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - reading received and copied out
 * TEE_ERROR_BAD_PARAMETERS - bad param shapes/sizes
 * TEE_ERROR_COMMUNICATION - no reading within the read timeout
 * TEE_ERROR_SHORT_BUFFER - reading larger than the caller's buffer
 */
#define PTA_SENSOR_LINK_CMD_READ	1

#endif /* __PTA_SENSOR_LINK_H */
