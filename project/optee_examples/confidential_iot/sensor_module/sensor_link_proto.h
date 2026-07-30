#ifndef SENSOR_LINK_PROTO_H
#define SENSOR_LINK_PROTO_H

/*
 * Wire protocol for the sensor_daemon <-> sensor_link PTA link (see
 * project/optee_os_ext/lib/libutee/include/pta_sensor_link.h for the
 * authoritative definition on the TA/PTA side - duplicated here because
 * this daemon is a plain host binary outside the OP-TEE SDK and can't
 * include that header directly). Keep these in sync by hand.
 *
 * Framing: [1B msg_type][2B length BE][payload].
 */
#define SENSOR_LINK_FRAME_CHALLENGE		0x01 /* device -> sensor */
#define SENSOR_LINK_FRAME_CHALLENGE_RESPONSE	0x02 /* sensor -> device */
#define SENSOR_LINK_FRAME_READING		0x03 /* sensor -> device */
/*
 * Pre-shared key delivery, used once in a device's life. SECRET_REQUEST
 * carries an empty payload; this daemon answers with SECRET, whose payload is
 * either SENSOR_LINK_SECRET_SIZE bytes (the key) or ZERO bytes, meaning
 * "refused - already served once". The refusal is an explicit empty frame
 * rather than silence so the device fails fast instead of waiting out its read
 * timeout, and so the stream stays framed for the traffic that follows.
 */
#define SENSOR_LINK_FRAME_SECRET_REQUEST	0x04 /* device -> sensor */
#define SENSOR_LINK_FRAME_SECRET		0x05 /* sensor -> device */
#define SENSOR_LINK_FRAME_HDR_SIZE		3

#define SENSOR_LINK_CHALLENGE_SIZE	32
#define SENSOR_LINK_HMAC_SIZE		32
#define SENSOR_LINK_SECRET_SIZE	32

/* READING payload: [4B big-endian int32 value][1B unit_len][unit_len ASCII]. */
#define SENSOR_LINK_READING_VALUE_SIZE	4
#define SENSOR_LINK_READING_UNIT_MAX	32

#endif /* SENSOR_LINK_PROTO_H */
