/*
 * Sensor Module companion process (confidential_iot project).
 *
 * Stands in for a physically separate sensor board wired to the Edge
 * Device by a serial cable. Runs OUTSIDE the QEMU guest, on the physical/
 * dev host, and connects as a plain TCP client to the loopback port QEMU
 * wires to the secure-only UART2 chardev backend (see
 * project/patches/virt-uart2.patch and scripts/sync-project.sh) - from this
 * process's point of view that TCP connection *is* the cable. Speaks the
 * length-prefixed framing documented in sensor_link_proto.h and
 * project/optee_os_ext/lib/libutee/include/pta_sensor_link.h.
 *
 * Owns the sensor<->device pre-shared secret, loaded from a local file written
 * by scripts/pair-sensor.sh - never compiled in, so one built image can be
 * paired with any device without a rebuild. That file stands in for a key
 * burned into the sensor's secure element at manufacture, and this process is
 * its authoritative source: the device has no copy until it asks for one over
 * the secure link, and this daemon answers at most once per power-on.
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "sensor_link_proto.h"

/* Synthetic reading cadence. Doesn't need to match the edge device's
 * CIOT_PUSH_INTERVAL exactly - the sensor_link PTA blocks a READ call until
 * a reading frame arrives, so pushing somewhat faster just means a fresh
 * reading is normally already waiting. */
#define READING_INTERVAL_SEC	2
#define ACCEPT_POLL_SEC		1

static uint8_t g_secret[SENSOR_LINK_SECRET_SIZE];

/*
 * One-shot latch for handing the burned-in secret to the device. PROCESS-global
 * on purpose - deliberately NOT a serve() local like `authenticated` below.
 *
 * The device pulls the secret over the link exactly once, on a generation that
 * has none sealed yet (see ta_provision_sensor_secret). A per-connection flag
 * would reset the instant QEMU's connection drops, so any local process that
 * then dialled this port could ask for the secret and be given it - which is
 * precisely the exposure this whole mechanism exists to remove.
 *
 * Equally deliberately NOT persisted to a file: scripts/run-project.sh wipes
 * the device's storage on a rebuild (build-stamp change) while keeping the
 * sensor's .sensor-secret, so the TA must be able to re-pull afterwards.
 * Restarting this daemon is what reopens the latch - and that same script
 * restarts it on every launch, before QEMU, so the latch's lifetime lines up
 * with the device's re-pull need without any coordination.
 */
static bool g_secret_served;
/*
 * Second gate. The secret may only be served during the FIRST connection this
 * process accepts, which is always the device's: this daemon has to be
 * listening before QEMU starts, and listen(fd, 1) plus a single-threaded accept
 * loop means nothing can get in front of it.
 *
 * Without this, a daemon whose secret was never requested - the normal case,
 * since a device whose secure storage survived never asks - would leave the
 * window open for its entire lifetime.
 */
static bool g_secret_window_closed;

static int load_secret(const char *path)
{
	FILE *f;
	size_t n;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "sensor_daemon: cannot open secret file %s\n", path);
		return -1;
	}
	n = fread(g_secret, 1, sizeof(g_secret), f);
	fclose(f);
	if (n != sizeof(g_secret)) {
		fprintf(stderr, "sensor_daemon: %s must be exactly %zu bytes\n",
			path, sizeof(g_secret));
		return -1;
	}
	return 0;
}

static int listen_on(uint16_t port)
{
	int fd;
	int one = 1;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(fd, 1) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Blocking read of exactly len bytes. Returns 0 on success, -1 on error/EOF. */
static int read_full(int fd, uint8_t *buf, size_t len)
{
	size_t got = 0;
	ssize_t n;

	while (got < len) {
		n = read(fd, buf + got, len - got);
		if (n <= 0)
			return -1;
		got += (size_t)n;
	}
	return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;
	ssize_t n;

	while (sent < len) {
		n = write(fd, buf + sent, len - sent);
		if (n <= 0)
			return -1;
		sent += (size_t)n;
	}
	return 0;
}

static int write_frame(int fd, uint8_t type, const uint8_t *payload,
			uint16_t len)
{
	uint8_t hdr[SENSOR_LINK_FRAME_HDR_SIZE];

	hdr[0] = type;
	hdr[1] = (uint8_t)(len >> 8);
	hdr[2] = (uint8_t)(len & 0xff);
	if (write_full(fd, hdr, sizeof(hdr)) != 0)
		return -1;
	if (len && write_full(fd, payload, len) != 0)
		return -1;
	return 0;
}

/* Handles one CHALLENGE frame already announced by its header: reads the
 * challenge payload, computes HMAC-SHA256(secret, challenge), replies. */
static int handle_challenge(int fd, uint16_t len)
{
	uint8_t challenge[SENSOR_LINK_CHALLENGE_SIZE];
	uint8_t response[SENSOR_LINK_HMAC_SIZE];
	unsigned int response_len = sizeof(response);

	if (len != sizeof(challenge)) {
		fprintf(stderr, "sensor_daemon: bad challenge length %u\n", len);
		return -1;
	}
	if (read_full(fd, challenge, sizeof(challenge)) != 0)
		return -1;

	if (!HMAC(EVP_sha256(), g_secret, sizeof(g_secret), challenge,
		  sizeof(challenge), response, &response_len) ||
	    response_len != sizeof(response))
		return -1;

	if (write_frame(fd, SENSOR_LINK_FRAME_CHALLENGE_RESPONSE, response,
			 sizeof(response)) != 0)
		return -1;

	printf("sensor_daemon: answered challenge\n");
	return 0;
}

/*
 * Handles one SECRET_REQUEST frame already announced by its header: hands the
 * burned-in secret to the device, at most once for this process.
 *
 * This is what replaces pushing the secret in from the Normal World as a
 * base64 argument. The device pulls it over the secure UART instead, so the
 * plaintext never touches the untrusted guest. The latch keeps that from
 * becoming a standing offer to anyone who can reach this socket.
 */
static int handle_secret_request(int fd, uint16_t len, bool authenticated)
{
	if (len != 0) {
		fprintf(stderr,
			"sensor_daemon: SECRET_REQUEST takes no payload (got %u)\n",
			len);
		return -1; /* stream is desynced - drop the connection */
	}

	if (g_secret_served || g_secret_window_closed || authenticated) {
		fprintf(stderr,
			"sensor_daemon: refusing SECRET_REQUEST (served=%d window_closed=%d authenticated=%d)\n",
			(int)g_secret_served, (int)g_secret_window_closed,
			(int)authenticated);
		/* Empty SECRET frame is the documented refusal. Answering beats
		 * staying silent: the device fails immediately with a specific
		 * error instead of stalling for its read timeout, and the
		 * stream stays framed for the traffic that follows. */
		return write_frame(fd, SENSOR_LINK_FRAME_SECRET, NULL, 0);
	}

	if (write_frame(fd, SENSOR_LINK_FRAME_SECRET, g_secret,
			 (uint16_t)sizeof(g_secret)) != 0)
		return -1;

	g_secret_served = true;
	printf("sensor_daemon: served the pre-shared secret once; latch closed\n");
	return 0;
}

/* Synthetic reading: a slowly varying "temperature" in whole degrees C,
 * independent of the TA's own (removed) mock counter - this process owns
 * its own value generator, demonstrating a genuinely separate component. */
static int send_reading(int fd, uint32_t tick)
{
	uint8_t payload[SENSOR_LINK_READING_VALUE_SIZE + 1 +
			SENSOR_LINK_READING_UNIT_MAX];
	int32_t value = 20 + (int32_t)(tick % 10);
	const char unit[] = "C";
	uint8_t unit_len = (uint8_t)(sizeof(unit) - 1);

	payload[0] = (uint8_t)((uint32_t)value >> 24);
	payload[1] = (uint8_t)((uint32_t)value >> 16);
	payload[2] = (uint8_t)((uint32_t)value >> 8);
	payload[3] = (uint8_t)((uint32_t)value);
	payload[4] = unit_len;
	memcpy(payload + 5, unit, unit_len);

	return write_frame(fd, SENSOR_LINK_FRAME_READING, payload,
			    (uint16_t)(5 + unit_len));
}

static void serve(int conn_fd)
{
	uint32_t tick = 0;
	time_t last_reading = 0;
	/*
	 * Gates the periodic READING push. The connection is accepted right
	 * at QEMU boot (see scripts/run-project.sh - the daemon must be
	 * listening before QEMU starts), but the TA doesn't attempt its
	 * first read (the CHALLENGE round trip inside ta_authenticate_sensor)
	 * until well after login/provisioning, on the order of a minute
	 * later. If readings were pushed on a timer the whole time,
	 * unconsumed frames would pile up in the PL011's small RX FIFO and
	 * overflow it long before the TA ever reads, corrupting the byte
	 * stream so badly that even the CHALLENGE_RESPONSE frame arrives
	 * garbled. So: no reading is ever sent before the first successful
	 * challenge-response, and the interval timer only starts counting
	 * from that point - by then the TA is actively draining the link
	 * roughly once per push interval, so no backlog can build up.
	 */
	bool authenticated = false;

	printf("sensor_daemon: device connected\n");

	for (;;) {
		fd_set rfds;
		struct timeval tv;
		int rc;
		time_t now;

		FD_ZERO(&rfds);
		FD_SET(conn_fd, &rfds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		rc = select(conn_fd + 1, &rfds, NULL, NULL, &tv);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (rc > 0 && FD_ISSET(conn_fd, &rfds)) {
			uint8_t hdr[SENSOR_LINK_FRAME_HDR_SIZE];
			uint16_t len;

			if (read_full(conn_fd, hdr, sizeof(hdr)) != 0)
				break; /* device closed the connection */
			len = (uint16_t)((hdr[1] << 8) | hdr[2]);

			if (hdr[0] == SENSOR_LINK_FRAME_CHALLENGE) {
				if (handle_challenge(conn_fd, len) != 0)
					break;
				if (!authenticated) {
					authenticated = true;
					last_reading = time(NULL);
				}
			} else if (hdr[0] == SENSOR_LINK_FRAME_SECRET_REQUEST) {
				if (handle_secret_request(conn_fd, len,
							  authenticated) != 0)
					break;
			} else {
				fprintf(stderr,
					"sensor_daemon: unexpected frame type 0x%02x\n",
					hdr[0]);
				break;
			}
		}

		if (!authenticated)
			continue;

		now = time(NULL);
		if (now - last_reading >= READING_INTERVAL_SEC) {
			if (send_reading(conn_fd, tick++) != 0)
				break;
			last_reading = now;
		}
	}

	printf("sensor_daemon: device disconnected\n");
}

int main(int argc, char *argv[])
{
	uint16_t port = 0;
	const char *secret_path = NULL;
	int listen_fd;
	int i;

	/* This runs as a backgrounded daemon with stdout/stderr redirected to a
	 * log file, not a terminal - glibc fully-buffers non-tty stdout by
	 * default, so without this every printf/fprintf would sit unflushed
	 * for as long as the process runs, making the log useless for live
	 * debugging. */
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
			port = (uint16_t)atoi(argv[++i]);
		else if (strcmp(argv[i], "--secret") == 0 && i + 1 < argc)
			secret_path = argv[++i];
	}
	if (!port || !secret_path) {
		fprintf(stderr,
			"usage: %s --port <port> --secret <path>\n", argv[0]);
		return 1;
	}

	if (load_secret(secret_path) != 0)
		return 1;

	listen_fd = listen_on(port);
	if (listen_fd < 0) {
		fprintf(stderr, "sensor_daemon: cannot listen on port %u\n", port);
		return 1;
	}
	printf("sensor_daemon: listening on 127.0.0.1:%u\n", port);

	for (;;) {
		int conn_fd = accept(listen_fd, NULL, NULL);

		if (conn_fd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		serve(conn_fd);
		close(conn_fd);
		/* The first connection is over, so no later peer may ask for the
		 * secret - whether or not this one did. See the comment on
		 * g_secret_window_closed. */
		g_secret_window_closed = true;
	}

	close(listen_fd);
	return 0;
}
