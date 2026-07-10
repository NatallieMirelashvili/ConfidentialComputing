#ifndef CONFIDENTIAL_IOT_NET_H
#define CONFIDENTIAL_IOT_NET_H

#include <stddef.h>
#include <stdint.h>

struct net_conn {
	int fd;
};

/*
 * Connects to host:port over TCP. Returns 0 on success, -1 on failure.
 * This is the device-facing link the management server's NetworkDeviceLink
 * listens on (see CC_Server/server/device_link/network.py).
 */
int net_connect(const char *host, uint16_t port, struct net_conn *conn);

/* Sends one newline-delimited JSON message (a trailing '\n' is appended). */
int net_send_line(struct net_conn *conn, const char *line);

/*
 * Reads one newline-delimited line into buf (nul-terminated, newline
 * stripped). Returns the line length on success, -1 on error/EOF/overflow.
 */
int net_recv_line(struct net_conn *conn, char *buf, size_t buf_cap);

void net_close(struct net_conn *conn);

#endif /* CONFIDENTIAL_IOT_NET_H */
