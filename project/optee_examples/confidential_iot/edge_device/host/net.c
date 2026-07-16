#include "net.h"

#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

int net_connect(const char *host, uint16_t port, struct net_conn *conn)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *rp;
	char port_str[8];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

	if (getaddrinfo(host, port_str, &hints, &res) != 0)
		return -1;

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}

	freeaddrinfo(res);

	if (fd < 0)
		return -1;

	conn->fd = fd;
	return 0;
}

int net_send_line(struct net_conn *conn, const char *line)
{
	size_t len = strlen(line);
	size_t sent = 0;

	while (sent < len) {
		ssize_t n = send(conn->fd, line + sent, len - sent, 0);

		if (n <= 0)
			return -1;
		sent += (size_t)n;
	}

	if (send(conn->fd, "\n", 1, 0) != 1)
		return -1;

	return 0;
}

int net_recv_line(struct net_conn *conn, char *buf, size_t buf_cap)
{
	size_t i = 0;

	if (buf_cap == 0)
		return -1;

	while (i + 1 < buf_cap) {
		char c;
		ssize_t n = recv(conn->fd, &c, 1, 0);

		if (n == 0)
			return -1; /* peer closed before a full line arrived */
		if (n < 0)
			return -1;
		if (c == '\n') {
			buf[i] = '\0';
			return (int)i;
		}
		buf[i++] = c;
	}

	return -1; /* line too long for buf_cap */
}

void net_close(struct net_conn *conn)
{
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}
}
