/* protocol.c - Module M2: Application protocol and message framing
 * Owner   : Ishita
 *
 * TCP is a byte stream, not a sequence of messages. This file solves that:
 *   - send_all / recv_all : keep calling send()/recv() until ALL bytes are transferred
 *   - send_blob / recv_blob : "2-byte length + data" framing used during the handshake
 *   - msg_name / session_init : message type names and session object set-up
 * The encrypted packet format itself lives in secure_channel.c (module M4).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include "common.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

const char *msg_name(int t)
{
    static const char *n[] = {"?", "REQ", "GRANT", "WAIT", "DENY", "REL", "STATUS", "HB", "ERR", "HELLO"};
    return (t >= 1 && t <= 9) ? n[t] : "?";
}

void session_init(session_t *s, int fd, int secure)
{
    memset(s, 0, sizeof *s);
    s->fd = fd;
    s->secure = secure;
    pthread_mutex_init(&s->send_lock, NULL);
}

int send_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* returns 1 = got n bytes, 0 = peer closed, -1 = error / timeout */
int recv_all(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = recv(fd, p, n, 0);
        if (r == 0) return 0;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 1;
}

int send_blob(int fd, const uint8_t *data, size_t n)
{
    uint8_t h[2] = { (uint8_t)(n >> 8), (uint8_t)n };
    if (send_all(fd, h, 2) < 0) return -1;
    return send_all(fd, data, n);
}

int recv_blob(int fd, uint8_t *data, size_t cap, size_t *n)
{
    uint8_t h[2];
    if (recv_all(fd, h, 2) <= 0) return -1;
    size_t len = ((size_t)h[0] << 8) | h[1];
    if (len > cap) return -1;                         /* never trust a length field from the network */
    if (len && recv_all(fd, data, len) <= 0) return -1;
    *n = len;
    return 0;
}
