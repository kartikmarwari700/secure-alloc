/* test_protocol.c - unit tests for M2 + M4: framing, encryption, tamper and replay rejection, over a socket pair. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../src/common.h"

static int fails = 0;
static void check(const char *name, int cond) { printf("%s  %s\n", cond ? "PASS" : "FAIL", name); if (!cond) fails++; }

static void make_pair(session_t *a, session_t *b, int secure)
{
    int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    session_init(a, sv[0], secure); session_init(b, sv[1], secure);
    random_bytes(a->key, KEY_LEN); memcpy(b->key, a->key, KEY_LEN);
}

int main(void)
{
    session_t a, b; char text[MAX_PAYLOAD + 1]; int type;

    puts("--- secure session ---");
    make_pair(&a, &b, 1);
    check("send REQ", send_msg(&a, MSG_REQ, "R1 2") == 0);
    check("recv REQ with right text", recv_msg(&b, &type, text, sizeof text) == 1 && type == MSG_REQ && !strcmp(text, "R1 2"));
    check("empty payload works (STATUS)", send_msg(&a, MSG_STATUS, "") == 0 && recv_msg(&b, &type, text, sizeof text) == 1 && text[0] == 0);
    check("reply in the other direction", send_msg(&b, MSG_GRANT, "ok") == 0 && recv_msg(&a, &type, text, sizeof text) == 1 && type == MSG_GRANT);

    send_msg(&a, MSG_REQ, "R2 1");
    check("sequence numbers increase", a.send_seq == 3);
    recv_msg(&b, &type, text, sizeof text);

    puts("--- tamper ---");
    check("tampered packet is rejected (-2)", send_tampered(&a, MSG_REQ, "R3 1") == 0 && recv_msg(&b, &type, text, sizeof text) == -2);
    check("reject kind = TAMPER", b.reject_kind == REJ_TAMPER);
    check("session still works afterwards", send_msg(&a, MSG_REQ, "R3 1") == 0 && recv_msg(&b, &type, text, sizeof text) == 1 && !strcmp(text, "R3 1"));

    puts("--- replay ---");
    check("replayed packet is rejected (-2)", send_replay(&a) == 0 && recv_msg(&b, &type, text, sizeof text) == -2);
    check("reject kind = REPLAY", b.reject_kind == REJ_REPLAY);
    check("normal message accepted after replay attempt", send_msg(&a, MSG_REL, "R3 1") == 0 && recv_msg(&b, &type, text, sizeof text) == 1 && type == MSG_REL);

    puts("--- wrong key ---");
    make_pair(&a, &b, 1);
    b.key[0] ^= 1;
    check("receiver with a different key rejects", send_msg(&a, MSG_REQ, "R1 1") == 0 && recv_msg(&b, &type, text, sizeof text) == -2);

    puts("--- protocol violations ---");
    make_pair(&a, &b, 1);
    uint8_t junk[HDR_LEN] = {1, 0, 0, 0, 1, 0xFF, 0xFF};         /* length 65535 > MAX_PAYLOAD */
    write(a.fd, junk, sizeof junk);
    check("oversized length field is refused (-1)", recv_msg(&b, &type, text, sizeof text) == -1);
    make_pair(&a, &b, 1);
    close(a.fd);
    check("closed connection returns 0", recv_msg(&b, &type, text, sizeof text) == 0);

    puts("--- plain mode ---");
    make_pair(&a, &b, 0);
    check("plain send/recv", send_msg(&a, MSG_REQ, "R1 1") == 0 && recv_msg(&b, &type, text, sizeof text) == 1 && !strcmp(text, "R1 1"));
    send_replay(&a);
    check("plain mode still blocks replays (seq)", recv_msg(&b, &type, text, sizeof text) == -2);

    puts("--- blob framing (handshake) ---");
    int sv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    uint8_t data[300], got[300]; size_t n;
    for (int i = 0; i < 300; i++) data[i] = (uint8_t)i;
    check("blob round trip", send_blob(sv[0], data, 300) == 0 && recv_blob(sv[1], got, sizeof got, &n) == 0 && n == 300 && !memcmp(data, got, 300));
    send_blob(sv[0], data, 300);
    check("blob larger than buffer is refused", recv_blob(sv[1], got, 100, &n) != 0);

    printf("\n%s (%d failed)\n", fails ? "SOME TESTS FAILED" : "ALL PROTOCOL TESTS PASSED", fails);
    return fails != 0;
}
