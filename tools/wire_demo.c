/* wire_demo.c - shows exactly what an eavesdropper (Wireshark) sees, without needing Wireshark
 * Owner   : Kartik (module M6, traffic analysis)
 *
 * It sends the SAME request  "R1 1"  through a socket pair in plain mode and in secure mode and prints the raw bytes
 * of the packet in a Wireshark-style hex dump, field by field. Then it flips one bit and shows the rejection,
 * and re-sends an old packet and shows the replay rejection.   Run:  ./wire_demo
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include "common.h"

static void hexdump(const uint8_t *b, int n)
{
    for (int i = 0; i < n; i += 16) {
        printf("   %04x  ", i);
        for (int j = 0; j < 16; j++) { if (i + j < n) printf("%02x ", b[i + j]); else printf("   "); }
        printf(" ");
        for (int j = 0; j < 16 && i + j < n; j++) putchar(isprint(b[i + j]) ? b[i + j] : '.');
        putchar('\n');
    }
}

static void fields(const uint8_t *f, int n)
{
    unsigned seq = ((unsigned)f[1] << 24) | (f[2] << 16) | (f[3] << 8) | f[4];
    int len = (f[5] << 8) | f[6];
    printf("   Type=%d (%s)  Seq=%u  Length=%d  IV=", f[0], msg_name(f[0]), seq, len);
    for (int i = 0; i < IV_LEN; i++) printf("%02x", f[7 + i]);
    printf("  Tag=");
    for (int i = 0; i < 4; i++) printf("%02x", f[n - TAG_LEN + i]);
    printf("...\n");
}

static int capture(session_t *tx, int rx_fd, int type, const char *text, uint8_t *buf)
{
    send_msg(tx, type, text);
    return (int)read(rx_fd, buf, MAX_FRAME);          /* what an eavesdropper on the wire would capture */
}

int main(void)
{
    int sv[2];
    uint8_t cap[MAX_FRAME];
    char text[MAX_PAYLOAD + 1];
    int type;

    puts("=== 1. PLAIN mode: client sends  REQ \"R1 1\" ===");
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    session_t plain; session_init(&plain, sv[0], 0);
    int n = capture(&plain, sv[1], MSG_REQ, "R1 1", cap);
    fields(cap, n); hexdump(cap, n);
    puts("   -> an eavesdropper reads the request in the ASCII column. Nothing is hidden.\n");
    close(sv[0]); close(sv[1]);

    puts("=== 2. SECURE mode (AES-256-GCM): the same REQ \"R1 1\" ===");
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    session_t tx, rx;
    session_init(&tx, sv[0], 1); session_init(&rx, sv[1], 1);
    random_bytes(tx.key, KEY_LEN); memcpy(rx.key, tx.key, KEY_LEN);      /* stands in for the Diffie-Hellman key */
    n = capture(&tx, sv[1], MSG_REQ, "R1 1", cap);
    fields(cap, n); hexdump(cap, n);
    puts("   -> payload is ciphertext. Same message again gives different bytes (random IV):");
    uint8_t cap2[MAX_FRAME];
    int n2 = capture(&tx, sv[1], MSG_REQ, "R1 1", cap2);
    fields(cap2, n2);
    printf("   identical ciphertext? %s\n\n", memcmp(cap + HDR_LEN, cap2 + HDR_LEN, 4) == 0 ? "yes (BAD)" : "no (good)");

    puts("=== 3. Attacker flips ONE bit of a captured packet and forwards it ===");
    uint8_t bad[MAX_FRAME]; memcpy(bad, cap, (size_t)n);
    bad[HDR_LEN] ^= 1;
    /* feed the packets to a 'server' session through a fresh socket pair */
    int pv[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, pv);
    session_t srv; session_init(&srv, pv[1], 1); memcpy(srv.key, tx.key, KEY_LEN);
    write(pv[0], bad, (size_t)n);
    int rc = recv_msg(&srv, &type, text, sizeof text);
    printf("   server: recv_msg = %d  -> %s\n\n", rc, rc == -2 ? srv.err : "ACCEPTED (BAD)");

    puts("=== 4. Attacker replays an old, valid packet ===");
    write(pv[0], cap, (size_t)n);                    /* first delivery: genuine */
    rc = recv_msg(&srv, &type, text, sizeof text);
    printf("   first delivery : recv_msg = %d (accepted, text=\"%s\")\n", rc, text);
    write(pv[0], cap, (size_t)n);                    /* attacker sends the very same bytes again */
    rc = recv_msg(&srv, &type, text, sizeof text);
    printf("   replayed copy  : recv_msg = %d  -> %s\n", rc, rc == -2 ? srv.err : "ACCEPTED (BAD)");
    return 0;
}
