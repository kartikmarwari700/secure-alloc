/* client.c - Modules M1/M2 (client side): menu-driven client, UDP heartbeat sender.
 * Owner   : Ishita   (the handshake itself is in auth.c, module M3)
 *
 *   ./client <server-ip> <client-id> [--plain] [--debug] [--udp-log] [--tcp-port N] [--udp-port N]
 *   example:  ./client 127.0.0.1 C1
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "common.h"
#include "auth.h"

static session_t g_sess;
static char g_id[16];
static const char *g_ip;
static int g_debug = 0, g_udp_log = 0, g_tcp_port = TCP_PORT, g_udp_port = UDP_PORT;
static volatile int g_hb_on = 1;

/* ---------------- UDP heartbeat thread ---------------- */
static void *hb_thread(void *arg)
{
    (void)arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET; to.sin_port = htons(g_udp_port); inet_pton(AF_INET, g_ip, &to.sin_addr);
    unsigned seq = 0;
    for (;;) {
        if (g_hb_on) {
            char text[64], msg[160], hex[65]; uint8_t h[32];
            snprintf(text, sizeof text, "HB %s %u", g_id, ++seq);
            hmac_sha256(g_sess.key, (const uint8_t *)text, strlen(text), h);   /* proves the heartbeat is really ours */
            to_hex(h, 32, hex);
            snprintf(msg, sizeof msg, "%s %s", text, hex);
            sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&to, sizeof to);
        }
        time_t t0 = time(NULL);
        while (time(NULL) < t0 + HB_INTERVAL) {                 /* wait, and print UDP status if it arrives */
            struct pollfd p = { fd, POLLIN, 0 };
            if (poll(&p, 1, 500) > 0) {
                char buf[512];
                ssize_t n = recvfrom(fd, buf, sizeof buf - 1, 0, NULL, NULL);
                if (n > 0 && g_udp_log) { buf[n] = 0; printf("\n[UDP] %s\n> ", buf); fflush(stdout); }
            }
        }
    }
    return NULL;
}

/* ---------------- tiny stdin line reader (works together with select) ---------------- */
static char inbuf[1024];
static size_t inlen = 0;

static void fill_input(int *eof)                 /* call once when select() says stdin is readable */
{
    if (inlen == sizeof inbuf) inlen = 0;        /* overlong line: discard */
    ssize_t r = read(0, inbuf + inlen, sizeof inbuf - inlen);
    if (r <= 0) *eof = 1; else inlen += (size_t)r;
}

static int next_line(char *line, size_t cap)     /* returns 1 and a line if a full line is buffered */
{
    char *nl = memchr(inbuf, '\n', inlen);
    if (!nl) return 0;
    size_t n = (size_t)(nl - inbuf), used = n + 1;
    if (n >= cap) n = cap - 1;
    memcpy(line, inbuf, n); line[n] = 0;
    memmove(inbuf, inbuf + used, inlen - used); inlen -= used;
    return 1;
}

static void print_menu(void)
{
    puts("\n=========== SecureAlloc client ===========");
    puts(" 1 / req <res> <units>   request a resource    e.g.  req R1 1");
    puts(" 2 / rel <res> <units>   release a resource    e.g.  rel R1 1");
    puts(" 3 / status              show resource table");
    puts(" 4 / tamper              attack demo: send a modified packet");
    puts(" 5 / replay              attack demo: resend the previous packet");
    puts(" 6 / mute                stop heartbeats (server will time us out)");
    puts(" 7 / menu                show this menu");
    puts(" 0 / quit                disconnect");
    puts("Resources on the server: R1 (1 unit), R2 (1 unit), R3 (3 units)");
    puts("==========================================");
}

static void print_incoming(int type, const char *text)
{
    printf("\n<< [%s] %s\n> ", msg_name(type), text);
    fflush(stdout);
}

/* returns 1 to quit */
static int handle_command(char *line)
{
    char *tok[3] = {0}; int n = 0;
    for (char *p = strtok(line, " \t\r"); p && n < 3; p = strtok(NULL, " \t\r")) tok[n++] = p;
    if (n == 0) return 0;
    const char *c = tok[0];
    char msg[64];

    if (!strcmp(c, "1") || !strcmp(c, "req") || !strcmp(c, "2") || !strcmp(c, "rel")) {
        int is_req = (!strcmp(c, "1") || !strcmp(c, "req"));
        if (n < 3) { puts("usage: req <resource> <units>   or   rel <resource> <units>"); return 0; }
        snprintf(msg, sizeof msg, "%s %s", tok[1], tok[2]);
        printf(">> [%s] %s\n", is_req ? "REQ" : "REL", msg);
        if (send_msg(&g_sess, is_req ? MSG_REQ : MSG_REL, msg) < 0) { puts("send failed"); return 1; }
    } else if (!strcmp(c, "3") || !strcmp(c, "status")) {
        send_msg(&g_sess, MSG_STATUS, "");
    } else if (!strcmp(c, "4") || !strcmp(c, "tamper")) {
        puts(">> sending a REQ whose ciphertext has one bit flipped (attacker in the middle)");
        send_tampered(&g_sess, MSG_REQ, "R3 1");
    } else if (!strcmp(c, "5") || !strcmp(c, "replay")) {
        puts(">> re-sending the previous packet byte-for-byte (replay attack)");
        send_replay(&g_sess);
    } else if (!strcmp(c, "6") || !strcmp(c, "mute")) {
        g_hb_on = !g_hb_on;
        printf("heartbeats %s\n", g_hb_on ? "ON" : "OFF - server should drop us after ~6 s");
    } else if (!strcmp(c, "7") || !strcmp(c, "menu") || !strcmp(c, "h")) {
        print_menu();
    } else if (!strcmp(c, "0") || !strcmp(c, "q") || !strcmp(c, "quit")) {
        return 1;
    } else {
        puts("unknown command - type 'menu'");
    }
    return 0;
}

int main(int argc, char **argv)
{
    int secure = 1;
    if (argc < 3) { fprintf(stderr, "usage: %s <server-ip> <client-id e.g. C1> [--plain] [--debug] [--udp-log] [--tcp-port N] [--udp-port N]\n", argv[0]); return 1; }
    g_ip = argv[1];
    snprintf(g_id, sizeof g_id, "%s", argv[2]);
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--plain")) secure = 0;
        else if (!strcmp(argv[i], "--debug")) g_debug = 1;
        else if (!strcmp(argv[i], "--udp-log")) g_udp_log = 1;
        else if (!strcmp(argv[i], "--tcp-port") && i + 1 < argc) g_tcp_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--udp-port") && i + 1 < argc) g_udp_port = atoi(argv[++i]);
    }
    size_t idl = strlen(g_id);
    if (idl < 1 || idl > 8) { fprintf(stderr, "client id must be 1-8 letters/digits\n"); return 1; }
    for (size_t i = 0; i < idl; i++)
        if (!((g_id[i] >= '0' && g_id[i] <= '9') || (g_id[i] >= 'A' && g_id[i] <= 'Z') || (g_id[i] >= 'a' && g_id[i] <= 'z'))) {
            fprintf(stderr, "client id must be letters/digits only\n"); return 1;
        }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons(g_tcp_port);
    if (inet_pton(AF_INET, g_ip, &sa.sin_addr) != 1) { fprintf(stderr, "bad IP address\n"); return 1; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("connect"); return 1; }   /* TCP 3-way handshake */
    session_init(&g_sess, fd, 0);

    if (secure) {
        if (auth_client_handshake(&g_sess, g_id, g_debug) < 0) return 1;
    } else {
        g_sess.secure = 0;
        send_msg(&g_sess, MSG_HELLO, g_id);
    }

    int type; char text[MAX_PAYLOAD + 1];
    int rc = recv_msg(&g_sess, &type, text, sizeof text);       /* first (encrypted) packet from server */
    if (rc != 1 || type != MSG_STATUS) {
        if (rc == 1) fprintf(stderr, "server refused: %s\n", text); else fprintf(stderr, "no welcome from server\n");
        return 1;
    }
    printf("Connected as %s - %s channel established.\n", g_id, secure ? "ENCRYPTED (AES-256-GCM)" : "PLAIN-TEXT");

    pthread_t t; pthread_create(&t, NULL, hb_thread, NULL); pthread_detach(t);

    print_menu();
    printf("> "); fflush(stdout);

    int eof = 0;
    time_t eof_time = 0;
    for (;;) {
        fd_set rf; FD_ZERO(&rf);
        FD_SET(fd, &rf);
        if (!eof) FD_SET(0, &rf);
        struct timeval tv = {1, 0};
        int mx = fd > 0 ? fd : 0;
        if (select(mx + 1, &rf, NULL, NULL, &tv) < 0) { if (errno == EINTR) continue; break; }

        if (FD_ISSET(fd, &rf)) {
            rc = recv_msg(&g_sess, &type, text, sizeof text);
            if (rc == 1) print_incoming(type, text);
            else if (rc == -2) { printf("\n!! rejected packet from server: %s\n> ", g_sess.err); fflush(stdout); }
            else { puts("\nconnection closed by server"); break; }
        }
        if (!eof && FD_ISSET(0, &rf)) {
            char line[256];
            fill_input(&eof);
            while (next_line(line, sizeof line)) {
                if (handle_command(line)) { close(fd); return 0; }
                printf("> "); fflush(stdout);
            }
            if (eof) eof_time = time(NULL);
        }
        if (eof && time(NULL) - eof_time >= 2) break;            /* piped input finished: wait 2 s for replies, then exit */
    }
    close(fd);
    return 0;
}
