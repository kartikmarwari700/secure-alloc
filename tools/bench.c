/* bench.c - load / performance test for the non-functional requirements
 * Owner   : Kartik (module M6, performance evaluation)
 *
 *   ./bench 127.0.0.1 20 50     -> 20 clients at the same time, 50 rounds each
 *
 * Checks:  NFR2  handshake < 1 s and request-response < 50 ms (LAN/loopback)
 *          NFR4  at least 20 simultaneous clients without loss of correctness
 * Every client: handshake -> N x (STATUS round trip, REQ R3 / REL R3 cycle) -> quit.
 * The resource table must be back to "R3 3/3 free" at the end (correctness check).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "common.h"
#include "auth.h"

static const char *g_ip;
static int g_rounds;

typedef struct { int idx; double hs_ms; double rtt_sum_ms, rtt_max_ms; long rtt_n; int errors; } result_t;

static double now_ms(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

static void send_hb(int ufd, struct sockaddr_in *to, const char *id, session_t *s, unsigned *seq)
{
    char text[64], msg[160], hex[65]; uint8_t h[32];
    snprintf(text, sizeof text, "HB %s %u", id, ++*seq);
    hmac_sha256(s->key, (const uint8_t *)text, strlen(text), h);
    to_hex(h, 32, hex);
    snprintf(msg, sizeof msg, "%s %s", text, hex);
    sendto(ufd, msg, strlen(msg), 0, (struct sockaddr *)to, sizeof *to);
}

static void *worker(void *arg)
{
    result_t *r = arg;
    char id[16], text[MAX_PAYLOAD + 1];
    int type;
    snprintf(id, sizeof id, "C%d", r->idx);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons(TCP_PORT); inet_pton(AF_INET, g_ip, &sa.sin_addr);
    session_t s; session_init(&s, fd, 0);

    double t0 = now_ms();
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || auth_client_handshake(&s, id, 0) < 0 ||
        recv_msg(&s, &type, text, sizeof text) != 1 || type != MSG_STATUS) { r->errors++; return NULL; }
    r->hs_ms = now_ms() - t0;                                    /* TCP connect + DH + RSA + first encrypted message */

    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ua = sa; ua.sin_port = htons(UDP_PORT);
    unsigned hbseq = 0;

    for (int i = 0; i < g_rounds; i++) {
        if (i % 20 == 0) send_hb(ufd, &ua, id, &s, &hbseq);

        double t1 = now_ms();                                    /* round trip 1: STATUS */
        if (send_msg(&s, MSG_STATUS, "") < 0 || recv_msg(&s, &type, text, sizeof text) != 1 || type != MSG_STATUS) { r->errors++; break; }
        double rtt = now_ms() - t1;
        r->rtt_sum_ms += rtt; r->rtt_n++; if (rtt > r->rtt_max_ms) r->rtt_max_ms = rtt;

        if (send_msg(&s, MSG_REQ, "R3 1") < 0 || recv_msg(&s, &type, text, sizeof text) != 1) { r->errors++; break; }
        if (type == MSG_WAIT && (recv_msg(&s, &type, text, sizeof text) != 1 || type != MSG_GRANT)) { r->errors++; break; }
        else if (type != MSG_WAIT && type != MSG_GRANT) { r->errors++; break; }
        send_hb(ufd, &ua, id, &s, &hbseq);
        if (send_msg(&s, MSG_REL, "R3 1") < 0 || recv_msg(&s, &type, text, sizeof text) != 1 || type != MSG_STATUS) { r->errors++; break; }
    }
    close(ufd); close(fd);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: %s <server-ip> <clients 1-20> <rounds>\n", argv[0]); return 1; }
    g_ip = argv[1];
    int n = atoi(argv[2]); g_rounds = atoi(argv[3]);
    if (n < 1 || n > 20 || g_rounds < 1) { fprintf(stderr, "clients must be 1..20\n"); return 1; }

    pthread_t th[20]; result_t res[20];
    memset(res, 0, sizeof res);
    double t0 = now_ms();
    for (int i = 0; i < n; i++) { res[i].idx = i + 1; pthread_create(&th[i], NULL, worker, &res[i]); }
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
    double total = now_ms() - t0;

    double hs_sum = 0, hs_max = 0, rtt_sum = 0, rtt_max = 0; long rtt_n = 0; int errors = 0;
    for (int i = 0; i < n; i++) {
        hs_sum += res[i].hs_ms; if (res[i].hs_ms > hs_max) hs_max = res[i].hs_ms;
        rtt_sum += res[i].rtt_sum_ms; rtt_n += res[i].rtt_n; if (res[i].rtt_max_ms > rtt_max) rtt_max = res[i].rtt_max_ms;
        errors += res[i].errors;
    }
    printf("clients: %d   rounds each: %d   total time: %.0f ms\n", n, g_rounds, total);
    printf("handshake (connect+DH+RSA)   avg %.1f ms   max %.1f ms   -> NFR2 (< 1000 ms): %s\n",
           hs_sum / n, hs_max, hs_max < 1000 ? "PASS" : "FAIL");
    printf("request-response round trip  avg %.3f ms   max %.3f ms   -> NFR2 (< 50 ms):   %s\n",
           rtt_n ? rtt_sum / rtt_n : 0, rtt_max, (rtt_n && rtt_max < 50) ? "PASS" : "FAIL");
    printf("errors: %d   -> NFR4 (%d simultaneous clients, no errors): %s\n", errors, n, errors == 0 ? "PASS" : "FAIL");

    /* correctness: all resources must be free again */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons(TCP_PORT); inet_pton(AF_INET, g_ip, &sa.sin_addr);
    session_t s; session_init(&s, fd, 0);
    char text[MAX_PAYLOAD + 1]; int type, ok = 0;
    usleep(300000);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0 && auth_client_handshake(&s, "C1", 0) == 0 &&
        recv_msg(&s, &type, text, sizeof text) == 1 && send_msg(&s, MSG_STATUS, "") == 0 &&
        recv_msg(&s, &type, text, sizeof text) == 1) {
        printf("final resource table: %s\n", text);
        ok = strstr(text, "R3 3/3 free") != NULL;
    }
    printf("consistency check (R3 back to 3/3): %s\n", ok ? "PASS" : "FAIL");
    close(fd);
    return (errors == 0 && ok) ? 0 : 1;
}
