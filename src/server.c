/* server.c - Module M1: socket communication layer (server side) + glue to M3, M4, M5
 * Owner   : Ishita
 *
 *   ./server                       secure mode (DH + RSA + AES-256-GCM)
 *   ./server --plain               plain mode (no encryption) - only for the Wireshark comparison
 *   ./server --debug               also print the session-key fingerprint (compare with the client)
 *   ./server --config FILE         read ports / timeouts / resources from FILE (see secure_alloc.conf)
 *
 * Threads:
 *   main thread    : accept() loop, one new pthread per client
 *   client threads : handshake, then receive REQ / REL / STATUS and answer
 *   udp thread     : receives heartbeats, sends UDP status, drops silent clients
 *   console thread : admin commands typed on the server terminal (help, status, clients, stats, quit)
 * All shared state (clients[] and the resource table) is protected by ONE mutex: g_lock.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include "common.h"
#include "resource.h"
#include "auth.h"
#include "config.h"
#include "logger.h"

typedef struct {
    int  used;                    /* slot in use (thread running) */
    int  ready;                   /* handshake finished, client registered */
    char id[16];
    session_t s;
    struct sockaddr_in peer;      /* TCP peer address */
    struct sockaddr_in udp;       /* where to send UDP status (learned from heartbeats) */
    int  have_udp;
    time_t connected_at, last_hb;
    uint32_t hb_seq;
    char fp[17];                  /* session-key fingerprint (debug) */
} client_t;

static client_t clients[MAX_CLIENTS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;   /* protects clients[] AND the resource table */
static config_t g_cfg;
static int g_secure = 1, g_debug = 0, g_udp_fd = -1;
static volatile sig_atomic_t g_stop = 0;
static time_t g_start;

/* statistics (shown by the "stats" console command and at shutdown) */
static unsigned long st_conn, st_hs_ok, st_hs_fail, st_rx, st_tx, st_tamper, st_replay, st_hb_timeout, st_hb_rx;
#define INC(x) __atomic_add_fetch(&(x), 1, __ATOMIC_RELAXED)

/* resource manager wants to tell client c something (late GRANT, deadlock notice). Called with g_lock held. */
static void notify(int c, int type, const char *text)
{
    LOGI("-> %s [%s] %s", clients[c].id, msg_name(type), text);
    send_msg(&clients[c].s, type, text); INC(st_tx);
}

static void rm_logger(const char *line) { LOGW("%s", line); }

static void print_stats(void)
{
    rm_stats_t r; rm_get_stats(&r);
    LOGI("---- statistics (uptime %lds) ----", (long)(time(NULL) - g_start));
    LOGI("connections %lu | handshakes ok %lu failed %lu | packets rx %lu tx %lu", st_conn, st_hs_ok, st_hs_fail, st_rx, st_tx);
    LOGI("rejected: tampered %lu replayed %lu | heartbeats %lu, timeouts %lu", st_tamper, st_replay, st_hb_rx, st_hb_timeout);
    LOGI("resources: grants %lu waits %lu releases %lu | deadlocks %lu (rollbacks %lu)", r.grants, r.waits, r.releases, r.deadlocks, r.rollbacks);
}

/* ---------------- one thread per client ---------------- */
static void *client_thread(void *arg)
{
    int slot = (int)(intptr_t)arg;
    client_t *c = &clients[slot];
    char payload[MAX_PAYLOAD + 1], id[16] = "";
    int type, rc;

    if (g_secure) {
        if (auth_server_handshake(&c->s, id, g_debug) < 0) { INC(st_hs_fail); goto cleanup; }
        if (g_debug) key_fingerprint(c->s.key, c->fp);
    } else {                                                        /* plain mode: HELLO <id> */
        rc = recv_msg(&c->s, &type, payload, sizeof payload);
        if (rc != 1 || type != MSG_HELLO || !valid_client_id(payload)) { INC(st_hs_fail); goto cleanup; }
        memcpy(id, payload, strlen(payload) + 1);                   /* valid_client_id() limits to 8 chars */
    }
    INC(st_hs_ok);
    struct timeval none = {0, 0};                                   /* handshake done: remove the timeout */
    setsockopt(c->s.fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none);

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (i != slot && clients[i].ready && strcmp(clients[i].id, id) == 0) {
            pthread_mutex_unlock(&g_lock);
            LOGS("client id '%s' is already connected - second connection refused (spoofing attempt?)", id);
            send_msg(&c->s, MSG_ERR, "client id already connected");
            goto cleanup;
        }
    memcpy(c->id, id, strlen(id) + 1);
    c->ready = 1; c->connected_at = c->last_hb = time(NULL);
    rm_register(slot, id, client_priority(id));
    pthread_mutex_unlock(&g_lock);

    LOGI("client %s connected from %s:%d (%s) [slot %d]", id, inet_ntoa(c->peer.sin_addr), ntohs(c->peer.sin_port),
         g_secure ? "secure, session key established" : "PLAIN mode", slot);
    send_msg(&c->s, MSG_STATUS, "WELCOME"); INC(st_tx);

    for (;;) {
        rc = recv_msg(&c->s, &type, payload, sizeof payload);
        if (rc == 0 || rc == -1) break;                             /* closed or broken */
        if (rc == -2) {                                             /* tampered or replayed packet */
            LOGS("REJECTED packet from %s: %s", id, c->s.err);
            if (c->s.reject_kind == REJ_TAMPER) INC(st_tamper); else INC(st_replay);
            send_msg(&c->s, MSG_ERR, "packet rejected by server"); INC(st_tx);
            continue;
        }
        INC(st_rx);
        LOGI("<- %s [%s] %s", id, msg_name(type), payload);

        char out[400], res[16];
        int units, rt;
        pthread_mutex_lock(&g_lock);
        if (type == MSG_REQ || type == MSG_REL) {
            if (sscanf(payload, "%15s %d", res, &units) != 2) { snprintf(out, sizeof out, "usage: <resource> <units>"); rt = MSG_ERR; }
            else if (type == MSG_REQ) rt = rm_request(slot, res, units, out, sizeof out);
            else                      rt = rm_release(slot, res, units, out, sizeof out);
        } else if (type == MSG_STATUS) {
            rm_status(slot, out, sizeof out); rt = MSG_STATUS;
        } else {
            snprintf(out, sizeof out, "unknown message type"); rt = MSG_ERR;
        }
        LOGI("-> %s [%s] %s", id, msg_name(rt), out);
        send_msg(&c->s, rt, out); INC(st_tx);                       /* under the lock => replies stay in order */
        pthread_mutex_unlock(&g_lock);
    }

cleanup:
    pthread_mutex_lock(&g_lock);
    if (c->ready) {
        LOGI("client %s disconnected - releasing its resources", id);
        rm_remove_client(slot);
    }
    c->ready = 0;
    shutdown(c->s.fd, SHUT_RDWR);
    close(c->s.fd);
    pthread_mutex_destroy(&c->s.send_lock);
    c->used = 0;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

/* ---------------- UDP: heartbeat receiver + status broadcaster + timeout monitor ---------------- */
static void handle_heartbeat(char *buf, struct sockaddr_in *from)
{
    char id[16], mac[80];
    unsigned seq;
    if (sscanf(buf, "HB %15s %u %79s", id, &seq, mac) != 3) return;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_t *c = &clients[i];
        if (!c->ready || strcmp(c->id, id) != 0) continue;
        char text[64], expect[65]; uint8_t h[32];
        snprintf(text, sizeof text, "HB %s %u", id, seq);
        hmac_sha256(c->s.key, (const uint8_t *)text, strlen(text), h);    /* only the real client knows the key */
        to_hex(h, 32, expect);
        if (strcmp(expect, mac) == 0 && seq > c->hb_seq) {
            c->hb_seq = seq; c->last_hb = time(NULL); c->udp = *from; c->have_udp = 1;
            INC(st_hb_rx);
        } else {
            LOGS("bad or replayed UDP heartbeat claiming to be %s ignored", id);
        }
        break;
    }
    pthread_mutex_unlock(&g_lock);
}

static void *udp_thread(void *arg)
{
    (void)arg;
    time_t last_status = 0;
    for (;;) {
        char buf[256];
        struct sockaddr_in from; socklen_t fl = sizeof from;
        ssize_t n = recvfrom(g_udp_fd, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl);   /* 1 s timeout */
        if (n > 0) { buf[n] = 0; handle_heartbeat(buf, &from); }

        time_t now = time(NULL);
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            client_t *c = &clients[i];
            if (!c->ready) continue;
            if (now - c->last_hb > g_cfg.hb_timeout) {               /* silent client */
                LOGW("heartbeat timeout for %s - dropping connection", c->id);
                INC(st_hb_timeout);
                shutdown(c->s.fd, SHUT_RDWR);                        /* its thread wakes up and frees resources */
                c->last_hb = now;
            }
        }
        if (now - last_status >= g_cfg.status_interval) {
            last_status = now;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                client_t *c = &clients[i];
                if (!c->ready || !c->have_udp) continue;
                char msg[400];
                strcpy(msg, "STATUS ");
                rm_status(i, msg + 7, sizeof msg - 7);
                sendto(g_udp_fd, msg, strlen(msg), 0, (struct sockaddr *)&c->udp, sizeof c->udp);
            }
        }
        pthread_mutex_unlock(&g_lock);
    }
    return NULL;
}

/* ---------------- admin console (typed on the server terminal) ---------------- */
static void *console_thread(void *arg)
{
    (void)arg;
    char line[128];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strcmp(line, "help")) {
            puts("console commands:  status  clients  stats  quit  help");
        } else if (!strcmp(line, "status")) {
            char buf[2048];
            pthread_mutex_lock(&g_lock); rm_dump(buf, sizeof buf); pthread_mutex_unlock(&g_lock);
            fputs(buf, stdout);
        } else if (!strcmp(line, "clients")) {
            time_t now = time(NULL); int n = 0;
            pthread_mutex_lock(&g_lock);
            for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].ready) {
                printf("  slot %2d  %-4s  %s:%d  online %lds  last heartbeat %lds ago  %s%s\n", i, clients[i].id,
                       inet_ntoa(clients[i].peer.sin_addr), ntohs(clients[i].peer.sin_port),
                       (long)(now - clients[i].connected_at), (long)(now - clients[i].last_hb),
                       g_secure ? "key " : "PLAIN", g_debug ? clients[i].fp : "");
                n++;
            }
            pthread_mutex_unlock(&g_lock);
            printf("  %d client(s) connected\n", n);
        } else if (!strcmp(line, "stats")) {
            print_stats();
        } else if (!strcmp(line, "quit") || !strcmp(line, "exit")) {
            g_stop = 1; break;
        } else if (line[0]) {
            puts("unknown command - type 'help'");
        }
    }
    return NULL;
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

int main(int argc, char **argv)
{
    const char *conf = NULL;
    config_defaults(&g_cfg);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--plain")) g_secure = 0;
        else if (!strcmp(argv[i], "--debug")) g_debug = 1;
        else if (!strcmp(argv[i], "--config") && i + 1 < argc) conf = argv[++i];
        else { fprintf(stderr, "usage: %s [--plain] [--debug] [--config FILE]\n", argv[0]); return 1; }
    }
    if (conf) {
        int rc = config_load(&g_cfg, conf);
        if (rc == -1) { fprintf(stderr, "cannot open config file %s\n", conf); return 1; }
        if (rc == -2) return 1;
    }
    log_open(g_cfg.log_path);
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa_int = {0};
    sa_int.sa_handler = on_signal;                                  /* Ctrl+C -> clean shutdown with statistics */
    sigaction(SIGINT, &sa_int, NULL); sigaction(SIGTERM, &sa_int, NULL);
    g_start = time(NULL);

    rm_init(notify);
    rm_set_logger(rm_logger);
    for (int i = 0; i < g_cfg.nres; i++) rm_add_resource(g_cfg.rname[i], g_cfg.rtotal[i]);

    int lfd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_ANY); sa.sin_port = htons(g_cfg.tcp_port);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(lfd, 32) < 0) { perror("tcp bind/listen"); return 1; }

    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ua = sa; ua.sin_port = htons(g_cfg.udp_port);
    struct timeval tv = {1, 0};
    setsockopt(g_udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (bind(g_udp_fd, (struct sockaddr *)&ua, sizeof ua) < 0) { perror("udp bind"); return 1; }

    pthread_t ut, ct;
    pthread_create(&ut, NULL, udp_thread, NULL); pthread_detach(ut);
    pthread_create(&ct, NULL, console_thread, NULL); pthread_detach(ct);

    LOGI("SecureAlloc server up: TCP %d, UDP %d, mode = %s", g_cfg.tcp_port, g_cfg.udp_port,
         g_secure ? "SECURE" : "PLAIN (insecure!)");
    char rl[256] = "";
    for (int i = 0; i < g_cfg.nres; i++) {
        char t[32]; snprintf(t, sizeof t, "%s x%d  ", g_cfg.rname[i], g_cfg.rtotal[i]); strncat(rl, t, sizeof rl - strlen(rl) - 1);
    }
    LOGI("resources: %s| heartbeat timeout %ds | log file %s", rl, g_cfg.hb_timeout, g_cfg.log_path);
    LOGI("type 'help' for server console commands, Ctrl+C to stop");

    while (!g_stop) {
        fd_set rf; FD_ZERO(&rf); FD_SET(lfd, &rf);
        struct timeval wait = {1, 0};
        if (select(lfd + 1, &rf, NULL, NULL, &wait) <= 0) continue;   /* timeout or signal: re-check g_stop */

        struct sockaddr_in peer; socklen_t pl = sizeof peer;
        int cfd = accept(lfd, (struct sockaddr *)&peer, &pl);
        if (cfd < 0) continue;
        INC(st_conn);

        pthread_mutex_lock(&g_lock);
        int slot = -1, active = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) if (clients[i].used) active++;
        for (int i = 0; i < MAX_CLIENTS && active < g_cfg.max_clients; i++) if (!clients[i].used) { slot = i; break; }
        if (slot < 0) {
            pthread_mutex_unlock(&g_lock);
            LOGW("too many clients (%d) - connection from %s refused", active, inet_ntoa(peer.sin_addr));
            close(cfd); continue;
        }
        memset(&clients[slot], 0, sizeof clients[slot]);
        clients[slot].used = 1;
        clients[slot].peer = peer;
        session_init(&clients[slot].s, cfd, g_secure);
        pthread_mutex_unlock(&g_lock);

        struct timeval hs = {10, 0};                                  /* a client that never finishes the handshake is dropped */
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &hs, sizeof hs);
        LOGI("new TCP connection from %s:%d", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

        pthread_t t;
        pthread_create(&t, NULL, client_thread, (void *)(intptr_t)slot);
        pthread_detach(t);
    }

    LOGI("server shutting down");
    print_stats();
    log_close();
    return 0;
}
