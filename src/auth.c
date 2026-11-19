/* auth.c - Module M3: Key exchange and authentication
 * Owner   : Priyani
 *
 * Handshake (section 6.2 of the synopsis):
 *
 *   Client                                           Server
 *     |------------- TCP connect (SYN, SYN-ACK, ACK) ----->|
 *     |<---- g^a mod p , RSA_sign_server(g^a) -------------|   client checks signature: "real server?"
 *     |----- g^b mod p , ID , RSA_sign_client(g^a|g^b|ID) ->|   server checks signature: "real client?"
 *     |  shared secret = g^ab mod p  (computed on both sides, never sent)
 *     |  session key   = SHA-256(shared secret)  -> AES-256
 *     |<------------- first encrypted message: WELCOME ----|
 *
 * Why the signatures matter: plain Diffie-Hellman can be attacked by a man-in-the-middle who swaps the public
 * values. Because g^a is signed with the server's private key and (g^a|g^b|ID) with the client's private key,
 * the attacker cannot forge them. Signing g^a inside the client's signature also binds it to this session.
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "auth.h"
#include "logger.h"

int valid_client_id(const char *id)
{
    size_t n = strlen(id);
    if (n < 1 || n > 8) return 0;
    for (size_t i = 0; i < n; i++) if (!isalnum((unsigned char)id[i])) return 0;
    return 1;
}

int client_priority(const char *id)
{
    while (*id && !isdigit((unsigned char)*id)) id++;
    return *id ? atoi(id) : 99;
}

void key_fingerprint(const uint8_t key[KEY_LEN], char hex[17])
{
    uint8_t fp[32];
    sha256(key, KEY_LEN, fp);
    to_hex(fp, 8, hex);
}

int auth_server_handshake(session_t *s, char *id_out, int debug)
{
    void *a = NULL;
    uint8_t ga[256], gb[300], sig[512], csig[512], secret[256], data[256 + 256 + 16];
    size_t siglen = sizeof sig, gbn, idn, csn;
    char idb[32];

    if (dh_generate(&a, ga) < 0) return -1;

    /* 1. server -> client : g^a mod p  +  RSA signature over it */
    if (rsa_sign("keys/server_priv.pem", ga, sizeof ga, sig, &siglen) < 0) {
        LOGE("cannot sign handshake: keys/server_priv.pem missing? run 'make keys'");
        dh_free(a); return -1;
    }
    if (send_blob(s->fd, ga, sizeof ga) < 0 || send_blob(s->fd, sig, siglen) < 0) { dh_free(a); return -1; }

    /* 2. client -> server : g^b mod p, client id, RSA signature over (g^a | g^b | id) */
    if (recv_blob(s->fd, gb, sizeof gb, &gbn) < 0 || gbn != 256 ||
        recv_blob(s->fd, (uint8_t *)idb, sizeof idb - 1, &idn) < 0 ||
        recv_blob(s->fd, csig, sizeof csig, &csn) < 0) {
        LOGW("handshake: incomplete or malformed message from client");
        dh_free(a); return -1;
    }
    idb[idn] = 0;
    if (!valid_client_id(idb)) { LOGS("handshake: invalid client id rejected"); dh_free(a); return -1; }

    memcpy(data, ga, 256); memcpy(data + 256, gb, 256); memcpy(data + 512, idb, idn);
    char path[64]; snprintf(path, sizeof path, "keys/%s_pub.pem", idb);
    if (rsa_verify(path, data, 512 + idn, csig, csn) < 0) {
        LOGS("handshake: RSA signature of '%s' INVALID or unknown client - connection refused", idb);
        dh_free(a); return -1;
    }

    /* 3. both sides compute g^ab mod p ; session key = SHA-256(secret) */
    if (dh_shared(a, gb, secret) < 0) { LOGS("handshake: invalid DH public value from %s", idb); dh_free(a); return -1; }
    dh_free(a);
    sha256(secret, sizeof secret, s->key);
    memset(secret, 0, sizeof secret);
    s->secure = 1;

    if (debug) {
        char fp[17]; key_fingerprint(s->key, fp);
        LOGI("DEBUG session-key fingerprint for %s = %s", idb, fp);
    }
    memcpy(id_out, idb, idn + 1);
    return 0;
}

int auth_client_handshake(session_t *s, const char *id, int debug)
{
    uint8_t ga[300], sig[512], gb[256], csig[512], secret[256], data[256 + 256 + 16];
    size_t gan, sn, csn = sizeof csig;
    void *b = NULL;
    int fd = s->fd;

    if (recv_blob(fd, ga, sizeof ga, &gan) < 0 || gan != 256 || recv_blob(fd, sig, sizeof sig, &sn) < 0) {
        fprintf(stderr, "handshake: no valid message from server\n"); return -1;
    }
    if (rsa_verify("keys/server_pub.pem", ga, 256, sig, sn) < 0) {      /* is this really our server? */
        fprintf(stderr, "SERVER AUTHENTICATION FAILED - signature on g^a is wrong. Aborting.\n"); return -1;
    }
    if (dh_generate(&b, gb) < 0) return -1;

    size_t idn = strlen(id);
    memcpy(data, ga, 256); memcpy(data + 256, gb, 256); memcpy(data + 512, id, idn);
    char path[64]; snprintf(path, sizeof path, "keys/%s_priv.pem", id);
    if (rsa_sign(path, data, 512 + idn, csig, &csn) < 0) {
        fprintf(stderr, "cannot sign with %s (run 'make keys')\n", path); dh_free(b); return -1;
    }
    if (send_blob(fd, gb, 256) < 0 || send_blob(fd, (const uint8_t *)id, idn) < 0 || send_blob(fd, csig, csn) < 0) {
        dh_free(b); return -1;
    }
    if (dh_shared(b, ga, secret) < 0) { dh_free(b); return -1; }
    dh_free(b);
    sha256(secret, sizeof secret, s->key);
    memset(secret, 0, sizeof secret);
    s->secure = 1;

    if (debug) {
        char fp[17]; key_fingerprint(s->key, fp);
        printf("DEBUG session-key fingerprint = %s  (server prints the same value with --debug)\n", fp);
    }
    return 0;
}
