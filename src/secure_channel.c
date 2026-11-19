/* secure_channel.c - Module M4: Encryption and integrity layer
 * Owner   : Priyani
 *
 * Packet on the wire (section 6.3 of the synopsis):
 *
 *   +------+---------+--------+-----------+----------------------+---------+
 *   | Type | Seq No. | Length |  IV/Nonce |  Payload (encrypted) |   Tag   |
 *   | 1 B  |  4 B    |  2 B   |   12 B    |      Length bytes    |  16 B   |
 *   +------+---------+--------+-----------+----------------------+---------+
 *
 * Protection provided (AES-256-GCM):
 *   confidentiality : payload is encrypted
 *   integrity       : the 16-byte tag covers payload AND the first 7 header bytes (Type, Seq, Length)
 *   freshness       : sequence number must always increase -> replayed packets are rejected
 *   IV              : random for each packet, so the same message never gives the same ciphertext
 *
 * In "plain mode" (--plain, only for the Wireshark comparison) the payload is sent as readable text.
 */
#include <stdio.h>
#include <string.h>
#include "common.h"

static int build_frame(session_t *s, int type, const char *payload, uint8_t *f)
{
    size_t n = strlen(payload);
    if (n > MAX_PAYLOAD) n = MAX_PAYLOAD;
    uint32_t seq = ++s->send_seq;

    f[0] = (uint8_t)type;
    f[1] = seq >> 24; f[2] = seq >> 16; f[3] = seq >> 8; f[4] = seq;
    f[5] = (uint8_t)(n >> 8); f[6] = (uint8_t)n;

    if (s->secure) {
        if (random_bytes(f + 7, IV_LEN) < 0) return -1;
        if (aes_gcm_encrypt(s->key, f + 7, f, 7, (const uint8_t *)payload, n, f + HDR_LEN, f + HDR_LEN + n) < 0)
            return -1;
    } else {
        memset(f + 7, 0, IV_LEN);
        memcpy(f + HDR_LEN, payload, n);
        memset(f + HDR_LEN + n, 0, TAG_LEN);
    }
    return (int)(HDR_LEN + n + TAG_LEN);
}

int send_msg(session_t *s, int type, const char *payload)
{
    uint8_t f[MAX_FRAME];
    int rc = -1;
    pthread_mutex_lock(&s->send_lock);
    int len = build_frame(s, type, payload, f);
    if (len > 0) {
        memcpy(s->last_frame, f, (size_t)len);
        s->last_len = len;
        rc = send_all(s->fd, f, (size_t)len);
    }
    pthread_mutex_unlock(&s->send_lock);
    return rc;
}

/* attack demo: an attacker flips one bit of the ciphertext in transit */
int send_tampered(session_t *s, int type, const char *payload)
{
    uint8_t f[MAX_FRAME];
    int rc = -1;
    pthread_mutex_lock(&s->send_lock);
    int len = build_frame(s, type, payload, f);
    if (len > 0) {
        f[HDR_LEN] ^= 0x01;
        rc = send_all(s->fd, f, (size_t)len);
    }
    pthread_mutex_unlock(&s->send_lock);
    return rc;
}

/* attack demo: an attacker re-sends a packet he captured earlier */
int send_replay(session_t *s)
{
    int rc = -1;
    pthread_mutex_lock(&s->send_lock);
    if (s->last_len > 0) rc = send_all(s->fd, s->last_frame, (size_t)s->last_len);
    pthread_mutex_unlock(&s->send_lock);
    return rc;
}

/* 1 = ok, 0 = peer closed, -1 = error/protocol violation, -2 = packet rejected (see s->err, s->reject_kind) */
int recv_msg(session_t *s, int *type, char *payload, size_t cap)
{
    uint8_t h[HDR_LEN], body[MAX_PAYLOAD + TAG_LEN], pt[MAX_PAYLOAD + 1];
    s->reject_kind = REJ_NONE;
    int r = recv_all(s->fd, h, HDR_LEN);
    if (r <= 0) return r;

    size_t n = ((size_t)h[5] << 8) | h[6];
    if (n > MAX_PAYLOAD) { snprintf(s->err, sizeof s->err, "bad length field"); return -1; }
    r = recv_all(s->fd, body, n + TAG_LEN);
    if (r <= 0) return r;

    uint32_t seq = ((uint32_t)h[1] << 24) | ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 8) | h[4];

    if (s->secure) {                                           /* 1) integrity tag */
        if (aes_gcm_decrypt(s->key, h + 7, h, 7, body, n, body + n, pt) < 0) {
            snprintf(s->err, sizeof s->err, "integrity tag mismatch (packet modified)");
            s->reject_kind = REJ_TAMPER;
            return -2;
        }
    } else {
        memcpy(pt, body, n);
    }
    if (seq <= s->recv_seq) {                                  /* 2) replay check */
        snprintf(s->err, sizeof s->err, "old sequence number %u (replay)", seq);
        s->reject_kind = REJ_REPLAY;
        return -2;
    }
    s->recv_seq = seq;

    pt[n] = 0;
    snprintf(payload, cap, "%s", (char *)pt);
    *type = h[0];
    return 1;
}
