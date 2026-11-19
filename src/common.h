/* common.h - shared definitions: ports, message types, packet format, session object
 * Project : SecureAlloc (Computer Networks Lab, JIIT)  -  used by every module
 */
#ifndef COMMON_H
#define COMMON_H
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#define TCP_PORT        5000          /* requests / grants (encrypted) */
#define UDP_PORT        5001          /* heartbeat + status broadcast  */
#define HB_INTERVAL     2             /* client sends heartbeat every 2 s */
#define HB_TIMEOUT      6             /* server drops silent client after 6 s */
#define STATUS_INTERVAL 5             /* server sends UDP status every 5 s */

#define MAX_PAYLOAD 512
#define HDR_LEN     19                /* type(1) + seq(4) + len(2) + iv(12) */
#define IV_LEN      12
#define TAG_LEN     16
#define KEY_LEN     32                /* AES-256 */
#define MAX_FRAME   (HDR_LEN + MAX_PAYLOAD + TAG_LEN)

enum { MSG_REQ = 1, MSG_GRANT, MSG_WAIT, MSG_DENY, MSG_REL, MSG_STATUS, MSG_HB, MSG_ERR, MSG_HELLO };

enum { REJ_NONE = 0, REJ_TAMPER = 1, REJ_REPLAY = 2 };

const char *msg_name(int type);

/* One secure TCP session (one per client) */
typedef struct {
    int      fd;
    int      secure;                  /* 1 = AES-256-GCM, 0 = plain mode (for Wireshark comparison) */
    uint8_t  key[KEY_LEN];            /* session key = SHA-256(DH shared secret) */
    uint32_t send_seq;                /* last sequence number we sent */
    uint32_t recv_seq;                /* highest sequence number accepted from the peer */
    pthread_mutex_t send_lock;        /* server threads may send to the same client */
    uint8_t  last_frame[MAX_FRAME];   /* kept so the client can demo a replay attack */
    int      last_len;
    char     err[64];                 /* why recv_msg rejected a packet */
    int      reject_kind;             /* REJ_TAMPER or REJ_REPLAY (set together with err) */
} session_t;

/* ---- protocol.c (M2) and secure_channel.c (M4) ---- */
void session_init(session_t *s, int fd, int secure);
int  send_all(int fd, const void *buf, size_t n);
int  recv_all(int fd, void *buf, size_t n);
int  send_blob(int fd, const uint8_t *data, size_t n);              /* handshake: 2-byte length + data */
int  recv_blob(int fd, uint8_t *data, size_t cap, size_t *n);
int  send_msg(session_t *s, int type, const char *payload);         /* 0 ok, -1 error */
int  recv_msg(session_t *s, int *type, char *payload, size_t cap);  /* 1 ok, 0 closed, -1 error, -2 rejected */
int  send_tampered(session_t *s, int type, const char *payload);    /* demo: flips one byte after encryption */
int  send_replay(session_t *s);                                     /* demo: resend the previous frame */

/* ---- crypto.c ---- */
int  dh_generate(void **priv, uint8_t pub[256]);
int  dh_shared(void *priv, const uint8_t peer_pub[256], uint8_t secret[256]);
void dh_free(void *priv);
void sha256(const uint8_t *data, size_t n, uint8_t out[32]);
int  rsa_sign(const char *priv_pem_path, const uint8_t *data, size_t n, uint8_t *sig, size_t *siglen);
int  rsa_verify(const char *pub_pem_path, const uint8_t *data, size_t n, const uint8_t *sig, size_t siglen);
int  aes_gcm_encrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN], const uint8_t *aad, size_t aadlen,
                     const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[TAG_LEN]);
int  aes_gcm_decrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN], const uint8_t *aad, size_t aadlen,
                     const uint8_t *ct, size_t n, const uint8_t tag[TAG_LEN], uint8_t *pt);
int  random_bytes(uint8_t *buf, size_t n);
void hmac_sha256(const uint8_t key[KEY_LEN], const uint8_t *data, size_t n, uint8_t out[32]);
void to_hex(const uint8_t *in, size_t n, char *out);
#endif
