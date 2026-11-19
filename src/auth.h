/* auth.h - Module M3 interface: Diffie-Hellman key exchange + RSA authentication */
#ifndef AUTH_H
#define AUTH_H
#include "common.h"

int valid_client_id(const char *id);      /* 1-8 letters/digits only (the id is used in a file name) */
int client_priority(const char *id);      /* "C3" -> 3 ; smaller number = higher priority */

/* server side: runs the whole handshake on s->fd, fills s->key, copies the authenticated id into id_out[16] */
int auth_server_handshake(session_t *s, char *id_out, int debug);
/* client side: returns 0 when the server is authenticated and the session key is ready */
int auth_client_handshake(session_t *s, const char *id, int debug);

/* fingerprint = first 8 bytes of SHA-256(session key), safe to print for comparison */
void key_fingerprint(const uint8_t key[KEY_LEN], char hex[17]);
#endif
