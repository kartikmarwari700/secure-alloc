/* crypto.c - Modules M3 + M4 (crypto part): Diffie-Hellman, RSA signatures, SHA-256, AES-256-GCM.
 * Everything is a thin wrapper around OpenSSL libcrypto.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "common.h"

/* ---------- Diffie-Hellman (2048-bit MODP group from RFC 3526, generator g = 2) ---------- */

typedef struct { BIGNUM *a, *p, *g; } dh_ctx;

int dh_generate(void **priv, uint8_t pub[256])
{
    dh_ctx *d = calloc(1, sizeof *d);
    BN_CTX *bc = BN_CTX_new();
    BIGNUM *A = BN_new();
    int ok = 0;
    if (!d || !bc || !A) goto done;
    d->p = BN_get_rfc3526_prime_2048(NULL);
    d->g = BN_new(); BN_set_word(d->g, 2);
    d->a = BN_new();
    if (!d->p || !BN_rand(d->a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) goto done;   /* secret exponent a */
    if (!BN_mod_exp(A, d->g, d->a, d->p, bc)) goto done;                                /* A = g^a mod p     */
    if (BN_bn2binpad(A, pub, 256) != 256) goto done;
    *priv = d; ok = 1;
done:
    BN_free(A); BN_CTX_free(bc);
    if (!ok && d) dh_free(d);
    return ok ? 0 : -1;
}

int dh_shared(void *priv, const uint8_t peer_pub[256], uint8_t secret[256])
{
    dh_ctx *d = priv;
    BN_CTX *bc = BN_CTX_new();
    BIGNUM *B = BN_bin2bn(peer_pub, 256, NULL), *S = BN_new(), *pm1 = BN_new();
    int ok = 0;
    if (!bc || !B || !S || !pm1) goto done;
    BN_copy(pm1, d->p); BN_sub_word(pm1, 1);
    if (BN_cmp(B, BN_value_one()) <= 0 || BN_cmp(B, pm1) >= 0) goto done;   /* reject 0, 1, p-1 ... */
    if (!BN_mod_exp(S, B, d->a, d->p, bc)) goto done;                        /* S = B^a mod p */
    if (BN_bn2binpad(S, secret, 256) != 256) goto done;
    ok = 1;
done:
    BN_free(B); BN_free(S); BN_free(pm1); BN_CTX_free(bc);
    return ok ? 0 : -1;
}

void dh_free(void *priv)
{
    dh_ctx *d = priv;
    if (!d) return;
    BN_clear_free(d->a); BN_free(d->p); BN_free(d->g); free(d);
}

void sha256(const uint8_t *data, size_t n, uint8_t out[32]) { SHA256(data, n, out); }

/* ---------- RSA sign / verify (PEM files made by 'make keys') ---------- */

int rsa_sign(const char *priv_pem_path, const uint8_t *data, size_t n, uint8_t *sig, size_t *siglen)
{
    FILE *f = fopen(priv_pem_path, "r");
    if (!f) return -1;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = c && EVP_DigestSignInit(c, NULL, EVP_sha256(), NULL, k) == 1
               && EVP_DigestSignUpdate(c, data, n) == 1
               && EVP_DigestSignFinal(c, sig, siglen) == 1;
    EVP_MD_CTX_free(c); EVP_PKEY_free(k);
    return ok ? 0 : -1;
}

int rsa_verify(const char *pub_pem_path, const uint8_t *data, size_t n, const uint8_t *sig, size_t siglen)
{
    FILE *f = fopen(pub_pem_path, "r");
    if (!f) return -1;
    EVP_PKEY *k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = c && EVP_DigestVerifyInit(c, NULL, EVP_sha256(), NULL, k) == 1
               && EVP_DigestVerifyUpdate(c, data, n) == 1
               && EVP_DigestVerifyFinal(c, sig, siglen) == 1;
    EVP_MD_CTX_free(c); EVP_PKEY_free(k);
    return ok ? 0 : -1;
}

/* ---------- AES-256-GCM: encryption + 16-byte integrity tag in one step ---------- */

int aes_gcm_encrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN], const uint8_t *aad, size_t aadlen,
                    const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len, ok = 0;
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(c, NULL, NULL, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(c, NULL, &len, aad, (int)aadlen) != 1) goto done;      /* header is authenticated */
    if (n > 0 && EVP_EncryptUpdate(c, ct, &len, pt, (int)n) != 1) goto done;
    if (EVP_EncryptFinal_ex(c, ct + n, &len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

int aes_gcm_decrypt(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN], const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t n, const uint8_t tag[TAG_LEN], uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len, ok = 0;
    uint8_t tmp[TAG_LEN];
    if (!c) return -1;
    memcpy(tmp, tag, TAG_LEN);
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(c, NULL, NULL, key, iv) != 1) goto done;
    if (EVP_DecryptUpdate(c, NULL, &len, aad, (int)aadlen) != 1) goto done;
    if (n > 0 && EVP_DecryptUpdate(c, pt, &len, ct, (int)n) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tmp) != 1) goto done;
    if (EVP_DecryptFinal_ex(c, pt + n, &len) != 1) goto done;                    /* fails if tag is wrong */
    ok = 1;
done:
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

int random_bytes(uint8_t *buf, size_t n) { return RAND_bytes(buf, (int)n) == 1 ? 0 : -1; }

void hmac_sha256(const uint8_t key[KEY_LEN], const uint8_t *data, size_t n, uint8_t out[32])
{
    unsigned int len = 32;
    HMAC(EVP_sha256(), key, KEY_LEN, data, n, out, &len);
}

void to_hex(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", in[i]);
    out[2 * n] = 0;
}
