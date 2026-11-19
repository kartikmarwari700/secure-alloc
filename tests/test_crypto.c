/* test_crypto.c - unit tests for modules M3 + M4 (crypto part). No network needed.
 * Covers: Diffie-Hellman agreement, RSA sign/verify (incl. forged data), SHA-256 vector, AES-GCM round trip,
 *         tamper detection, HMAC, random IV.   Run:  make check   (needs keys:  make keys)
 */
#include <stdio.h>
#include <string.h>
#include "../src/common.h"

static int fails = 0;
static void check(const char *name, int cond)
{
    printf("%s  %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails++;
}

int main(void)
{
    puts("--- Diffie-Hellman (2048-bit group, RFC 3526) ---");
    void *a, *b, *c; uint8_t A[256], B[256], C[256], s1[256], s2[256], s3[256];
    check("generate client + server values", dh_generate(&a, A) == 0 && dh_generate(&b, B) == 0);
    check("both sides compute shared secret", dh_shared(a, B, s1) == 0 && dh_shared(b, A, s2) == 0);
    check("shared secrets are identical", memcmp(s1, s2, 256) == 0);
    uint8_t zero[256] = {0}, one[256] = {0}; one[255] = 1;
    check("DH rejects public value 0", dh_shared(a, zero, s3) != 0);
    check("DH rejects public value 1", dh_shared(a, one, s3) != 0);
    dh_generate(&c, C);
    dh_shared(c, A, s3);
    check("an outsider's secret is different", memcmp(s1, s3, 256) != 0);
    uint8_t k1[32], k2[32];
    sha256(s1, 256, k1); sha256(s2, 256, k2);
    check("session keys (SHA-256 of secret) match", memcmp(k1, k2, 32) == 0);
    dh_free(a); dh_free(b); dh_free(c);

    puts("--- SHA-256 known answer ---");
    uint8_t h[32]; char hex[65];
    sha256((const uint8_t *)"abc", 3, h); to_hex(h, 32, hex);
    check("SHA-256(abc) = ba7816bf...", strncmp(hex, "ba7816bf8f01cfea414140de5dae2223", 32) == 0);

    puts("--- RSA signatures ---");
    uint8_t sig[512]; size_t sl = sizeof sig;
    const uint8_t msg[] = "g^a public value";
    check("server signs with its private key", rsa_sign("keys/server_priv.pem", msg, sizeof msg, sig, &sl) == 0);
    check("valid signature verifies", rsa_verify("keys/server_pub.pem", msg, sizeof msg, sig, sl) == 0);
    uint8_t forged[sizeof msg]; memcpy(forged, msg, sizeof msg); forged[0] ^= 1;
    check("modified data fails verification (MITM swap)", rsa_verify("keys/server_pub.pem", forged, sizeof forged, sig, sl) != 0);
    check("another party's key fails verification (spoofing)", rsa_verify("keys/C1_pub.pem", msg, sizeof msg, sig, sl) != 0);
    check("missing key file is an error", rsa_verify("keys/nobody_pub.pem", msg, sizeof msg, sig, sl) != 0);

    puts("--- AES-256-GCM ---");
    uint8_t key[32], iv[12], ct[64], pt[64], tag[16], aad[7] = {1, 0, 0, 0, 1, 0, 5};
    random_bytes(key, 32); random_bytes(iv, 12);
    const char *plain = "R1 1 secret";
    size_t n = strlen(plain);
    check("encrypt", aes_gcm_encrypt(key, iv, aad, 7, (const uint8_t *)plain, n, ct, tag) == 0);
    check("ciphertext differs from plaintext", memcmp(ct, plain, n) != 0);
    check("decrypt gives original text", aes_gcm_decrypt(key, iv, aad, 7, ct, n, tag, pt) == 0 && memcmp(pt, plain, n) == 0);
    uint8_t bad[64]; memcpy(bad, ct, n); bad[2] ^= 0x10;
    check("flipped ciphertext bit is detected", aes_gcm_decrypt(key, iv, aad, 7, bad, n, tag, pt) != 0);
    uint8_t aad2[7]; memcpy(aad2, aad, 7); aad2[4] ^= 1;
    check("modified header (sequence number) is detected", aes_gcm_decrypt(key, iv, aad2, 7, ct, n, tag, pt) != 0);
    uint8_t tag2[16]; memcpy(tag2, tag, 16); tag2[15] ^= 1;
    check("modified tag is detected", aes_gcm_decrypt(key, iv, aad, 7, ct, n, tag2, pt) != 0);
    uint8_t key2[32]; memcpy(key2, key, 32); key2[0] ^= 1;
    check("wrong key is detected", aes_gcm_decrypt(key2, iv, aad, 7, ct, n, tag, pt) != 0);
    uint8_t iv2[12], ctb[64], tagb[16]; random_bytes(iv2, 12);
    aes_gcm_encrypt(key, iv2, aad, 7, (const uint8_t *)plain, n, ctb, tagb);
    check("different IV gives different ciphertext", memcmp(ct, ctb, n) != 0);

    puts("--- HMAC-SHA256 (UDP heartbeat) ---");
    uint8_t m1[32], m2[32], m3[32];
    hmac_sha256(key, (const uint8_t *)"HB C1 1", 7, m1);
    hmac_sha256(key, (const uint8_t *)"HB C1 1", 7, m2);
    hmac_sha256(key, (const uint8_t *)"HB C1 2", 7, m3);
    check("same input -> same MAC", memcmp(m1, m2, 32) == 0);
    check("different sequence number -> different MAC", memcmp(m1, m3, 32) != 0);

    printf("\n%s (%d failed)\n", fails ? "SOME TESTS FAILED" : "ALL CRYPTO TESTS PASSED", fails);
    return fails != 0;
}
