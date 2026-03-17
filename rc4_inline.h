/*
 * rc4_inline.h -- Fast inline RC4 for small inputs (header-only)
 *
 * Replaces CommonCrypto CCCrypt(kCCAlgorithmRC4) for PDF password
 * verification where inputs are 16 or 32 bytes. Eliminates function
 * call overhead (~20 CCCrypt calls per R3/R4 password).
 *
 * API:
 *   rc4_encrypt(key, key_len, in, out, data_len)  -- general
 *   rc4_encrypt_16(key, key_len, in, out)          -- 16-byte specialization
 *   rc4_first_byte(key, key_len, first_in)         -- first byte only (early exit)
 */

#ifndef RC4_INLINE_H
#define RC4_INLINE_H

#include <stdint.h>
#include <string.h>

/* ── KSA: Key Scheduling Algorithm ────────────────────────────── */
static inline void rc4_init(uint8_t S[256], const uint8_t *key, int key_len)
{
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    uint8_t j = 0;
    /* Unroll for common key lengths to avoid modulo */
    if (key_len == 16) {
        for (int i = 0; i < 256; i++) {
            j = j + S[i] + key[i & 0x0F];
            uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        }
    } else if (key_len == 5) {
        /* Expand 5-byte key to avoid repeated modulo */
        uint8_t ek[260];
        for (int i = 0; i < 256; i += 5) {
            memcpy(ek + i, key, 5);
        }
        ek[255] = key[0]; /* handle 256 % 5 = 1 leftover */
        for (int i = 0; i < 256; i++) {
            j = j + S[i] + ek[i];
            uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        }
    } else {
        for (int i = 0; i < 256; i++) {
            j = j + S[i] + key[i % key_len];
            uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        }
    }
}

/* ── PRGA + XOR encrypt/decrypt ───────────────────────────────── */
static inline void rc4_crypt(uint8_t S[256], const uint8_t *in,
                             uint8_t *out, int len)
{
    uint8_t i = 0, j = 0;
    for (int k = 0; k < len; k++) {
        i++;
        j = j + S[i];
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        out[k] = in[k] ^ S[(uint8_t)(S[i] + S[j])];
    }
}

/* ── Combined KSA+PRGA for general use ────────────────────────── */
static inline void rc4_encrypt(const uint8_t *key, int key_len,
                               const uint8_t *in, uint8_t *out, int data_len)
{
    uint8_t S[256];
    rc4_init(S, key, key_len);
    rc4_crypt(S, in, out, data_len);
}

/* ── Specialized 16-byte version (R3/R4 hot path) ─────────────── */
static inline void rc4_encrypt_16(const uint8_t *key, int key_len,
                                  const uint8_t *in, uint8_t *out)
{
    uint8_t S[256];
    rc4_init(S, key, key_len);
    uint8_t i = 0, j = 0;
    for (int k = 0; k < 16; k++) {
        i++;
        j = j + S[i];
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        out[k] = in[k] ^ S[(uint8_t)(S[i] + S[j])];
    }
}

/* ── First byte only (for early-exit filtering) ───────────────── */
static inline uint8_t rc4_first_byte(const uint8_t *key, int key_len,
                                     uint8_t first_in)
{
    uint8_t S[256];
    rc4_init(S, key, key_len);
    /* PRGA: generate exactly 1 keystream byte */
    uint8_t j = S[1];
    uint8_t tmp = S[1]; S[1] = S[j]; S[j] = tmp;
    return first_in ^ S[(uint8_t)(S[1] + S[j])];
}

#endif /* RC4_INLINE_H */
