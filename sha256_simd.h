/*
 * sha256_simd.h -- ARM NEON SHA-256 acceleration (header-only)
 *
 * Uses ARM Crypto Extensions (vsha256hq_u32 etc.) for SHA-256.
 * SHA-384/512 are left to CommonCrypto which already uses hardware SHA-512.
 *
 * API:
 *   void sha256_hash_neon(const uint8_t *data, size_t len, uint8_t *out)
 *
 * Only compiled when __ARM_NEON and __ARM_FEATURE_SHA2 are defined.
 */

#ifndef SHA256_SIMD_H
#define SHA256_SIMD_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)

#include <arm_neon.h>

/* ── SHA-256 round constants ──────────────────────────────────── */
static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Process one 64-byte block of SHA-256 using ARM Crypto Extensions.
 *
 * The ARM SHA-256 intrinsics work on the state as two uint32x4_t:
 *   ABCD = {A, B, C, D}
 *   EFGH = {E, F, G, H}
 *
 * vsha256hq_u32(ABCD, EFGH, schedule_word) updates ABCD
 * vsha256h2q_u32(EFGH, ABCD_old, schedule_word) updates EFGH
 * vsha256su0q_u32 / vsha256su1q_u32 extend the message schedule
 */
static inline void sha256_block_neon(uint32x4_t *state0, uint32x4_t *state1,
                                      const uint8_t block[64])
{
    /* Load message words as big-endian uint32 */
    uint32x4_t msg0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block +  0)));
    uint32x4_t msg1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    uint32x4_t msg2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    uint32x4_t msg3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    /* Save original state */
    uint32x4_t abcd_save = *state0;
    uint32x4_t efgh_save = *state1;

    uint32x4_t tmp0, tmp1, tmp2;

    /* Rounds 0-3 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&SHA256_K[0]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg0 = vsha256su0q_u32(msg0, msg1);

    /* Rounds 4-7 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&SHA256_K[4]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);
    msg1 = vsha256su0q_u32(msg1, msg2);

    /* Rounds 8-11 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&SHA256_K[8]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);
    msg2 = vsha256su0q_u32(msg2, msg3);

    /* Rounds 12-15 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&SHA256_K[12]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);
    msg3 = vsha256su0q_u32(msg3, msg0);

    /* Rounds 16-19 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&SHA256_K[16]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);
    msg0 = vsha256su0q_u32(msg0, msg1);

    /* Rounds 20-23 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&SHA256_K[20]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);
    msg1 = vsha256su0q_u32(msg1, msg2);

    /* Rounds 24-27 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&SHA256_K[24]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);
    msg2 = vsha256su0q_u32(msg2, msg3);

    /* Rounds 28-31 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&SHA256_K[28]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);
    msg3 = vsha256su0q_u32(msg3, msg0);

    /* Rounds 32-35 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&SHA256_K[32]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);
    msg0 = vsha256su0q_u32(msg0, msg1);

    /* Rounds 36-39 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&SHA256_K[36]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);
    msg1 = vsha256su0q_u32(msg1, msg2);

    /* Rounds 40-43 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&SHA256_K[40]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);
    msg2 = vsha256su0q_u32(msg2, msg3);

    /* Rounds 44-47 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&SHA256_K[44]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);
    msg3 = vsha256su0q_u32(msg3, msg0);

    /* Rounds 48-51 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&SHA256_K[48]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);

    /* Rounds 52-55 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&SHA256_K[52]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);

    /* Rounds 56-59 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&SHA256_K[56]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);

    /* Rounds 60-63 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&SHA256_K[60]));
    tmp1 = *state0;
    tmp2 = *state1;
    *state0 = vsha256hq_u32(*state0, *state1, tmp0);
    *state1 = vsha256h2q_u32(tmp2, tmp1, tmp0);

    /* Add saved state */
    *state0 = vaddq_u32(*state0, abcd_save);
    *state1 = vaddq_u32(*state1, efgh_save);
}

/*
 * sha256_hash_neon -- Full SHA-256 hash with padding.
 * Handles arbitrary length input. Output is 32 bytes.
 */
static inline void sha256_hash_neon(const uint8_t *data, size_t len,
                                     uint8_t *out)
{
    /* SHA-256 initial hash values */
    uint32x4_t state0 = (uint32x4_t){0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a};
    uint32x4_t state1 = (uint32x4_t){0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    /* Process complete 64-byte blocks */
    size_t offset = 0;
    while (offset + 64 <= len) {
        sha256_block_neon(&state0, &state1, data + offset);
        offset += 64;
    }

    /* Final block(s) with padding */
    size_t remaining = len - offset;
    uint8_t pad_block[128]; /* up to 2 blocks for padding */
    memset(pad_block, 0, 128);
    if (remaining > 0)
        memcpy(pad_block, data + offset, remaining);
    pad_block[remaining] = 0x80;

    /* Bit length as big-endian 64-bit */
    uint64_t bit_len = (uint64_t)len * 8;
    if (remaining >= 56) {
        /* Need two blocks */
        pad_block[120] = (uint8_t)(bit_len >> 56);
        pad_block[121] = (uint8_t)(bit_len >> 48);
        pad_block[122] = (uint8_t)(bit_len >> 40);
        pad_block[123] = (uint8_t)(bit_len >> 32);
        pad_block[124] = (uint8_t)(bit_len >> 24);
        pad_block[125] = (uint8_t)(bit_len >> 16);
        pad_block[126] = (uint8_t)(bit_len >>  8);
        pad_block[127] = (uint8_t)(bit_len);
        sha256_block_neon(&state0, &state1, pad_block);
        sha256_block_neon(&state0, &state1, pad_block + 64);
    } else {
        /* Fits in one block */
        pad_block[56] = (uint8_t)(bit_len >> 56);
        pad_block[57] = (uint8_t)(bit_len >> 48);
        pad_block[58] = (uint8_t)(bit_len >> 40);
        pad_block[59] = (uint8_t)(bit_len >> 32);
        pad_block[60] = (uint8_t)(bit_len >> 24);
        pad_block[61] = (uint8_t)(bit_len >> 16);
        pad_block[62] = (uint8_t)(bit_len >>  8);
        pad_block[63] = (uint8_t)(bit_len);
        sha256_block_neon(&state0, &state1, pad_block);
    }

    /* Store result as big-endian */
    vst1q_u8(out,      vrev32q_u8(vreinterpretq_u8_u32(state0)));
    vst1q_u8(out + 16, vrev32q_u8(vreinterpretq_u8_u32(state1)));
}

#endif /* __ARM_NEON && __ARM_FEATURE_SHA2 */
#endif /* SHA256_SIMD_H */
