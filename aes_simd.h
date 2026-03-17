/*
 * aes_simd.h -- ARM NEON AES-128-CBC encrypt (header-only)
 *
 * Uses ARM Crypto Extensions (vaeseq_u8, vaesmcq_u8) for AES.
 *
 * API:
 *   void aes128_cbc_encrypt_neon(const uint8_t key[16], const uint8_t iv[16],
 *                                 const uint8_t *in, size_t len, uint8_t *out)
 *
 * Only compiled when __ARM_NEON and __ARM_FEATURE_CRYPTO are defined.
 */

#ifndef AES_SIMD_H
#define AES_SIMD_H

#include <stdint.h>
#include <stddef.h>

#if defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)

#include <arm_neon.h>

/* ── AES-128 key expansion ────────────────────────────────────── */

/* AES round constants */
static const uint8_t AES_RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/*
 * Expand a 16-byte AES-128 key into 11 round keys.
 *
 * We use vaeseq_u8 with a zero key to get SubBytes on the rotated word:
 * vaeseq_u8(data, zero) does AddRoundKey(zero) + SubBytes + ShiftRows
 * We only need SubBytes on the last column, so we work around ShiftRows.
 */
static inline void aes128_expand_key_neon(const uint8_t key[16],
                                           uint8x16_t rk[11])
{
    rk[0] = vld1q_u8(key);

    uint8x16_t zero = vdupq_n_u8(0);

    for (int i = 0; i < 10; i++) {
        /* Get the last 4 bytes of previous round key */
        uint32_t prev_last;
        vst1q_lane_u32(&prev_last, vreinterpretq_u32_u8(rk[i]), 3);

        /* RotWord: rotate left by 1 byte */
        uint32_t rotated = (prev_last >> 8) | (prev_last << 24);

        /* SubBytes via vaeseq_u8: put the word in position and apply AESE
         * which does SubBytes + ShiftRows. Since we only care about 4 bytes
         * and ShiftRows moves bytes around, we'll use a simpler approach. */

        /* Put rotated word into all 4 positions of a vector */
        uint8_t rot_bytes[16] = {0};
        rot_bytes[0] = (uint8_t)(rotated);
        rot_bytes[1] = (uint8_t)(rotated >> 8);
        rot_bytes[2] = (uint8_t)(rotated >> 16);
        rot_bytes[3] = (uint8_t)(rotated >> 24);
        /* Duplicate to all lanes to survive ShiftRows */
        rot_bytes[4] = rot_bytes[0]; rot_bytes[5] = rot_bytes[1];
        rot_bytes[6] = rot_bytes[2]; rot_bytes[7] = rot_bytes[3];
        rot_bytes[8] = rot_bytes[0]; rot_bytes[9] = rot_bytes[1];
        rot_bytes[10] = rot_bytes[2]; rot_bytes[11] = rot_bytes[3];
        rot_bytes[12] = rot_bytes[0]; rot_bytes[13] = rot_bytes[1];
        rot_bytes[14] = rot_bytes[2]; rot_bytes[15] = rot_bytes[3];

        uint8x16_t sub_input = vld1q_u8(rot_bytes);
        /* vaeseq_u8 does: AddRoundKey(zero) + SubBytes + ShiftRows
         * Since key is zero, AddRoundKey is identity.
         * SubBytes applies S-box to each byte.
         * ShiftRows shifts rows: row0 no shift, row1 shift 1, row2 shift 2, row3 shift 3
         * Since all columns are identical, ShiftRows has no visible effect. */
        uint8x16_t sub_result = vaeseq_u8(sub_input, zero);

        /* Extract the first 4 bytes (which have SubBytes applied) */
        uint32_t sub_word;
        vst1q_lane_u32(&sub_word, vreinterpretq_u32_u8(sub_result), 0);

        /* XOR with rcon */
        sub_word ^= (uint32_t)AES_RCON[i];

        /* Generate round key: each word = prev_word ^ sub_word */
        uint32_t w[4];
        vst1q_u32(w, vreinterpretq_u32_u8(rk[i]));
        w[0] ^= sub_word;
        w[1] ^= w[0];
        w[2] ^= w[1];
        w[3] ^= w[2];
        rk[i+1] = vreinterpretq_u8_u32(vld1q_u32(w));
    }
}

/*
 * AES-128-CBC encrypt using ARM Crypto Extensions.
 *
 * Input length must be a multiple of 16 (no padding performed).
 * Can work in-place (out == in).
 */
static inline void aes128_cbc_encrypt_neon(const uint8_t key[16],
                                            const uint8_t iv[16],
                                            const uint8_t *in, size_t len,
                                            uint8_t *out)
{
    /* Expand key */
    uint8x16_t rk[11];
    aes128_expand_key_neon(key, rk);

    /* CBC mode: each block is XOR'd with previous ciphertext then encrypted */
    uint8x16_t feedback = vld1q_u8(iv);
    size_t nblocks = len / 16;

    for (size_t b = 0; b < nblocks; b++) {
        uint8x16_t block = vld1q_u8(in + b * 16);
        block = veorq_u8(block, feedback); /* CBC XOR */

        /* AES-128 encrypt: 9 full rounds + 1 final round
         *
         * vaeseq_u8(block, rk) does: block ^= rk (AddRoundKey), then SubBytes, then ShiftRows
         * vaesmcq_u8(block) does: MixColumns
         *
         * For rounds 0-8: AESE + AESMC
         * For round 9 (final): AESE only, then XOR with final round key
         */
        block = vaesmcq_u8(vaeseq_u8(block, rk[0]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[1]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[2]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[3]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[4]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[5]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[6]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[7]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[8]));
        /* Final round: AESE + XOR with last round key (no MixColumns) */
        block = veorq_u8(vaeseq_u8(block, rk[9]), rk[10]);

        vst1q_u8(out + b * 16, block);
        feedback = block;
    }
}

/*
 * AES-128-CBC encrypt in-place with pre-expanded round keys.
 * Avoids key expansion overhead when the same key is used repeatedly.
 */
static inline void aes128_cbc_encrypt_inplace_rk(const uint8x16_t rk[11],
                                                   const uint8_t iv[16],
                                                   uint8_t *data, size_t len)
{
    uint8x16_t feedback = vld1q_u8(iv);
    size_t nblocks = len / 16;

    for (size_t b = 0; b < nblocks; b++) {
        uint8x16_t block = vld1q_u8(data + b * 16);
        block = veorq_u8(block, feedback);

        block = vaesmcq_u8(vaeseq_u8(block, rk[0]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[1]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[2]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[3]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[4]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[5]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[6]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[7]));
        block = vaesmcq_u8(vaeseq_u8(block, rk[8]));
        block = veorq_u8(vaeseq_u8(block, rk[9]), rk[10]);

        vst1q_u8(data + b * 16, block);
        feedback = block;
    }
}

#endif /* __ARM_NEON && __ARM_FEATURE_CRYPTO */
#endif /* AES_SIMD_H */
