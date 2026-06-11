/*
 * md5_simd.h -- ARM NEON 4-way parallel MD5 (header-only)
 *
 * Hashes 4 independent messages simultaneously using 128-bit NEON registers.
 * Each lane of a uint32x4_t processes a different message.
 *
 * API:
 *   void md5_x4(const uint8_t *data[4], size_t len[4], uint8_t out[4][16])
 *
 * Only compiled when __ARM_NEON is defined; otherwise this header is empty.
 */

#ifndef MD5_SIMD_H
#define MD5_SIMD_H

#ifdef __ARM_NEON

#include <arm_neon.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

/* ── MD5 round constants (T[i] = floor(2^32 * |sin(i+1)|)) ─────── */
static const uint32_t MD5_T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* MD5 per-round shift amounts */
static const int MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

/* MD5 message schedule index per round */
static const int MD5_K[64] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,  /* round 0-15 */
     1, 6,11, 0, 5,10,15, 4, 9,14, 3, 8,13, 2, 7,12,  /* round 16-31 */
     5, 8,11,14, 1, 4, 7,10,13, 0, 3, 6, 9,12,15, 2,  /* round 32-47 */
     0, 7,14, 5,12, 3,10, 1, 8,15, 6,13, 4,11, 2, 9   /* round 48-63 */
};

/* ── NEON rotate left ──────────────────────────────────────────── */
#define NEON_ROTL(x, n) vorrq_u32(vshlq_n_u32((x), (n)), vshrq_n_u32((x), 32 - (n)))

/* ── MD5 F/G/H/I functions (4-way NEON) ──────────────────────── */
static inline uint32x4_t md5_F(uint32x4_t B, uint32x4_t C, uint32x4_t D) {
    return vbslq_u32(B, C, D);  /* (B & C) | (~B & D) */
}
static inline uint32x4_t md5_G(uint32x4_t B, uint32x4_t C, uint32x4_t D) {
    return vbslq_u32(D, B, C);  /* (D & B) | (~D & C) */
}
static inline uint32x4_t md5_H(uint32x4_t B, uint32x4_t C, uint32x4_t D) {
    return veorq_u32(veorq_u32(B, C), D);
}
static inline uint32x4_t md5_I(uint32x4_t B, uint32x4_t C, uint32x4_t D) {
    return veorq_u32(C, vorrq_u32(B, vmvnq_u32(D)));
}

/*
 * Process one 64-byte block for 4 messages in parallel.
 * M[16] contains the 4-way message words (each uint32x4_t has one word per lane).
 * a,b,c,d are the running state (modified in place).
 */
static inline void md5_block_x4(uint32x4_t M[16],
                                  uint32x4_t *a, uint32x4_t *b,
                                  uint32x4_t *c, uint32x4_t *d)
{
    uint32x4_t A = *a, B = *b, C = *c, D = *d;
    uint32x4_t f, tmp;

    /* Unrolling all 64 rounds with a macro for the rotate (which needs
     * compile-time constant shift). We group by round function. */

#define MD5_ROUND(fn, a_, b_, c_, d_, k, s, t) do {          \
    f = fn((b_), (c_), (d_));                                 \
    tmp = vaddq_u32((a_), f);                                 \
    tmp = vaddq_u32(tmp, M[k]);                               \
    tmp = vaddq_u32(tmp, vdupq_n_u32(t));                     \
    tmp = NEON_ROTL(tmp, s);                                  \
    (a_) = vaddq_u32(tmp, (b_));                              \
} while(0)

    /* Rounds 0-15: F */
    MD5_ROUND(md5_F, A,B,C,D,  0, 7, 0xd76aa478);
    MD5_ROUND(md5_F, D,A,B,C,  1,12, 0xe8c7b756);
    MD5_ROUND(md5_F, C,D,A,B,  2,17, 0x242070db);
    MD5_ROUND(md5_F, B,C,D,A,  3,22, 0xc1bdceee);
    MD5_ROUND(md5_F, A,B,C,D,  4, 7, 0xf57c0faf);
    MD5_ROUND(md5_F, D,A,B,C,  5,12, 0x4787c62a);
    MD5_ROUND(md5_F, C,D,A,B,  6,17, 0xa8304613);
    MD5_ROUND(md5_F, B,C,D,A,  7,22, 0xfd469501);
    MD5_ROUND(md5_F, A,B,C,D,  8, 7, 0x698098d8);
    MD5_ROUND(md5_F, D,A,B,C,  9,12, 0x8b44f7af);
    MD5_ROUND(md5_F, C,D,A,B, 10,17, 0xffff5bb1);
    MD5_ROUND(md5_F, B,C,D,A, 11,22, 0x895cd7be);
    MD5_ROUND(md5_F, A,B,C,D, 12, 7, 0x6b901122);
    MD5_ROUND(md5_F, D,A,B,C, 13,12, 0xfd987193);
    MD5_ROUND(md5_F, C,D,A,B, 14,17, 0xa679438e);
    MD5_ROUND(md5_F, B,C,D,A, 15,22, 0x49b40821);

    /* Rounds 16-31: G */
    MD5_ROUND(md5_G, A,B,C,D,  1, 5, 0xf61e2562);
    MD5_ROUND(md5_G, D,A,B,C,  6, 9, 0xc040b340);
    MD5_ROUND(md5_G, C,D,A,B, 11,14, 0x265e5a51);
    MD5_ROUND(md5_G, B,C,D,A,  0,20, 0xe9b6c7aa);
    MD5_ROUND(md5_G, A,B,C,D,  5, 5, 0xd62f105d);
    MD5_ROUND(md5_G, D,A,B,C, 10, 9, 0x02441453);
    MD5_ROUND(md5_G, C,D,A,B, 15,14, 0xd8a1e681);
    MD5_ROUND(md5_G, B,C,D,A,  4,20, 0xe7d3fbc8);
    MD5_ROUND(md5_G, A,B,C,D,  9, 5, 0x21e1cde6);
    MD5_ROUND(md5_G, D,A,B,C, 14, 9, 0xc33707d6);
    MD5_ROUND(md5_G, C,D,A,B,  3,14, 0xf4d50d87);
    MD5_ROUND(md5_G, B,C,D,A,  8,20, 0x455a14ed);
    MD5_ROUND(md5_G, A,B,C,D, 13, 5, 0xa9e3e905);
    MD5_ROUND(md5_G, D,A,B,C,  2, 9, 0xfcefa3f8);
    MD5_ROUND(md5_G, C,D,A,B,  7,14, 0x676f02d9);
    MD5_ROUND(md5_G, B,C,D,A, 12,20, 0x8d2a4c8a);

    /* Rounds 32-47: H */
    MD5_ROUND(md5_H, A,B,C,D,  5, 4, 0xfffa3942);
    MD5_ROUND(md5_H, D,A,B,C,  8,11, 0x8771f681);
    MD5_ROUND(md5_H, C,D,A,B, 11,16, 0x6d9d6122);
    MD5_ROUND(md5_H, B,C,D,A, 14,23, 0xfde5380c);
    MD5_ROUND(md5_H, A,B,C,D,  1, 4, 0xa4beea44);
    MD5_ROUND(md5_H, D,A,B,C,  4,11, 0x4bdecfa9);
    MD5_ROUND(md5_H, C,D,A,B,  7,16, 0xf6bb4b60);
    MD5_ROUND(md5_H, B,C,D,A, 10,23, 0xbebfbc70);
    MD5_ROUND(md5_H, A,B,C,D, 13, 4, 0x289b7ec6);
    MD5_ROUND(md5_H, D,A,B,C,  0,11, 0xeaa127fa);
    MD5_ROUND(md5_H, C,D,A,B,  3,16, 0xd4ef3085);
    MD5_ROUND(md5_H, B,C,D,A,  6,23, 0x04881d05);
    MD5_ROUND(md5_H, A,B,C,D,  9, 4, 0xd9d4d039);
    MD5_ROUND(md5_H, D,A,B,C, 12,11, 0xe6db99e5);
    MD5_ROUND(md5_H, C,D,A,B, 15,16, 0x1fa27cf8);
    MD5_ROUND(md5_H, B,C,D,A,  2,23, 0xc4ac5665);

    /* Rounds 48-63: I */
    MD5_ROUND(md5_I, A,B,C,D,  0, 6, 0xf4292244);
    MD5_ROUND(md5_I, D,A,B,C,  7,10, 0x432aff97);
    MD5_ROUND(md5_I, C,D,A,B, 14,15, 0xab9423a7);
    MD5_ROUND(md5_I, B,C,D,A,  5,21, 0xfc93a039);
    MD5_ROUND(md5_I, A,B,C,D, 12, 6, 0x655b59c3);
    MD5_ROUND(md5_I, D,A,B,C,  3,10, 0x8f0ccc92);
    MD5_ROUND(md5_I, C,D,A,B, 10,15, 0xffeff47d);
    MD5_ROUND(md5_I, B,C,D,A,  1,21, 0x85845dd1);
    MD5_ROUND(md5_I, A,B,C,D,  8, 6, 0x6fa87e4f);
    MD5_ROUND(md5_I, D,A,B,C, 15,10, 0xfe2ce6e0);
    MD5_ROUND(md5_I, C,D,A,B,  6,15, 0xa3014314);
    MD5_ROUND(md5_I, B,C,D,A, 13,21, 0x4e0811a1);
    MD5_ROUND(md5_I, A,B,C,D,  4, 6, 0xf7537e82);
    MD5_ROUND(md5_I, D,A,B,C, 11,10, 0xbd3af235);
    MD5_ROUND(md5_I, C,D,A,B,  2,15, 0x2ad7d2bb);
    MD5_ROUND(md5_I, B,C,D,A,  9,21, 0xeb86d391);

#undef MD5_ROUND

    *a = vaddq_u32(*a, A);
    *b = vaddq_u32(*b, B);
    *c = vaddq_u32(*c, C);
    *d = vaddq_u32(*d, D);
}

/*
 * md5_x4 -- Hash 4 messages in parallel using NEON.
 *
 * CONTRACT: All four lanes MUST have the same length (same block count after
 * padding). The re-pad path that normalises lanes to max_blocks is only valid
 * when every lane already produces the same block count; giving lanes with
 * differing lengths produces wrong digests for the shorter lanes.
 * Maximum supported message length: 512 bytes (plenty for PDF key derivation
 * where messages are <= 84 bytes).
 *
 * data[i] points to the i-th message (length len[i]).
 * out[i] receives the 16-byte MD5 digest for message i.
 */
static inline void md5_x4(const uint8_t *data[4], size_t len[4],
                           uint8_t out[4][16])
{
    /* Contract: all four lanes must have equal length (same block count).
     * The re-pad path is only valid under that assumption. */
    assert(len[0] == len[1] && len[1] == len[2] && len[2] == len[3]);
    /* Pad each message individually into aligned buffers.
     * Max padded size: ceil((512 + 9) / 64) * 64 = 576 bytes = 9 blocks */
    uint8_t padded[4][576];
    int nblocks[4];

    for (int i = 0; i < 4; i++) {
        size_t mlen = len[i];
        if (mlen > 512) mlen = 512;  /* safety cap */
        memcpy(padded[i], data[i], mlen);

        /* MD5 padding: append 0x80, then zeros, then 64-bit LE length */
        size_t pad_pos = mlen;
        padded[i][pad_pos++] = 0x80;

        /* Pad to 56 mod 64 */
        size_t target = (mlen + 9 + 63) & ~(size_t)63;
        memset(padded[i] + pad_pos, 0, target - pad_pos);

        /* Append bit length as 64-bit LE at end of last block */
        uint64_t bit_len = (uint64_t)mlen * 8;
        memcpy(padded[i] + target - 8, &bit_len, 8);

        nblocks[i] = (int)(target / 64);
    }

    /* Find max block count (all lanes must process same number of blocks,
     * but extra blocks for shorter messages are just zero-padded which
     * won't affect the result since we already did proper MD5 padding) */
    int max_blocks = nblocks[0];
    for (int i = 1; i < 4; i++)
        if (nblocks[i] > max_blocks) max_blocks = nblocks[i];

    /* Zero-fill any blocks beyond each message's padding (so the state
     * isn't corrupted -- but actually we need to handle this differently:
     * after the proper padding, extra blocks would change the hash.
     * Instead, we'll process each lane's correct number of blocks and
     * save/restore state for shorter messages.) */

    /* Simpler approach: all messages get padded to the same number of blocks.
     * Re-pad everyone to max_blocks * 64 bytes. */
    for (int i = 0; i < 4; i++) {
        if (nblocks[i] < max_blocks) {
            /* Re-pad this message to max_blocks * 64 */
            size_t mlen = len[i];
            if (mlen > 512) mlen = 512;
            size_t new_target = (size_t)max_blocks * 64;
            memset(padded[i], 0, new_target);
            memcpy(padded[i], data[i], mlen);
            padded[i][mlen] = 0x80;
            uint64_t bit_len = (uint64_t)mlen * 8;
            memcpy(padded[i] + new_target - 8, &bit_len, 8);
            nblocks[i] = max_blocks;
        }
    }

    /* Initialize MD5 state */
    uint32x4_t a = vdupq_n_u32(0x67452301);
    uint32x4_t b = vdupq_n_u32(0xefcdab89);
    uint32x4_t c = vdupq_n_u32(0x98badcfe);
    uint32x4_t d = vdupq_n_u32(0x10325476);

    /* Process blocks */
    for (int blk = 0; blk < max_blocks; blk++) {
        uint32x4_t M[16];

        /* Load 16 message words, interleaving 4 messages into NEON lanes */
        for (int w = 0; w < 16; w++) {
            uint32_t w0, w1, w2, w3;
            memcpy(&w0, padded[0] + blk * 64 + w * 4, 4);
            memcpy(&w1, padded[1] + blk * 64 + w * 4, 4);
            memcpy(&w2, padded[2] + blk * 64 + w * 4, 4);
            memcpy(&w3, padded[3] + blk * 64 + w * 4, 4);
            uint32_t vals[4] = { w0, w1, w2, w3 };
            M[w] = vld1q_u32(vals);
        }

        md5_block_x4(M, &a, &b, &c, &d);
    }

    /* Extract results from lanes */
    uint32_t ra[4], rb[4], rc[4], rd[4];
    vst1q_u32(ra, a);
    vst1q_u32(rb, b);
    vst1q_u32(rc, c);
    vst1q_u32(rd, d);

    for (int i = 0; i < 4; i++) {
        memcpy(out[i] + 0,  &ra[i], 4);
        memcpy(out[i] + 4,  &rb[i], 4);
        memcpy(out[i] + 8,  &rc[i], 4);
        memcpy(out[i] + 12, &rd[i], 4);
    }
}

/*
 * md5_x4_oneshot -- Hash 4 messages that share the same length.
 * Slightly faster path when all messages have equal length.
 */
static inline void md5_x4_oneshot(const uint8_t *data[4], size_t len,
                                   uint8_t out[4][16])
{
    size_t lens[4] = { len, len, len, len };
    md5_x4(data, lens, out);
}

/*
 * md5_x4_short -- Hash 4 short buffers (up to 55 bytes each, single block).
 * This is the fast path for the 50-iteration MD5 loop in Algorithm 2
 * where each hash input is <= 16 bytes.
 */
static inline void md5_x4_short(const uint8_t bufs[4][64], size_t len,
                                  uint8_t out[4][16])
{
    /* Build single padded block for each message */
    uint8_t padded[4][64];
    for (int i = 0; i < 4; i++) {
        memcpy(padded[i], bufs[i], len);
        memset(padded[i] + len, 0, 64 - len);
        padded[i][len] = 0x80;
        uint64_t bit_len = (uint64_t)len * 8;
        memcpy(padded[i] + 56, &bit_len, 8);
    }

    uint32x4_t a = vdupq_n_u32(0x67452301);
    uint32x4_t b = vdupq_n_u32(0xefcdab89);
    uint32x4_t c = vdupq_n_u32(0x98badcfe);
    uint32x4_t d = vdupq_n_u32(0x10325476);

    uint32x4_t M[16];
    for (int w = 0; w < 16; w++) {
        uint32_t w0, w1, w2, w3;
        memcpy(&w0, padded[0] + w * 4, 4);
        memcpy(&w1, padded[1] + w * 4, 4);
        memcpy(&w2, padded[2] + w * 4, 4);
        memcpy(&w3, padded[3] + w * 4, 4);
        uint32_t vals[4] = { w0, w1, w2, w3 };
        M[w] = vld1q_u32(vals);
    }

    md5_block_x4(M, &a, &b, &c, &d);

    uint32_t ra[4], rb[4], rc[4], rd[4];
    vst1q_u32(ra, a);
    vst1q_u32(rb, b);
    vst1q_u32(rc, c);
    vst1q_u32(rd, d);

    for (int i = 0; i < 4; i++) {
        memcpy(out[i] + 0,  &ra[i], 4);
        memcpy(out[i] + 4,  &rb[i], 4);
        memcpy(out[i] + 8,  &rc[i], 4);
        memcpy(out[i] + 12, &rd[i], 4);
    }
}

#endif /* __ARM_NEON */
#endif /* MD5_SIMD_H */
