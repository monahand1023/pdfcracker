/*
 * sha512_simd.h -- ARM NEON SHA-512/SHA-384 acceleration (header-only)
 *
 * Uses ARM Crypto Extensions (vsha512hq_u64 etc.) for SHA-512 and SHA-384.
 * Requires ARMv8.2-A SHA-512 instructions.
 *
 * API:
 *   void sha512_hash_neon(const uint8_t *data, size_t len, uint8_t *out)  // 64-byte output
 *   void sha384_hash_neon(const uint8_t *data, size_t len, uint8_t *out)  // 48-byte output
 *
 * Only compiled when __ARM_NEON and __ARM_FEATURE_SHA512 are defined.
 */

#ifndef SHA512_SIMD_H
#define SHA512_SIMD_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA512)

#include <arm_neon.h>

/* -- SHA-512 round constants ------------------------------------------------ */
static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/*
 * Process one 128-byte block of SHA-512 using ARM SHA-512 Crypto Extensions.
 *
 * State: ab={A,B}, cd={C,D}, ef={E,F}, gh={G,H}
 *
 * The ARM SHA-512 intrinsics process 2 rounds at a time using a 4-phase cycle:
 *   Phase A: updates gh (via SHA512H2) and cd (via add-back)
 *   Phase B: updates ef and ab
 *   Phase C: updates cd and gh
 *   Phase D: updates ab and ef
 *
 * Key difference from SHA-256 intrinsics: the K+W values must have state
 * values pre-added, and vextq_u64 constructs overlapping pairs {F,G}, {D,E}.
 */
static inline void sha512_block_neon(uint64x2_t *state0, uint64x2_t *state1,
                                      uint64x2_t *state2, uint64x2_t *state3,
                                      const uint8_t block[128])
{
    /* Load 16 message words as big-endian uint64 */
    uint64x2_t s0 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block +   0)));
    uint64x2_t s1 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block +  16)));
    uint64x2_t s2 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block +  32)));
    uint64x2_t s3 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block +  48)));
    uint64x2_t s4 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block +  64)));
    uint64x2_t s5 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block +  80)));
    uint64x2_t s6 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block +  96)));
    uint64x2_t s7 = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block + 112)));

    uint64x2_t ab = *state0, cd = *state1, ef = *state2, gh = *state3;
    uint64x2_t ab_save = ab, cd_save = cd, ef_save = ef, gh_save = gh;

    uint64x2_t initial_sum, sum, intermed;

    /* -- Rounds 0-15: no message schedule extension needed -- */

    /* Rounds 0-1 (Phase A) */
    initial_sum = vaddq_u64(s0, vld1q_u64(&SHA512_K[0]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 2-3 (Phase B) */
    initial_sum = vaddq_u64(s1, vld1q_u64(&SHA512_K[2]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 4-5 (Phase C) */
    initial_sum = vaddq_u64(s2, vld1q_u64(&SHA512_K[4]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 6-7 (Phase D) */
    initial_sum = vaddq_u64(s3, vld1q_u64(&SHA512_K[6]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 8-9 (Phase A) */
    initial_sum = vaddq_u64(s4, vld1q_u64(&SHA512_K[8]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 10-11 (Phase B) */
    initial_sum = vaddq_u64(s5, vld1q_u64(&SHA512_K[10]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 12-13 (Phase C) */
    initial_sum = vaddq_u64(s6, vld1q_u64(&SHA512_K[12]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 14-15 (Phase D) */
    initial_sum = vaddq_u64(s7, vld1q_u64(&SHA512_K[14]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* -- Rounds 16-79: with message schedule extension -- */

    /* Rounds 16-17 (Phase A) */
    s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
    initial_sum = vaddq_u64(s0, vld1q_u64(&SHA512_K[16]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 18-19 (Phase B) */
    s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
    initial_sum = vaddq_u64(s1, vld1q_u64(&SHA512_K[18]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 20-21 (Phase C) */
    s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
    initial_sum = vaddq_u64(s2, vld1q_u64(&SHA512_K[20]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 22-23 (Phase D) */
    s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
    initial_sum = vaddq_u64(s3, vld1q_u64(&SHA512_K[22]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 24-25 (Phase A) */
    s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
    initial_sum = vaddq_u64(s4, vld1q_u64(&SHA512_K[24]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 26-27 (Phase B) */
    s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
    initial_sum = vaddq_u64(s5, vld1q_u64(&SHA512_K[26]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 28-29 (Phase C) */
    s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
    initial_sum = vaddq_u64(s6, vld1q_u64(&SHA512_K[28]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 30-31 (Phase D) */
    s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
    initial_sum = vaddq_u64(s7, vld1q_u64(&SHA512_K[30]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 32-33 (Phase A) */
    s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
    initial_sum = vaddq_u64(s0, vld1q_u64(&SHA512_K[32]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 34-35 (Phase B) */
    s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
    initial_sum = vaddq_u64(s1, vld1q_u64(&SHA512_K[34]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 36-37 (Phase C) */
    s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
    initial_sum = vaddq_u64(s2, vld1q_u64(&SHA512_K[36]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 38-39 (Phase D) */
    s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
    initial_sum = vaddq_u64(s3, vld1q_u64(&SHA512_K[38]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 40-41 (Phase A) */
    s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
    initial_sum = vaddq_u64(s4, vld1q_u64(&SHA512_K[40]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 42-43 (Phase B) */
    s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
    initial_sum = vaddq_u64(s5, vld1q_u64(&SHA512_K[42]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 44-45 (Phase C) */
    s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
    initial_sum = vaddq_u64(s6, vld1q_u64(&SHA512_K[44]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 46-47 (Phase D) */
    s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
    initial_sum = vaddq_u64(s7, vld1q_u64(&SHA512_K[46]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 48-49 (Phase A) */
    s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
    initial_sum = vaddq_u64(s0, vld1q_u64(&SHA512_K[48]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 50-51 (Phase B) */
    s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
    initial_sum = vaddq_u64(s1, vld1q_u64(&SHA512_K[50]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 52-53 (Phase C) */
    s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
    initial_sum = vaddq_u64(s2, vld1q_u64(&SHA512_K[52]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 54-55 (Phase D) */
    s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
    initial_sum = vaddq_u64(s3, vld1q_u64(&SHA512_K[54]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 56-57 (Phase A) */
    s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
    initial_sum = vaddq_u64(s4, vld1q_u64(&SHA512_K[56]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 58-59 (Phase B) */
    s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
    initial_sum = vaddq_u64(s5, vld1q_u64(&SHA512_K[58]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 60-61 (Phase C) */
    s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
    initial_sum = vaddq_u64(s6, vld1q_u64(&SHA512_K[60]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 62-63 (Phase D) */
    s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
    initial_sum = vaddq_u64(s7, vld1q_u64(&SHA512_K[62]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 64-65 (Phase A) */
    s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
    initial_sum = vaddq_u64(s0, vld1q_u64(&SHA512_K[64]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 66-67 (Phase B) */
    s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
    initial_sum = vaddq_u64(s1, vld1q_u64(&SHA512_K[66]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 68-69 (Phase C) */
    s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
    initial_sum = vaddq_u64(s2, vld1q_u64(&SHA512_K[68]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 70-71 (Phase D) */
    s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
    initial_sum = vaddq_u64(s3, vld1q_u64(&SHA512_K[70]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Rounds 72-73 (Phase A) */
    s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
    initial_sum = vaddq_u64(s4, vld1q_u64(&SHA512_K[72]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    intermed = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
    gh = vsha512h2q_u64(intermed, cd, ab);
    cd = vaddq_u64(cd, intermed);

    /* Rounds 74-75 (Phase B) */
    s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
    initial_sum = vaddq_u64(s5, vld1q_u64(&SHA512_K[74]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ef);
    intermed = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
    ef = vsha512h2q_u64(intermed, ab, gh);
    ab = vaddq_u64(ab, intermed);

    /* Rounds 76-77 (Phase C) */
    s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
    initial_sum = vaddq_u64(s6, vld1q_u64(&SHA512_K[76]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), cd);
    intermed = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
    cd = vsha512h2q_u64(intermed, gh, ef);
    gh = vaddq_u64(gh, intermed);

    /* Rounds 78-79 (Phase D) */
    s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
    initial_sum = vaddq_u64(s7, vld1q_u64(&SHA512_K[78]));
    sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), ab);
    intermed = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
    ab = vsha512h2q_u64(intermed, ef, cd);
    ef = vaddq_u64(ef, intermed);

    /* Add saved state */
    *state0 = vaddq_u64(ab, ab_save);
    *state1 = vaddq_u64(cd, cd_save);
    *state2 = vaddq_u64(ef, ef_save);
    *state3 = vaddq_u64(gh, gh_save);
}

/*
 * Internal helper: store a uint64 as big-endian bytes.
 */
static inline void sha512_store_be64(uint8_t *dst, uint64_t val)
{
    dst[0] = (uint8_t)(val >> 56);
    dst[1] = (uint8_t)(val >> 48);
    dst[2] = (uint8_t)(val >> 40);
    dst[3] = (uint8_t)(val >> 32);
    dst[4] = (uint8_t)(val >> 24);
    dst[5] = (uint8_t)(val >> 16);
    dst[6] = (uint8_t)(val >>  8);
    dst[7] = (uint8_t)(val);
}

/*
 * Internal helper: SHA-512 core with configurable IV.
 * Handles arbitrary length input with proper MD padding for 128-byte blocks.
 * Writes full 64-byte (512-bit) digest to out.
 */
static inline void sha512_hash_neon_iv(const uint8_t *data, size_t len,
                                        uint8_t *out,
                                        uint64x2_t state0, uint64x2_t state1,
                                        uint64x2_t state2, uint64x2_t state3)
{
    /* Process complete 128-byte blocks */
    size_t offset = 0;
    while (offset + 128 <= len) {
        sha512_block_neon(&state0, &state1, &state2, &state3, data + offset);
        offset += 128;
    }

    /* Final block(s) with padding.
     * SHA-512 uses 128-byte blocks.  Padding: append 0x80, then zeros,
     * then 128-bit big-endian bit length.  The length field occupies
     * the last 16 bytes of the final block.  If remaining data + 1 (0x80)
     * + 16 (length) > 128, we need two padding blocks. */
    size_t remaining = len - offset;
    uint8_t pad_block[256]; /* up to 2 blocks for padding */
    memset(pad_block, 0, 256);
    if (remaining > 0)
        memcpy(pad_block, data + offset, remaining);
    pad_block[remaining] = 0x80;

    /* Bit length as big-endian 128-bit.  We only support up to 2^64 - 1
     * bytes of input, so the high 64 bits are always zero. */
    uint64_t bit_len = (uint64_t)len * 8;

    if (remaining >= 112) {
        /* Need two padding blocks */
        sha512_store_be64(pad_block + 248, bit_len);
        sha512_block_neon(&state0, &state1, &state2, &state3, pad_block);
        sha512_block_neon(&state0, &state1, &state2, &state3, pad_block + 128);
    } else {
        /* Fits in one block */
        sha512_store_be64(pad_block + 120, bit_len);
        sha512_block_neon(&state0, &state1, &state2, &state3, pad_block);
    }

    /* Store result as big-endian */
    vst1q_u8(out,      vrev64q_u8(vreinterpretq_u8_u64(state0)));
    vst1q_u8(out + 16, vrev64q_u8(vreinterpretq_u8_u64(state1)));
    vst1q_u8(out + 32, vrev64q_u8(vreinterpretq_u8_u64(state2)));
    vst1q_u8(out + 48, vrev64q_u8(vreinterpretq_u8_u64(state3)));
}

/*
 * sha512_hash_neon -- Full SHA-512 hash with padding.
 * Handles arbitrary length input. Output is 64 bytes.
 */
static inline void sha512_hash_neon(const uint8_t *data, size_t len,
                                     uint8_t *out)
{
    /* SHA-512 initial hash values */
    uint64x2_t state0 = (uint64x2_t){0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL};
    uint64x2_t state1 = (uint64x2_t){0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL};
    uint64x2_t state2 = (uint64x2_t){0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL};
    uint64x2_t state3 = (uint64x2_t){0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    sha512_hash_neon_iv(data, len, out, state0, state1, state2, state3);
}

/*
 * sha384_hash_neon -- Full SHA-384 hash with padding.
 * SHA-384 is SHA-512 with different IVs and truncated to 48 bytes.
 */
static inline void sha384_hash_neon(const uint8_t *data, size_t len,
                                     uint8_t *out)
{
    /* SHA-384 initial hash values */
    uint64x2_t state0 = (uint64x2_t){0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL};
    uint64x2_t state1 = (uint64x2_t){0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL};
    uint64x2_t state2 = (uint64x2_t){0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL};
    uint64x2_t state3 = (uint64x2_t){0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};

    /* Compute full 64-byte SHA-512 digest, then truncate */
    uint8_t full_digest[64];
    sha512_hash_neon_iv(data, len, full_digest, state0, state1, state2, state3);
    memcpy(out, full_digest, 48);
}

#endif /* __ARM_NEON && __ARM_FEATURE_SHA512 */
#endif /* SHA512_SIMD_H */
