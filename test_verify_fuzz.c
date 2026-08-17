/* ================================================================
 * test_verify_fuzz.c — fuzz + differential harness for the VERIFY path
 *
 * The existing fuzzer (test_parse_fuzz.c) only calls pdf_parse_encrypt;
 * it never touches the password-verification functions. Yet that is where
 * the crypto (KDF / RC4 / SHA / AES) runs and where the recent hardening
 * fixes landed. This harness closes that gap:
 *
 *   1. Parse fuzz input into PDFEncryptParams (may be valid with adversarial
 *      field values: odd key_length, revision, salts, O/U bytes, lengths).
 *   2. If valid, exercise every verify entry point — scalar user/owner for
 *      R2-R6 (KDF, RC4, R6 Algorithm 2.B, SHA-256/384/512, AES) and the
 *      NEON batch4 paths — with several derived passwords, including an
 *      over-length (>127) one that stresses the algorithm_2b buffer defense.
 *      ASan/UBSan catch any over-read/overflow/UB.
 *   3. DIFFERENTIAL ORACLE: for R2-R4, assert each NEON batch4 lane result
 *      equals the scalar result for the same password. Divergence aborts.
 *
 * Build (libFuzzer, needs Homebrew LLVM — see Makefile `fuzz-verify`):
 *   clang -fsanitize=fuzzer,address,undefined -o fuzz_verify \
 *       test_verify_fuzz.c pdf_encrypt.c saslprep.c <frameworks>
 *
 * Build (standalone runner, Apple clang — no libFuzzer runtime needed):
 *   clang -DSTANDALONE -fsanitize=address,undefined -o verify_fuzz_standalone \
 *       test_verify_fuzz.c pdf_encrypt.c saslprep.c <frameworks>
 *   ./verify_fuzz_standalone test_*.pdf        # replay seeds + mutation loop
 * ================================================================ */

#include "pdf_encrypt.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Build a NUL-free C-string password from a slice of the fuzz input.
 * NUL-free keeps pwlen == strlen, so the batch4-vs-scalar differential
 * compares the same effective bytes (the NUL-safety of the batch path is
 * covered separately by the unit tests). */
static void derive_pw(const uint8_t *data, size_t size,
                      size_t off, size_t want, char *out, size_t outcap)
{
    size_t j = 0;
    for (size_t i = 0; i < want && j + 1 < outcap; i++) {
        uint8_t b = size ? data[(off + i) % size] : (uint8_t)'a';
        out[j++] = b ? (char)b : '.';   /* map embedded NUL to '.' */
    }
    out[j] = '\0';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    PDFEncryptParams p = pdf_parse_encrypt(data, size);
    if (!p.valid) return 0;

    /* Four passwords: empty, short, over-length (>127 stresses the R6 KDF
     * buffer defense), and a mid-slice one. */
    enum { NPW = 4, PWCAP = 300 };
    char pw[NPW][PWCAP];
    const char *pwp[NPW];
    int pwlen[NPW];

    pw[0][0] = '\0';                                   /* empty password */
    derive_pw(data, size, 0,            size % 41,  pw[1], PWCAP);
    derive_pw(data, size, 1,            220,        pw[2], PWCAP); /* > 127 */
    derive_pw(data, size, size / 2 + 1, 32,         pw[3], PWCAP);
    for (int i = 0; i < NPW; i++) {
        pwp[i]   = pw[i];
        pwlen[i] = (int)strlen(pw[i]);
    }

    /* Scalar verify — exercises the full crypto path for the parsed revision. */
    for (int i = 0; i < NPW; i++) {
        (void)pdf_verify_user_password(&p, pw[i]);
        (void)pdf_verify_owner_password(&p, pw[i]);
    }

    /* Differential oracle: NEON batch4 must agree with scalar, lane by lane.
     * Only R2-R4 have a NEON batch4 MD5 path; R5/R6 batch owner falls back to
     * scalar and batch user returns 0, so the invariant is only asserted here. */
#ifdef __ARM_NEON
    if (p.revision >= 2 && p.revision <= 4) {
        int uh = pdf_verify_user_batch4(&p, pwp, pwlen);
        int oh = pdf_verify_owner_batch4(&p, pwp, pwlen);
        for (int i = 0; i < NPW; i++) {
            int su = pdf_verify_user_password(&p, pw[i]);
            int so = pdf_verify_owner_password(&p, pw[i]);
            if (((uh >> i) & 1) != su) {
                fprintf(stderr, "DIFFERENTIAL: user lane %d batch=%d scalar=%d "
                        "R=%d keylen=%d\n", i, (uh >> i) & 1, su,
                        p.revision, p.key_length);
                abort();
            }
            if (((oh >> i) & 1) != so) {
                fprintf(stderr, "DIFFERENTIAL: owner lane %d batch=%d scalar=%d "
                        "R=%d keylen=%d\n", i, (oh >> i) & 1, so,
                        p.revision, p.key_length);
                abort();
            }
        }
    }
#endif
    return 0;
}

/* ================================================================
 * Standalone runner — lets the harness run under Apple clang's ASan/UBSan
 * without the libFuzzer runtime. Replays each file argument as a seed, then
 * runs a deterministic mutation loop over the seed pool to explore the
 * parameter space (odd revisions, key lengths, salts, truncations).
 * ================================================================ */
#ifdef STANDALONE

/* xorshift64 — deterministic PRNG (Math.random()/time are intentionally
 * avoided so runs are reproducible). */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint64_t xrng(void)
{
    uint64_t x = g_rng;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    g_rng = x;
    return x;
}

static uint8_t *read_file(const char *path, size_t *out_n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    *out_n = got;
    return buf;
}

/* Run one input through the harness via a fresh heap buffer, so ASan can
 * flag any over-read past the actual input length. */
static void run_once(const uint8_t *data, size_t n)
{
    uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
    if (!buf) return;
    if (n) memcpy(buf, data, n);
    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
}

int main(int argc, char **argv)
{
    /* Load seeds. */
    uint8_t *seed[64];
    size_t   seed_n[64];
    int nseed = 0;
    for (int i = 1; i < argc && nseed < 64; i++) {
        size_t n = 0;
        uint8_t *b = read_file(argv[i], &n);
        if (b) { seed[nseed] = b; seed_n[nseed] = n; nseed++; run_once(b, n); }
    }
    if (nseed == 0) {
        fprintf(stderr, "usage: %s <seed.pdf> [more.pdf...]\n", argv[0]);
        return 2;
    }

    /* Mutation loop: perturb copies of the seeds and replay them. Many
     * mutations still parse as valid PDFs with adversarial encrypt fields —
     * exactly the space the parse-only fuzzer never verified. */
    /* Iteration count overridable via env (R6's KDF is slow under ASan). */
    long ITERS = 50000;
    const char *env = getenv("VERIFY_FUZZ_ITERS");
    if (env) { long v = atol(env); if (v > 0) ITERS = v; }
    size_t maxn = 0;
    for (int i = 0; i < nseed; i++) if (seed_n[i] > maxn) maxn = seed_n[i];
    uint8_t *work = (uint8_t *)malloc(maxn ? maxn : 1);
    if (!work) return 1;

    for (long it = 0; it < ITERS; it++) {
        int s = (int)(xrng() % (uint64_t)nseed);
        size_t n = seed_n[s];
        if (n == 0) continue;
        memcpy(work, seed[s], n);
        int nmut = 1 + (int)(xrng() % 24);
        for (int m = 0; m < nmut; m++) {
            size_t pos = (size_t)(xrng() % n);
            work[pos] = (uint8_t)(xrng() & 0xFF);
        }
        /* Sometimes truncate to stress length handling. */
        size_t use = (xrng() & 7) ? n : (size_t)(xrng() % (n + 1));
        run_once(work, use);
    }

    free(work);
    for (int i = 0; i < nseed; i++) free(seed[i]);
    fprintf(stderr, "standalone: %d seeds, %ld mutation iterations — clean\n",
            nseed, ITERS);
    return 0;
}
#endif /* STANDALONE */
