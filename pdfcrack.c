/*
 * pdfcrack.c — Fast PDF password cracker for macOS
 *
 * Uses native Core Graphics (CGPDFDocument) — no external deps.
 * Parallel attack via pthreads across all CPU cores.
 * Optional Metal GPU acceleration for MD5 key derivation.
 *
 * Build:
 *   make pdfcrack
 *
 * Usage:
 *   pdfcrack -f file.pdf -d wordlist.txt            # dictionary attack
 *   pdfcrack -f file.pdf -b -l 6                    # brute-force up to len 6
 *   pdfcrack -f file.pdf -b -l 6 -c abc123          # custom charset
 *   pdfcrack -f file.pdf -b -l 6 -t 8               # 8 threads
 *   pdfcrack -f file.pdf -b -l 6 -G                 # disable GPU
 */

#include <CoreGraphics/CoreGraphics.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <time.h>
#include <sys/qos.h>
#include <mach/mach_time.h>
#include "pdf_encrypt.h"
#include "metal_keygen.h"

/* Suppress deprecated warnings for CC_MD5 used in RC4 verify */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

/* Batch size for atomic counter updates — avoids cache-line thrashing */
#define TESTED_BATCH 256

#define DEFAULT_CHARSET \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define MAX_PASS_LEN 32
#define MAX_THREADS  64
#define BAR_WIDTH    35

/* ── shared state ─────────────────────────────────────────────── */
static atomic_int  g_found   = 0;
static char        g_password[MAX_PASS_LEN + 1] = {0};
static atomic_long g_tested  = 0;
static atomic_long g_total   = 0;   /* 0 = unknown */

/* ── config (read-only after parse) ──────────────────────────── */
static const char *g_pdf_path = NULL;
static const char *g_charset  = NULL;
static int         g_cs_len   = 0;
static int         g_nthreads = 0;

/* ── fast crypto path (bypasses CGPDFDocument) ────────────────── */
static PDFEncryptParams g_enc_params;
static int              g_fast_crypto = 0; /* 1 = use direct MD5+RC4 */

/* ── GPU acceleration ──────────────────────────────────────────── */
#define GPU_BATCH_SIZE  65536
#define CPU_WORK_CHUNK  512   /* CPU threads grab this many from shared counter */
static MetalKeygenContext *g_gpu_ctx   = NULL;
static int                 g_use_gpu   = 0;
static atomic_long         g_next_idx  = 0; /* shared work counter for GPU+CPU */

/* ── dictionary word list ─────────────────────────────────────── */
static char **g_words  = NULL;
static long   g_nwords = 0;

/* ================================================================
 * PDF helpers
 * Fast path: direct MD5+RC4 (no CGPDFDocument overhead, thread-safe)
 * Slow path: CGPDFDocument (fallback for unsupported encryption)
 * ================================================================ */
static CGPDFDocumentRef open_pdf(void)
{
    CFStringRef s = CFStringCreateWithCString(NULL, g_pdf_path,
                                              kCFStringEncodingUTF8);
    CFURLRef url  = CFURLCreateWithFileSystemPath(NULL, s,
                                                  kCFURLPOSIXPathStyle, false);
    CFRelease(s);
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(url);
    CFRelease(url);
    return doc;
}

static inline int test_password_fast(const char *pass)
{
    return pdf_verify_password(&g_enc_params, pass);
}

static inline int test_password_cg(CGPDFDocumentRef doc, const char *pass)
{
    return CGPDFDocumentUnlockWithPassword(doc, pass);
}

/* ================================================================
 * Progress thread
 * ================================================================ */
static void print_bar(double pct)
{
    int filled = (int)(pct / 100.0 * BAR_WIDTH);
    fputc('[', stderr);
    for (int i = 0; i < BAR_WIDTH; i++)
        fputc(i < filled ? '#' : '.', stderr);
    fputc(']', stderr);
}

static void *progress_thread(void *arg)
{
    (void)arg;
    long   prev    = 0;
    time_t t0      = time(NULL);
    long   avg_buf[8] = {0};
    int    avg_i   = 0;

    while (!atomic_load(&g_found)) {
        struct timespec ts = {0, 500000000L}; /* 0.5s */
        nanosleep(&ts, NULL);

        long cur     = atomic_load(&g_tested);
        long total   = atomic_load(&g_total);
        long rate    = (cur - prev) * 2; /* per 0.5s → per sec */
        prev         = cur;
        long elapsed = (long)(time(NULL) - t0);

        /* rolling average for ETA */
        avg_buf[avg_i++ % 8] = rate;
        long avg_rate = 0;
        for (int i = 0; i < 8; i++) avg_rate += avg_buf[i];
        avg_rate /= 8;

        fputs("\r  ", stderr);

        if (total > 0) {
            double pct = (double)cur / (double)total * 100.0;
            if (pct > 100.0) pct = 100.0;
            print_bar(pct);

            long eta = -1;
            if (avg_rate > 0 && total > cur)
                eta = (total - cur) / avg_rate;

            if (eta >= 0)
                fprintf(stderr,
                    " %5.1f%%  %ld/%ld  %ld/s  elapsed %lds  ETA %lds   ",
                    pct, cur, total, rate, elapsed, eta);
            else
                fprintf(stderr,
                    " %5.1f%%  %ld/%ld  %ld/s  elapsed %lds   ",
                    pct, cur, total, rate, elapsed);
        } else {
            fprintf(stderr,
                "  tested: %-12ld  %ld/s  elapsed: %lds   ",
                cur, rate, elapsed);
        }
        fflush(stderr);
    }
    return NULL;
}

/* ================================================================
 * Dictionary attack
 * ================================================================ */
typedef struct { int id; int use_shared; } DictArg;

static void *dict_worker(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    DictArg *a = (DictArg *)arg;

    /* Only open CGPDFDocument if we need the slow path */
    CGPDFDocumentRef doc = NULL;
    if (!g_fast_crypto) {
        doc = open_pdf();
        if (!doc) { free(arg); return NULL; }
    }

    long local_count = 0;

    if (a->use_shared) {
        /* Shared work counter mode — grab CPU_WORK_CHUNK at a time */
        for (;;) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            long chunk_start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
            if (chunk_start >= g_nwords) break;
            long chunk_end = chunk_start + CPU_WORK_CHUNK;
            if (chunk_end > g_nwords) chunk_end = g_nwords;

            for (long i = chunk_start; i < chunk_end; i++) {
                if (__builtin_expect(atomic_load_explicit(&g_found,
                                     memory_order_relaxed), 0))
                    break;
                if (++local_count == TESTED_BATCH) {
                    atomic_fetch_add_explicit(&g_tested, local_count,
                                              memory_order_relaxed);
                    local_count = 0;
                }
                int hit = g_fast_crypto ? test_password_fast(g_words[i])
                                        : test_password_cg(doc, g_words[i]);
                if (hit) {
                    if (!atomic_exchange(&g_found, 1))
                        strncpy(g_password, g_words[i], MAX_PASS_LEN);
                }
            }
        }
    } else {
        /* Interleaved mode (CPU-only) */
        for (long i = a->id; i < g_nwords; i += g_nthreads) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            if (++local_count == TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count,
                                          memory_order_relaxed);
                local_count = 0;
            }
            int hit = g_fast_crypto ? test_password_fast(g_words[i])
                                    : test_password_cg(doc, g_words[i]);
            if (hit) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, g_words[i], MAX_PASS_LEN);
            }
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_tested, local_count);

    if (doc) CGPDFDocumentRelease(doc);
    free(arg);
    return NULL;
}

/* ================================================================
 * Brute-force
 * ================================================================ */
static void index_to_pass(long idx, int length, char *out)
{
    for (int i = length - 1; i >= 0; i--) {
        out[i] = g_charset[idx % g_cs_len];
        idx /= g_cs_len;
    }
    out[length] = '\0';
}

static long count_for_length(int len)
{
    long n = 1;
    for (int i = 0; i < len; i++) {
        if (n > (long)2e18 / g_cs_len) return (long)2e18;
        n *= g_cs_len;
    }
    return n;
}

typedef struct { int id; int length; long start; long end; int use_shared; } BruteArg;

static void *brute_worker(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    BruteArg *a = (BruteArg *)arg;

    CGPDFDocumentRef doc = NULL;
    if (!g_fast_crypto) {
        doc = open_pdf();
        if (!doc) { free(arg); return NULL; }
    }

    char pass[MAX_PASS_LEN + 1];
    long local_count = 0;

    if (a->use_shared) {
        /* Shared work counter mode — grab CPU_WORK_CHUNK at a time */
        for (;;) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            long chunk_start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
            if (chunk_start >= a->end) break;
            long chunk_end = chunk_start + CPU_WORK_CHUNK;
            if (chunk_end > a->end) chunk_end = a->end;

            for (long i = chunk_start; i < chunk_end; i++) {
                if (__builtin_expect(atomic_load_explicit(&g_found,
                                     memory_order_relaxed), 0))
                    break;
                index_to_pass(i, a->length, pass);
                if (++local_count == TESTED_BATCH) {
                    atomic_fetch_add_explicit(&g_tested, local_count,
                                              memory_order_relaxed);
                    local_count = 0;
                }
                int hit = g_fast_crypto ? test_password_fast(pass)
                                        : test_password_cg(doc, pass);
                if (hit) {
                    if (!atomic_exchange(&g_found, 1))
                        strncpy(g_password, pass, MAX_PASS_LEN);
                }
            }
        }
    } else {
        /* Pre-partitioned range mode (CPU-only) */
        for (long i = a->start; i < a->end; i++) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            index_to_pass(i, a->length, pass);
            if (++local_count == TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count,
                                          memory_order_relaxed);
                local_count = 0;
            }
            int hit = g_fast_crypto ? test_password_fast(pass)
                                    : test_password_cg(doc, pass);
            if (hit) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
            }
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_tested, local_count);

    if (doc) CGPDFDocumentRelease(doc);
    free(arg);
    return NULL;
}

/* ================================================================
 * Benchmark gate: compare GPU+RC4 pipeline vs CPU-only
 * Returns 1 if GPU is worth using, 0 otherwise.
 * ================================================================ */
static int benchmark_gpu(void)
{
    const int N = 2000;
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);

    /* Generate dummy passwords */
    const char **passwords = malloc(sizeof(char *) * N);
    char *pw_storage = malloc(8 * N);
    uint8_t *keys = malloc((size_t)N * key_bytes);
    if (!passwords || !pw_storage || !keys) {
        free(passwords); free(pw_storage); free(keys);
        return 0;
    }
    for (int i = 0; i < N; i++) {
        snprintf(pw_storage + i * 8, 8, "bench%d", i);
        passwords[i] = pw_storage + i * 8;
    }

    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    /* Time GPU pipeline: keygen + RC4 verify */
    uint64_t t0 = mach_absolute_time();
    int n = metal_keygen_batch(g_gpu_ctx, passwords, N, keys);
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            const uint8_t *key = keys + i * key_bytes;
            if (g_enc_params.revision == 2) {
                uint8_t u[32]; size_t ol = 32;
                CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0, key, key_bytes,
                        NULL, PDF_PASSWORD_PADDING, 32, u, 32, &ol);
            } else {
                CC_MD5_CTX md5; CC_MD5_Init(&md5);
                CC_MD5_Update(&md5, PDF_PASSWORD_PADDING, 32);
                CC_MD5_Update(&md5, g_enc_params.file_id,
                              (CC_LONG)g_enc_params.file_id_len);
                uint8_t h[16]; CC_MD5_Final(h, &md5);
                uint8_t enc[16]; size_t ol = 16;
                CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0, key, key_bytes,
                        NULL, h, 16, enc, 16, &ol);
                for (int r = 1; r <= 19; r++) {
                    uint8_t mk[16];
                    for (int j = 0; j < key_bytes; j++) mk[j] = key[j] ^ (uint8_t)r;
                    uint8_t tmp[16]; ol = 16;
                    CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0, mk, key_bytes,
                            NULL, enc, 16, tmp, 16, &ol);
                    memcpy(enc, tmp, 16);
                }
            }
        }
    }
    uint64_t t1 = mach_absolute_time();
    double gpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    double gpu_rate = gpu_s > 0 ? N / gpu_s : 0;

    /* Time CPU-only */
    t0 = mach_absolute_time();
    for (int i = 0; i < N; i++)
        pdf_verify_user_password(&g_enc_params, passwords[i]);
    t1 = mach_absolute_time();
    double cpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    double cpu_rate = cpu_s > 0 ? N / cpu_s : 0;

    free(passwords); free(pw_storage); free(keys);

    fprintf(stderr, "Bench  : GPU %.0f/s vs CPU %.0f/s (single-core)",
            gpu_rate, cpu_rate);

    /* GPU pipeline must beat a single CPU core to be worthwhile,
     * since it runs as one extra "thread" alongside all CPU threads */
    if (gpu_rate > cpu_rate * 0.5) {
        fprintf(stderr, " — GPU enabled\n");
        return 1;
    } else {
        fprintf(stderr, " — GPU disabled (too slow)\n");
        return 0;
    }
}

/* ================================================================
 * GPU + CPU RC4 verification helper
 * Given a batch of keys from the GPU, run RC4 verification on CPU.
 * ================================================================ */
static int verify_keys_rc4(const uint8_t *keys, const char **passwords,
                           int count, int key_bytes)
{
    for (int i = 0; i < count; i++) {
        const uint8_t *key = keys + i * key_bytes;

        if (g_enc_params.revision == 2) {
            /* Algorithm 4: RC4-encrypt padding, compare all 32 bytes of U */
            uint8_t computed_u[32];
            size_t out_len = 32;
            CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                    key, (size_t)key_bytes, NULL,
                    PDF_PASSWORD_PADDING, 32,
                    computed_u, 32, &out_len);
            if (memcmp(computed_u, g_enc_params.u_value, 32) == 0) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, passwords[i], MAX_PASS_LEN);
                return 1;
            }
        } else {
            /* Algorithm 5: MD5(padding+fileID), 20 RC4 passes, compare 16 bytes */
            CC_MD5_CTX md5;
            CC_MD5_Init(&md5);
            CC_MD5_Update(&md5, PDF_PASSWORD_PADDING, 32);
            CC_MD5_Update(&md5, g_enc_params.file_id,
                          (CC_LONG)g_enc_params.file_id_len);
            uint8_t hash[16];
            CC_MD5_Final(hash, &md5);

            uint8_t encrypted[16];
            size_t out_len = 16;
            CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                    key, (size_t)key_bytes, NULL,
                    hash, 16, encrypted, 16, &out_len);

            for (int r = 1; r <= 19; r++) {
                uint8_t mod_key[16];
                for (int j = 0; j < key_bytes; j++)
                    mod_key[j] = key[j] ^ (uint8_t)r;
                uint8_t temp[16];
                out_len = 16;
                CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                        mod_key, (size_t)key_bytes, NULL,
                        encrypted, 16, temp, 16, &out_len);
                memcpy(encrypted, temp, 16);
            }

            if (memcmp(encrypted, g_enc_params.u_value, 16) == 0) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, passwords[i], MAX_PASS_LEN);
                return 1;
            }
        }
    }
    return 0;
}

/* ================================================================
 * GPU brute-force worker
 * Grabs batches from shared g_next_idx, runs MD5 on GPU, RC4 on CPU.
 * ================================================================ */
typedef struct { int length; long total; } GPUBruteArg;

static void *gpu_brute_worker(void *arg)
{
    GPUBruteArg *a = (GPUBruteArg *)arg;
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    char *pw_storage = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));
    uint8_t *keys = malloc((size_t)GPU_BATCH_SIZE * key_bytes);

    if (!pw_ptrs || !pw_storage || !keys) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->total) end = a->total;
        int count = (int)(end - start);

        /* Generate password strings */
        for (int i = 0; i < count; i++) {
            char *pw = pw_storage + i * (MAX_PASS_LEN + 1);
            index_to_pass(start + i, a->length, pw);
            pw_ptrs[i] = pw;
        }

        /* GPU: MD5 key derivation */
        int n = metal_keygen_batch(g_gpu_ctx, pw_ptrs, count, keys);
        if (n <= 0) break;

        /* CPU: RC4 verification */
        verify_keys_rc4(keys, pw_ptrs, n, key_bytes);

        atomic_fetch_add_explicit(&g_tested, (long)n, memory_order_relaxed);
    }

done:
    free(pw_ptrs);
    free(pw_storage);
    free(keys);
    free(arg);
    return NULL;
}

/* ================================================================
 * GPU dictionary worker
 * Grabs batches from shared g_next_idx into word list.
 * ================================================================ */
static void *gpu_dict_worker(void *arg)
{
    (void)arg;
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    uint8_t *keys = malloc((size_t)GPU_BATCH_SIZE * key_bytes);

    if (!pw_ptrs || !keys) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= g_nwords) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > g_nwords) end = g_nwords;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++)
            pw_ptrs[i] = g_words[start + i];

        int n = metal_keygen_batch(g_gpu_ctx, (const char **)pw_ptrs, count, keys);
        if (n <= 0) break;

        verify_keys_rc4(keys, pw_ptrs, n, key_bytes);

        atomic_fetch_add_explicit(&g_tested, (long)n, memory_order_relaxed);
    }

done:
    free(pw_ptrs);
    free(keys);
    free(arg);
    return NULL;
}

/* ================================================================
 * Wordlist loader
 * ================================================================ */
static int load_wordlist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    long n = 0;
    int  c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') n++;
    rewind(f);

    g_words = malloc((size_t)(n + 1) * sizeof(char *));
    if (!g_words) { fclose(f); return 0; }

    char   line[MAX_PASS_LEN + 4];
    long   idx = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (!len) continue;
        if ((g_words[idx] = malloc(len + 1)))
            memcpy(g_words[idx++], line, len + 1);
    }
    g_nwords = idx;
    fclose(f);
    return 1;
}

/* ================================================================
 * Usage
 * ================================================================ */
static void usage(const char *p)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s -f <pdf> -d <wordlist>               dictionary attack\n"
        "  %s -f <pdf> -b [-l <maxlen>] [-c <cs>]  brute-force\n"
        "\nOptions:\n"
        "  -f  PDF file\n"
        "  -d  wordlist (one password per line)\n"
        "  -b  brute-force mode\n"
        "  -l  max password length (default: 4)\n"
        "  -c  charset (default: a-zA-Z0-9)\n"
        "  -t  threads (default: CPU core count)\n"
        "  -G  disable GPU acceleration\n",
        p, p);
    exit(1);
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    const char *pdf_path  = NULL;
    const char *dict_path = NULL;
    const char *charset   = DEFAULT_CHARSET;
    int         brute     = 0;
    int         max_len   = 4;
    int         no_gpu    = 0;
    int         nthreads  = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 4;

    int opt;
    while ((opt = getopt(argc, argv, "f:d:bl:c:t:G")) != -1) {
        switch (opt) {
            case 'f': pdf_path  = optarg;       break;
            case 'd': dict_path = optarg;       break;
            case 'b': brute     = 1;            break;
            case 'l': max_len   = atoi(optarg); break;
            case 'c': charset   = optarg;       break;
            case 't': nthreads  = atoi(optarg); break;
            case 'G': no_gpu    = 1;            break;
            default:  usage(argv[0]);
        }
    }

    if (!pdf_path)            { fprintf(stderr, "-f required\n");       usage(argv[0]); }
    if (!brute && !dict_path) { fprintf(stderr, "-d or -b required\n"); usage(argv[0]); }
    if (nthreads > MAX_THREADS) nthreads = MAX_THREADS;

    /* ── Validate PDF ──────────────────────────────────────────── */
    g_pdf_path = pdf_path;
    CGPDFDocumentRef probe = open_pdf();
    if (!probe) { fprintf(stderr, "Cannot open: %s\n", pdf_path); return 1; }

    if (!CGPDFDocumentIsEncrypted(probe)) {
        fprintf(stderr, "PDF is not encrypted — no password needed.\n");
        CGPDFDocumentRelease(probe);
        return 0;
    }
    if (CGPDFDocumentUnlockWithPassword(probe, "")) {
        printf("Password found: (empty)\n");
        CGPDFDocumentRelease(probe);
        return 0;
    }
    CGPDFDocumentRelease(probe);

    g_charset  = charset;
    g_cs_len   = (int)strlen(charset);
    g_nthreads = nthreads;

    /* ── Try fast crypto path (direct MD5+RC4) ─────────────────── */
    g_enc_params = pdf_parse_encrypt_file(pdf_path);
    if (g_enc_params.valid) {
        g_fast_crypto = 1;
        fprintf(stderr, "Crypto : direct MD5+RC4 (R%d, %d-bit key) — ~10x faster\n",
                g_enc_params.revision, g_enc_params.key_length);
    } else {
        fprintf(stderr, "Crypto : CGPDFDocument fallback (unsupported encryption)\n");
    }

    /* ── Try GPU acceleration ─────────────────────────────────────── */
    if (g_fast_crypto && !no_gpu) {
        g_gpu_ctx = metal_keygen_init(&g_enc_params, NULL);
        if (g_gpu_ctx) {
            if (benchmark_gpu()) {
                g_use_gpu = 1;
            } else {
                metal_keygen_free(g_gpu_ctx);
                g_gpu_ctx = NULL;
            }
        }
    }

    fprintf(stderr, "Target : %s\n", pdf_path);
    fprintf(stderr, "Threads: %d%s\n", nthreads,
            g_use_gpu ? " + GPU" : "");

    /* ── Start progress thread ─────────────────────────────────── */
    pthread_t prog;
    pthread_create(&prog, NULL, progress_thread, NULL);

    pthread_t threads[MAX_THREADS];
    int       spawned = 0;

    /* ── Dictionary attack ─────────────────────────────────────── */
    if (dict_path) {
        if (!load_wordlist(dict_path)) {
            atomic_store(&g_found, 1); /* stop progress thread */
            pthread_join(prog, NULL);
            return 1;
        }
        fprintf(stderr, "Mode   : dictionary (%ld words)\n\n", g_nwords);
        atomic_store(&g_total, g_nwords);
        atomic_store(&g_next_idx, 0);

        /* Spawn GPU worker if available */
        if (g_use_gpu) {
            pthread_create(&threads[spawned++], NULL, gpu_dict_worker, NULL);
        }

        int limit = nthreads < (int)g_nwords ? nthreads : (int)g_nwords;
        for (int t = 0; t < limit; t++) {
            DictArg *a = malloc(sizeof(DictArg));
            a->id = t;
            a->use_shared = g_use_gpu;
            pthread_create(&threads[spawned++], NULL, dict_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
    }

    /* ── Brute-force attack ────────────────────────────────────── */
    else {
        fprintf(stderr, "Mode   : brute-force (len 1..%d, charset \"%s\")\n\n",
                max_len, charset);

        for (int len = 1; len <= max_len && !atomic_load(&g_found); len++) {
            long total = count_for_length(len);
            fprintf(stderr, "\n  [len %d] %ld candidates\n", len, total);

            atomic_store(&g_tested, 0);
            atomic_store(&g_total, total);
            atomic_store(&g_next_idx, 0);
            spawned = 0;

            if (g_use_gpu) {
                /* Shared work counter mode: GPU + CPU all pull from g_next_idx */
                GPUBruteArg *ga = malloc(sizeof(GPUBruteArg));
                *ga = (GPUBruteArg){ .length = len, .total = total };
                pthread_create(&threads[spawned++], NULL, gpu_brute_worker, ga);

                for (int t = 0; t < nthreads; t++) {
                    BruteArg *a = malloc(sizeof(BruteArg));
                    *a = (BruteArg){ .id = t, .length = len,
                                     .start = 0, .end = total, .use_shared = 1 };
                    pthread_create(&threads[spawned++], NULL, brute_worker, a);
                }
            } else {
                /* Pre-partitioned ranges (CPU-only) */
                long chunk = (total + nthreads - 1) / nthreads;
                for (int t = 0; t < nthreads; t++) {
                    long start = (long)t * chunk;
                    long end   = start + chunk;
                    if (start >= total) break;
                    if (end   > total)  end = total;

                    BruteArg *a = malloc(sizeof(BruteArg));
                    *a = (BruteArg){ .id = t, .length = len,
                                     .start = start, .end = end, .use_shared = 0 };
                    pthread_create(&threads[spawned++], NULL, brute_worker, a);
                }
            }
            for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
        }
    }

    /* ── Stop progress thread and print result ─────────────────── */
    atomic_store(&g_found, 1); /* ensure progress thread exits */
    pthread_join(prog, NULL);
    fputs("\n\n", stderr);

    if (g_gpu_ctx) metal_keygen_free(g_gpu_ctx);

    if (g_password[0] || atomic_load(&g_found)) {
        if (g_password[0]) {
            printf("Password found: %s\n", g_password);
            return 0;
        }
    }
    printf("Password not found.\n");
    return 1;
}
