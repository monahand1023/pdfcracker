/*
 * client.c — Distributed PDF cracker worker node (v2, lease-aware)
 *
 * Connects to a server, receives the PDF and work config, then cracks
 * locally using all CPU cores + optional Metal GPU via pthreads.
 *
 * v2 changes: UUID persistence, auto-reconnect with exponential backoff,
 * lease-aware work loop, graceful shutdown with PARTIAL.
 *
 * Build:
 *   make client
 *
 * Usage:
 *   ./client                                # auto-discover server via Bonjour
 *   ./client -s 192.168.1.10                # connect to server
 *   ./client -s 192.168.1.10 -p 8888        # custom port
 *   ./client -s 192.168.1.10 -t 4           # limit to 4 threads
 *   ./client -s 192.168.1.10 -G             # disable GPU
 */

#include "protocol.h"
#include "pdf_encrypt.h"
#include "metal_keygen.h"
#include <CoreGraphics/CoreGraphics.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/qos.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <sys/stat.h>
#include <pwd.h>
#include <dns_sd.h>
#include <sys/select.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

/* Batch size for atomic counter updates — avoids cache-line thrashing */
#define TESTED_BATCH 256

/* Maximum local threads (MAX_CLIENTS + 1 for GPU thread) */
#define MAX_LOCAL_THREADS 65

/* ── Local state ──────────────────────────────────────────────── */
static int   g_nthreads = 0;
static int   g_no_gpu   = 0;
static char  g_pdf_path[256] = {0};  /* temp file */
static int   g_server_fd = -1;

/* ── Fast crypto path ─────────────────────────────────────────── */
static PDFEncryptParams g_enc_params;
static int              g_fast_crypto = 0;

/* ── GPU acceleration ──────────────────────────────────────────── */
#define GPU_BATCH_SIZE  65536
#define CPU_WORK_CHUNK  512
static MetalKeygenContext *g_gpu_ctx = NULL;
static MetalSHA256Context *g_sha256_ctx = NULL;
static MetalR6Context     *g_r6_ctx    = NULL;
static int                 g_use_gpu = 0;
static atomic_long         g_next_idx = 0;

/* ── Mode config (received from server) ───────────────────────── */
static int   g_brute    = 0;
static int   g_max_len  = 0;
static char  g_charset[256] = {0};
static int   g_cs_len   = 0;
static int   g_password_mode = PW_MODE_BOTH;

/* ── Per-chunk shared state (reset each chunk) ────────────────── */
static atomic_int  g_chunk_found  = 0;
static char        g_chunk_pass[MAX_PASS_LEN + 1] = {0};
static atomic_long g_chunk_tested = 0;

/* ── Session / reconnect state ────────────────────────────────── */
static char          g_client_uuid[UUID_LEN + 1] = {0};
static uint64_t      g_current_lease_id = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;

/* ================================================================
 * UUID persistence — ~/.pdfcracker_id
 * ================================================================ */
static void ensure_uuid(void)
{
    /* Build path: ~/.pdfcracker_id */
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) home = "/tmp";

    char path[512];
    snprintf(path, sizeof(path), "%s/.pdfcracker_id", home);

    /* Try to read existing UUID */
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(g_client_uuid, sizeof(g_client_uuid), f)) {
            /* Strip trailing whitespace */
            size_t len = strlen(g_client_uuid);
            while (len > 0 && (g_client_uuid[len-1] == '\n' ||
                               g_client_uuid[len-1] == '\r' ||
                               g_client_uuid[len-1] == ' '))
                g_client_uuid[--len] = '\0';
            if (len == UUID_LEN) {
                fclose(f);
                return;
            }
        }
        fclose(f);
    }

    /* Generate UUID v4 from /dev/urandom */
    uint8_t bytes[16];
    f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("/dev/urandom");
        /* Fallback: use time + pid */
        srand((unsigned)(time(NULL) ^ getpid()));
        for (int i = 0; i < 16; i++) bytes[i] = (uint8_t)(rand() & 0xFF);
    } else {
        if (fread(bytes, 1, 16, f) != 16) {
            perror("fread urandom");
            fclose(f);
            return;
        }
        fclose(f);
    }

    /* Set version (4) and variant (0b10xx) bits */
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  /* version 4 */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  /* variant 1 */

    snprintf(g_client_uuid, sizeof(g_client_uuid),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);

    /* Write to file */
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", g_client_uuid);
        fclose(f);
    }
}

/* ================================================================
 * PDF helpers
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

static inline int test_password(CGPDFDocumentRef doc, const char *pass)
{
    return CGPDFDocumentUnlockWithPassword(doc, pass);
}

static inline int test_password_fast_mode(const char *pass)
{
    if (g_password_mode == PW_MODE_USER)
        return pdf_verify_user_password(&g_enc_params, pass);
    if (g_password_mode == PW_MODE_OWNER)
        return pdf_verify_owner_password(&g_enc_params, pass);
    return test_password_fast_mode(pass);
}

/* ================================================================
 * Brute-force worker (local thread)
 * ================================================================ */
typedef struct {
    long start;
    long end;
    int  length;
} BruteLocalArg;

static void *brute_local_worker(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    BruteLocalArg *a = (BruteLocalArg *)arg;

    CGPDFDocumentRef doc = NULL;
    if (!g_fast_crypto) {
        doc = open_pdf();
        if (!doc) { free(arg); return NULL; }
    }

    char pass[MAX_PASS_LEN + 1];
    long local_count = 0;

    if (g_use_gpu) {
        /* Shared counter mode — grab CPU_WORK_CHUNK at a time */
        for (;;) {
            if (__builtin_expect(atomic_load_explicit(&g_chunk_found,
                                 memory_order_relaxed), 0))
                break;
            long cs = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
            if (cs >= a->end) break;
            long ce = cs + CPU_WORK_CHUNK;
            if (ce > a->end) ce = a->end;
            for (long i = cs; i < ce; i++) {
                if (__builtin_expect(atomic_load_explicit(&g_chunk_found,
                                     memory_order_relaxed), 0))
                    break;
                index_to_password(i, a->length, g_charset, g_cs_len, pass);
                if (++local_count == TESTED_BATCH) {
                    atomic_fetch_add_explicit(&g_chunk_tested, local_count,
                                              memory_order_relaxed);
                    local_count = 0;
                }
                int hit = g_fast_crypto ? test_password_fast_mode(pass)
                                        : test_password(doc, pass);
                if (hit) {
                    if (!atomic_exchange(&g_chunk_found, 1))
                        strncpy(g_chunk_pass, pass, MAX_PASS_LEN);
                    g_chunk_pass[MAX_PASS_LEN] = '\0';
                        g_chunk_pass[MAX_PASS_LEN] = '\0';
                }
            }
        }
    } else {
        for (long i = a->start; i < a->end; i++) {
            if (__builtin_expect(atomic_load_explicit(&g_chunk_found,
                                 memory_order_relaxed), 0))
                break;
            index_to_password(i, a->length, g_charset, g_cs_len, pass);
            if (++local_count == TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_chunk_tested, local_count,
                                          memory_order_relaxed);
                local_count = 0;
            }
            int hit = g_fast_crypto ? test_password_fast_mode(pass)
                                    : test_password(doc, pass);
            if (hit) {
                if (!atomic_exchange(&g_chunk_found, 1))
                    strncpy(g_chunk_pass, pass, MAX_PASS_LEN);
                    g_chunk_pass[MAX_PASS_LEN] = '\0';
            }
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_chunk_tested, local_count);

    if (doc) CGPDFDocumentRelease(doc);
    free(arg);
    return NULL;
}

/* ================================================================
 * Dictionary worker (local thread)
 * ================================================================ */
typedef struct {
    char **words;
    long   start;
    long   count;
    int    stride;   /* thread index stride for interleaved access */
    int    offset;
} DictLocalArg;

static void *dict_local_worker(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    DictLocalArg *a = (DictLocalArg *)arg;

    CGPDFDocumentRef doc = NULL;
    if (!g_fast_crypto) {
        doc = open_pdf();
        if (!doc) { free(arg); return NULL; }
    }

    long local_count = 0;

    if (g_use_gpu) {
        /* Shared counter mode — grab CPU_WORK_CHUNK at a time */
        for (;;) {
            if (__builtin_expect(atomic_load_explicit(&g_chunk_found,
                                 memory_order_relaxed), 0))
                break;
            long cs = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
            if (cs >= a->count) break;
            long ce = cs + CPU_WORK_CHUNK;
            if (ce > a->count) ce = a->count;
            for (long i = cs; i < ce; i++) {
                if (__builtin_expect(atomic_load_explicit(&g_chunk_found,
                                     memory_order_relaxed), 0))
                    break;
                if (++local_count == TESTED_BATCH) {
                    atomic_fetch_add_explicit(&g_chunk_tested, local_count,
                                              memory_order_relaxed);
                    local_count = 0;
                }
                int hit = g_fast_crypto ? test_password_fast_mode(a->words[i])
                                        : test_password(doc, a->words[i]);
                if (hit) {
                    if (!atomic_exchange(&g_chunk_found, 1))
                        strncpy(g_chunk_pass, a->words[i], MAX_PASS_LEN);
                    g_chunk_pass[MAX_PASS_LEN] = '\0';
                        g_chunk_pass[MAX_PASS_LEN] = '\0';
                }
            }
        }
    } else {
        for (long i = a->offset; i < a->count; i += a->stride) {
            if (__builtin_expect(atomic_load_explicit(&g_chunk_found,
                                 memory_order_relaxed), 0))
                break;
            if (++local_count == TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_chunk_tested, local_count,
                                          memory_order_relaxed);
                local_count = 0;
            }
            int hit = g_fast_crypto ? test_password_fast_mode(a->words[i])
                                    : test_password(doc, a->words[i]);
            if (hit) {
                if (!atomic_exchange(&g_chunk_found, 1))
                    strncpy(g_chunk_pass, a->words[i], MAX_PASS_LEN);
                    g_chunk_pass[MAX_PASS_LEN] = '\0';
            }
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_chunk_tested, local_count);

    if (doc) CGPDFDocumentRelease(doc);
    free(arg);
    return NULL;
}

/* ================================================================
 * Benchmark gate: compare GPU+RC4 vs CPU-only
 * ================================================================ */
static int benchmark_gpu(void)
{
    const int N = 2000;

    const char **passwords = malloc(sizeof(char *) * N);
    char *pw_storage = malloc(16 * N);
    if (!passwords || !pw_storage) {
        free(passwords); free(pw_storage);
        return 0;
    }
    for (int i = 0; i < N; i++) {
        snprintf(pw_storage + i * 16, 16, "bench%d", i);
        passwords[i] = pw_storage + i * 16;
    }

    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    uint64_t t0, t1;

    if (g_enc_params.revision >= 6 && g_r6_ctx) {
        /* R6 GPU benchmark */
        int bench_n = N < 500 ? N : 500; /* R6 is slow, use fewer */
        t0 = mach_absolute_time();
        metal_r6_verify_batch(g_r6_ctx, passwords, bench_n);
        t1 = mach_absolute_time();
        double gpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
        double gpu_rate = gpu_s > 0 ? bench_n / gpu_s : 0;

        t0 = mach_absolute_time();
        for (int i = 0; i < bench_n; i++)
            pdf_verify_user_password(&g_enc_params, passwords[i]);
        t1 = mach_absolute_time();
        double cpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
        double cpu_rate = cpu_s > 0 ? bench_n / cpu_s : 0;

        free(passwords); free(pw_storage);
        fprintf(stderr, "Bench  : GPU %.0f/s vs CPU %.0f/s (single-core, R6)",
                gpu_rate, cpu_rate);
        if (gpu_rate > cpu_rate * 0.5) {
            fprintf(stderr, " — GPU enabled\n");
            return 1;
        } else {
            fprintf(stderr, " — GPU disabled (too slow)\n");
            return 0;
        }
    } else if (g_enc_params.revision == 5 && g_sha256_ctx) {
        /* R5 GPU benchmark */
        t0 = mach_absolute_time();
        metal_sha256_verify_batch(g_sha256_ctx, passwords, N);
        t1 = mach_absolute_time();
        double gpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
        double gpu_rate = gpu_s > 0 ? N / gpu_s : 0;

        t0 = mach_absolute_time();
        for (int i = 0; i < N; i++)
            pdf_verify_user_password(&g_enc_params, passwords[i]);
        t1 = mach_absolute_time();
        double cpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
        double cpu_rate = cpu_s > 0 ? N / cpu_s : 0;

        free(passwords); free(pw_storage);
        fprintf(stderr, "Bench  : GPU %.0f/s vs CPU %.0f/s (single-core, R5)",
                gpu_rate, cpu_rate);
        if (gpu_rate > cpu_rate * 0.5) {
            fprintf(stderr, " — GPU enabled\n");
            return 1;
        } else {
            fprintf(stderr, " — GPU disabled (too slow)\n");
            return 0;
        }
    }

    /* R2-R4: original keygen + RC4 benchmark */
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);
    uint8_t *keys = malloc((size_t)N * key_bytes);
    if (!keys) {
        free(passwords); free(pw_storage);
        return 0;
    }

    t0 = mach_absolute_time();
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
    t1 = mach_absolute_time();
    double gpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    double gpu_rate = gpu_s > 0 ? N / gpu_s : 0;

    t0 = mach_absolute_time();
    for (int i = 0; i < N; i++)
        pdf_verify_user_password(&g_enc_params, passwords[i]);
    t1 = mach_absolute_time();
    double cpu_s = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    double cpu_rate = cpu_s > 0 ? N / cpu_s : 0;

    free(passwords); free(pw_storage); free(keys);

    fprintf(stderr, "Bench  : GPU %.0f/s vs CPU %.0f/s (single-core)", gpu_rate, cpu_rate);
    if (gpu_rate > cpu_rate * 0.5) {
        fprintf(stderr, " — GPU enabled\n");
        return 1;
    } else {
        fprintf(stderr, " — GPU disabled (too slow)\n");
        return 0;
    }
}

/* ================================================================
 * GPU RC4 verification helper (same as pdfcrack.c)
 * ================================================================ */
static int verify_keys_rc4(const uint8_t *keys, const char **passwords,
                           int count, int key_bytes)
{
    for (int i = 0; i < count; i++) {
        const uint8_t *key = keys + i * key_bytes;
        if (g_enc_params.revision == 2) {
            uint8_t computed_u[32];
            size_t out_len = 32;
            CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                    key, (size_t)key_bytes, NULL,
                    PDF_PASSWORD_PADDING, 32,
                    computed_u, 32, &out_len);
            if (memcmp(computed_u, g_enc_params.u_value, 32) == 0) {
                if (!atomic_exchange(&g_chunk_found, 1))
                    strncpy(g_chunk_pass, passwords[i], MAX_PASS_LEN);
                    g_chunk_pass[MAX_PASS_LEN] = '\0';
                return 1;
            }
        } else {
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
                if (!atomic_exchange(&g_chunk_found, 1))
                    strncpy(g_chunk_pass, passwords[i], MAX_PASS_LEN);
                    g_chunk_pass[MAX_PASS_LEN] = '\0';
                return 1;
            }
        }
    }
    return 0;
}

/* ================================================================
 * GPU brute-force worker for client chunks
 * ================================================================ */
typedef struct { int length; long total_end; } GPUBruteLocalArg;

static void *gpu_brute_local_worker(void *arg)
{
    GPUBruteLocalArg *a = (GPUBruteLocalArg *)arg;
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);
    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    char *pw_storage = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));
    uint8_t *keys = malloc((size_t)GPU_BATCH_SIZE * key_bytes);
    if (!pw_ptrs || !pw_storage || !keys) goto done;

    while (!atomic_load_explicit(&g_chunk_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->total_end) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->total_end) end = a->total_end;
        int count = (int)(end - start);
        for (int i = 0; i < count; i++) {
            char *pw = pw_storage + i * (MAX_PASS_LEN + 1);
            index_to_password(start + i, a->length, g_charset, g_cs_len, pw);
            pw_ptrs[i] = pw;
        }
        int nn = metal_keygen_batch(g_gpu_ctx, pw_ptrs, count, keys);
        if (nn <= 0) break;
        verify_keys_rc4(keys, pw_ptrs, nn, key_bytes);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)nn, memory_order_relaxed);
    }
done:
    free(pw_ptrs); free(pw_storage); free(keys); free(arg);
    return NULL;
}

/* ================================================================
 * GPU dictionary worker for client chunks
 * ================================================================ */
typedef struct { char **words; long count; } GPUDictLocalArg;

static void *gpu_dict_local_worker(void *arg)
{
    GPUDictLocalArg *a = (GPUDictLocalArg *)arg;
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);
    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    uint8_t *keys = malloc((size_t)GPU_BATCH_SIZE * key_bytes);
    if (!pw_ptrs || !keys) goto done;

    while (!atomic_load_explicit(&g_chunk_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->count) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->count) end = a->count;
        int count = (int)(end - start);
        for (int i = 0; i < count; i++)
            pw_ptrs[i] = a->words[start + i];
        int nn = metal_keygen_batch(g_gpu_ctx, (const char **)pw_ptrs, count, keys);
        if (nn <= 0) break;
        verify_keys_rc4(keys, pw_ptrs, nn, key_bytes);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)nn, memory_order_relaxed);
    }
done:
    free(pw_ptrs); free(keys); free(arg);
    return NULL;
}

/* ================================================================
 * SHA-256 (R5) wait-and-check helper
 * ================================================================ */
static inline int sha256_wait_and_check(void *handle, int count,
                                         const char **pw_buf)
{
    int match_type = 0;
    int match = (g_password_mode == PW_MODE_BOTH)
        ? metal_sha256_wait_results_ex(g_sha256_ctx, handle, count, &match_type)
        : metal_sha256_wait_results(g_sha256_ctx, handle, count);
    if (match >= 0) {
        if (!atomic_exchange(&g_chunk_found, 1)) {
            strncpy(g_chunk_pass, pw_buf[match], MAX_PASS_LEN);
            g_chunk_pass[MAX_PASS_LEN] = '\0';
        }
    }
    return match;
}

/* ================================================================
 * R6 wait-and-check helper
 * ================================================================ */
static inline int r6_wait_and_check(void *handle, int count,
                                     const char **pw_buf)
{
    int match_type = 0;
    int match = (g_password_mode == PW_MODE_BOTH)
        ? metal_r6_wait_results_ex(g_r6_ctx, handle, count, &match_type)
        : metal_r6_wait_results(g_r6_ctx, handle, count);
    if (match >= 0) {
        if (!atomic_exchange(&g_chunk_found, 1)) {
            strncpy(g_chunk_pass, pw_buf[match], MAX_PASS_LEN);
            g_chunk_pass[MAX_PASS_LEN] = '\0';
        }
    }
    return match;
}

/* ================================================================
 * GPU R5 SHA-256 brute-force worker for client chunks
 * ================================================================ */
static void *gpu_sha256_brute_local_worker(void *arg)
{
    GPUBruteLocalArg *a = (GPUBruteLocalArg *)arg;

    /* Double-buffered password arrays for pipelining */
    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_chunk_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->total_end) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->total_end) end = a->total_end;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            index_to_password(start + i, a->length, g_charset, g_cs_len, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                      memory_order_relaxed);
        }

        pending_handle = metal_sha256_submit_async(g_sha256_ctx,
                                                    pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                  memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) {
        free(pw_ptrs[b]);
        free(pw_storage[b]);
    }
    free(arg);
    return NULL;
}

/* ================================================================
 * GPU R5 SHA-256 dictionary worker for client chunks
 * ================================================================ */
typedef struct { char **words; long count; } GPUSHA256DictLocalArg;

static void *gpu_sha256_dict_local_worker(void *arg)
{
    GPUSHA256DictLocalArg *a = (GPUSHA256DictLocalArg *)arg;

    const char **pw_ptrs[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        if (!pw_ptrs[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_chunk_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->count) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->count) end = a->count;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++)
            pw_ptrs[cur_buf][i] = a->words[start + i];

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                      memory_order_relaxed);
        }

        pending_handle = metal_sha256_submit_async(g_sha256_ctx,
                                                    pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                  memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) free(pw_ptrs[b]);
    free(arg);
    return NULL;
}

/* ================================================================
 * GPU R6 brute-force worker for client chunks
 * ================================================================ */
static void *gpu_r6_brute_local_worker(void *arg)
{
    GPUBruteLocalArg *a = (GPUBruteLocalArg *)arg;
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (batch > GPU_BATCH_SIZE) batch = GPU_BATCH_SIZE;

    /* Double-buffered password arrays for pipelining */
    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN + 1));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_chunk_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= a->total_end) break;
        long end = start + batch;
        if (end > a->total_end) end = a->total_end;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            index_to_password(start + i, a->length, g_charset, g_cs_len, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                      memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                  memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) {
        free(pw_ptrs[b]);
        free(pw_storage[b]);
    }
    free(arg);
    return NULL;
}

/* ================================================================
 * GPU R6 dictionary worker for client chunks
 * ================================================================ */
typedef struct { char **words; long count; } GPUR6DictLocalArg;

static void *gpu_r6_dict_local_worker(void *arg)
{
    GPUR6DictLocalArg *a = (GPUR6DictLocalArg *)arg;
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (batch > GPU_BATCH_SIZE) batch = GPU_BATCH_SIZE;

    const char **pw_ptrs[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        if (!pw_ptrs[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_chunk_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= a->count) break;
        long end = start + batch;
        if (end > a->count) end = a->count;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++)
            pw_ptrs[cur_buf][i] = a->words[start + i];

        if (pending_handle) {
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                      memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)pending_count,
                                  memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) free(pw_ptrs[b]);
    free(arg);
    return NULL;
}

/* ================================================================
 * Crack a brute-force chunk locally
 * Returns: 1 if found (password in g_chunk_pass), 0 if exhausted
 * ================================================================ */
static int crack_brute_chunk(int length, long start, long end)
{
    atomic_store(&g_chunk_found, 0);
    atomic_store(&g_chunk_tested, 0);
    atomic_store(&g_next_idx, start);
    g_chunk_pass[0] = '\0';

    long total = end - start;
    int  nt    = g_nthreads;
    if (nt > total) nt = (int)total;

    pthread_t threads[MAX_LOCAL_THREADS];
    int spawned = 0;

    if (g_use_gpu) {
        GPUBruteLocalArg *ga = malloc(sizeof(GPUBruteLocalArg));
        ga->length = length;
        ga->total_end = end;
        void *(*gpu_fn)(void *) = gpu_brute_local_worker;
        if (g_r6_ctx)       gpu_fn = gpu_r6_brute_local_worker;
        else if (g_sha256_ctx) gpu_fn = gpu_sha256_brute_local_worker;
        pthread_create(&threads[spawned++], NULL, gpu_fn, ga);

        /* CPU threads use shared counter */
        for (int t = 0; t < nt; t++) {
            BruteLocalArg *a = malloc(sizeof(BruteLocalArg));
            a->length = length;
            a->start  = start; /* unused in shared mode, but set for safety */
            a->end    = end;
            pthread_create(&threads[spawned++], NULL, brute_local_worker, a);
        }
    } else {
        long chunk = (total + nt - 1) / nt;
        for (int t = 0; t < nt; t++) {
            BruteLocalArg *a = malloc(sizeof(BruteLocalArg));
            a->length = length;
            a->start  = start + (long)t * chunk;
            a->end    = a->start + chunk;
            if (a->end > end) a->end = end;
            pthread_create(&threads[spawned++], NULL, brute_local_worker, a);
        }
    }
    for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

    return atomic_load(&g_chunk_found);
}

/* ================================================================
 * Crack a dictionary chunk locally
 * Returns: 1 if found (password in g_chunk_pass), 0 if exhausted
 * ================================================================ */
static int crack_dict_chunk(char **words, long count)
{
    atomic_store(&g_chunk_found, 0);
    atomic_store(&g_chunk_tested, 0);
    atomic_store(&g_next_idx, 0);
    g_chunk_pass[0] = '\0';

    int nt = g_nthreads;
    if (nt > count) nt = (int)count;

    pthread_t threads[MAX_LOCAL_THREADS];
    int spawned = 0;

    if (g_use_gpu) {
        if (g_r6_ctx) {
            GPUR6DictLocalArg *ga = malloc(sizeof(GPUR6DictLocalArg));
            ga->words = words;
            ga->count = count;
            pthread_create(&threads[spawned++], NULL, gpu_r6_dict_local_worker, ga);
        } else if (g_sha256_ctx) {
            GPUSHA256DictLocalArg *ga = malloc(sizeof(GPUSHA256DictLocalArg));
            ga->words = words;
            ga->count = count;
            pthread_create(&threads[spawned++], NULL, gpu_sha256_dict_local_worker, ga);
        } else {
            GPUDictLocalArg *ga = malloc(sizeof(GPUDictLocalArg));
            ga->words = words;
            ga->count = count;
            pthread_create(&threads[spawned++], NULL, gpu_dict_local_worker, ga);
        }
    }

    for (int t = 0; t < nt; t++) {
        DictLocalArg *a = malloc(sizeof(DictLocalArg));
        a->words  = words;
        a->start  = 0;
        a->count  = count;
        a->stride = g_use_gpu ? 1 : nt; /* shared counter uses stride=1 */
        a->offset = t;
        pthread_create(&threads[spawned++], NULL, dict_local_worker, a);
    }
    for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

    return atomic_load(&g_chunk_found);
}

/* ================================================================
 * Cleanup temp file on exit
 * ================================================================ */
static void cleanup(void)
{
    if (g_pdf_path[0]) unlink(g_pdf_path);
    if (g_server_fd >= 0) { close(g_server_fd); g_server_fd = -1; }
}

/* ================================================================
 * Bonjour/mDNS auto-discovery for _pdfcracker._tcp
 * ================================================================ */

/* Context passed through the chain of callbacks */
typedef struct {
    char     host[256];
    int      port;
    int      found;
    int      resolved;
    int      got_addr;
} DiscoverCtx;

/* Wait for a single dns_sd event with a timeout (seconds).
 * Returns 0 on success, -1 on timeout or error. */
static int dnssd_wait(DNSServiceRef ref, int timeout_secs)
{
    int fd = DNSServiceRefSockFD(ref);
    if (fd < 0) return -1;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    struct timeval tv = { .tv_sec = timeout_secs, .tv_usec = 0 };
    int ret = select(fd + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) return -1;

    DNSServiceErrorType err = DNSServiceProcessResult(ref);
    return (err == kDNSServiceErr_NoError) ? 0 : -1;
}

/* Callback: DNSServiceGetAddrInfo resolved hostname to IP */
static void DNSSD_API getaddr_callback(
    DNSServiceRef sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    DNSServiceErrorType errorCode,
    const char *hostname,
    const struct sockaddr *address,
    uint32_t ttl,
    void *context)
{
    (void)sdRef; (void)flags; (void)interfaceIndex;
    (void)hostname; (void)ttl;

    DiscoverCtx *ctx = (DiscoverCtx *)context;
    if (errorCode != kDNSServiceErr_NoError) return;
    if (ctx->got_addr) return;  /* take first result only */

    if (address->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)address;
        inet_ntop(AF_INET, &sin->sin_addr, ctx->host, sizeof(ctx->host));
        ctx->got_addr = 1;
    } else if (address->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)address;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ctx->host, sizeof(ctx->host));
        ctx->got_addr = 1;
    }
}

/* Callback: DNSServiceResolve found hostname + port */
static void DNSSD_API resolve_callback(
    DNSServiceRef sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    DNSServiceErrorType errorCode,
    const char *fullname,
    const char *hosttarget,
    uint16_t port,
    uint16_t txtLen,
    const unsigned char *txtRecord,
    void *context)
{
    (void)sdRef; (void)flags; (void)fullname;
    (void)txtLen; (void)txtRecord;

    DiscoverCtx *ctx = (DiscoverCtx *)context;
    if (errorCode != kDNSServiceErr_NoError) return;

    ctx->port = ntohs(port);
    ctx->resolved = 1;

    /* Now resolve the hostname to an IP address */
    DNSServiceRef addrRef = NULL;
    DNSServiceErrorType err = DNSServiceGetAddrInfo(
        &addrRef, 0, interfaceIndex,
        kDNSServiceProtocol_IPv4,
        hosttarget, getaddr_callback, ctx);

    if (err == kDNSServiceErr_NoError) {
        /* Wait up to 5 seconds for address resolution */
        dnssd_wait(addrRef, 5);
        DNSServiceRefDeallocate(addrRef);
    }
}

/* Callback: DNSServiceBrowse found a service instance */
static void DNSSD_API browse_callback(
    DNSServiceRef sdRef,
    DNSServiceFlags flags,
    uint32_t interfaceIndex,
    DNSServiceErrorType errorCode,
    const char *serviceName,
    const char *regtype,
    const char *replyDomain,
    void *context)
{
    (void)sdRef; (void)flags;

    DiscoverCtx *ctx = (DiscoverCtx *)context;
    if (errorCode != kDNSServiceErr_NoError) return;
    if (ctx->found) return;  /* take first service */

    ctx->found = 1;
    fprintf(stderr, "Bonjour: found \"%s\" (%s%s)\n",
            serviceName, regtype, replyDomain);

    /* Resolve this service to get hostname + port */
    DNSServiceRef resolveRef = NULL;
    DNSServiceErrorType err = DNSServiceResolve(
        &resolveRef, 0, interfaceIndex,
        serviceName, regtype, replyDomain,
        resolve_callback, ctx);

    if (err == kDNSServiceErr_NoError) {
        /* Wait up to 5 seconds for resolution */
        dnssd_wait(resolveRef, 5);
        DNSServiceRefDeallocate(resolveRef);
    }
}

/*
 * discover_server — Browse for _pdfcracker._tcp via Bonjour.
 * On success, writes the IP string into host_out (must be >= 256 bytes)
 * and the port into *port_out. Returns 0 on success, -1 on failure.
 */
static int discover_server(char *host_out, size_t host_out_sz, int *port_out)
{
    fprintf(stderr, "Searching for _pdfcracker._tcp via Bonjour...\n");

    DiscoverCtx ctx;
    memset(&ctx, 0, sizeof(ctx));

    DNSServiceRef browseRef = NULL;
    DNSServiceErrorType err = DNSServiceBrowse(
        &browseRef, 0, 0,
        "_pdfcracker._tcp", NULL,
        browse_callback, &ctx);

    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceBrowse failed: %d\n", (int)err);
        return -1;
    }

    /* Wait up to 5 seconds for a browse result */
    if (dnssd_wait(browseRef, 5) < 0 && !ctx.found) {
        fprintf(stderr, "Bonjour: no _pdfcracker._tcp service found "
                        "(timed out after 5s)\n");
        DNSServiceRefDeallocate(browseRef);
        return -1;
    }
    DNSServiceRefDeallocate(browseRef);

    if (!ctx.got_addr) {
        fprintf(stderr, "Bonjour: service found but could not resolve address\n");
        return -1;
    }

    snprintf(host_out, host_out_sz, "%s", ctx.host);
    *port_out = ctx.port;

    fprintf(stderr, "Bonjour: resolved to %s:%d\n", host_out, *port_out);
    return 0;
}

/* ================================================================
 * Connect to server
 * ================================================================ */
static int connect_to_server(const char *host, int port)
{
    struct hostent *he = gethostbyname(host);
    if (!he) { fprintf(stderr, "Cannot resolve: %s\n", host); return -1; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
    };
    memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    return fd;
}

/* ================================================================
 * SIGINT handler — graceful shutdown
 * ================================================================ */
static void sigint_handler(int sig)
{
    (void)sig;
    g_shutdown_requested = 1;
    /* Note: atomic_store is not async-signal-safe; the main thread
       will set g_chunk_found after checking g_shutdown_requested. */
}

/* ================================================================
 * Reset session-specific state for a new connection
 * ================================================================ */
static void reset_session_state(void)
{
    g_brute = 0;
    g_max_len = 0;
    g_charset[0] = '\0';
    g_cs_len = 0;
    g_fast_crypto = 0;
    g_use_gpu = 0;
    if (g_gpu_ctx) { metal_keygen_free(g_gpu_ctx); g_gpu_ctx = NULL; }
    if (g_sha256_ctx) { metal_sha256_free(g_sha256_ctx); g_sha256_ctx = NULL; }
    if (g_r6_ctx) { metal_r6_free(g_r6_ctx); g_r6_ctx = NULL; }
    g_current_lease_id = 0;
    memset(&g_enc_params, 0, sizeof(g_enc_params));
    if (g_pdf_path[0]) { unlink(g_pdf_path); g_pdf_path[0] = '\0'; }
}

/* ================================================================
 * run_session — single connection lifecycle
 * Returns: 0 = done/found, 1 = disconnected (retry), 2 = shutdown
 * ================================================================ */
static int run_session(const char *host, int port)
{
    reset_session_state();

    /* ── Connect ───────────────────────────────────────────────── */
    fprintf(stderr, "Connecting to %s:%d ...\n", host, port);
    int fd = connect_to_server(host, port);
    if (fd < 0) return 1;
    g_server_fd = fd;
    fprintf(stderr, "Connected.\n");

    char line[MAX_LINE];

    /* ── Handshake ─────────────────────────────────────────────── */
    sock_printf(fd, "HELLO %d %s %d", g_nthreads, g_client_uuid, PROTO_VERSION);

    /* ── Receive CONFIG ────────────────────────────────────────── */
    if (sock_readline(fd, line, sizeof(line)) < 0) {
        fprintf(stderr, "Lost connection during config\n");
        close(fd); g_server_fd = -1;
        return 1;
    }

    int pw_mode_tmp = PW_MODE_BOTH;
    if (sscanf(line, "CONFIG BRUTE %d %d", &g_max_len, &pw_mode_tmp) >= 1) {
        g_brute = 1;
        g_password_mode = pw_mode_tmp;
        /* Read CHARSET line */
        if (sock_readline(fd, line, sizeof(line)) < 0) {
            close(fd); g_server_fd = -1; return 1;
        }
        if (strncmp(line, "CHARSET ", 8) != 0) {
            fprintf(stderr, "Expected CHARSET, got: %s\n", line);
            close(fd); g_server_fd = -1; return 1;
        }
        strncpy(g_charset, line + 8, sizeof(g_charset) - 1);
        g_cs_len = (int)strlen(g_charset);
        fprintf(stderr, "Mode: brute-force (len 1..%d, charset \"%s\", pw_mode %d)\n",
                g_max_len, g_charset, g_password_mode);
    } else if (sscanf(line, "CONFIG DICT %d", &pw_mode_tmp) >= 0 &&
               strncmp(line, "CONFIG DICT", 11) == 0) {
        g_brute = 0;
        if (sscanf(line, "CONFIG DICT %d", &pw_mode_tmp) == 1)
            g_password_mode = pw_mode_tmp;
        fprintf(stderr, "Mode: dictionary (pw_mode %d)\n", g_password_mode);
    } else {
        fprintf(stderr, "Unknown config: %s\n", line);
        close(fd); g_server_fd = -1; return 1;
    }

    /* ── Receive optional protocol messages (PWMODE, etc.) then PDF ── */
    if (sock_readline(fd, line, sizeof(line)) < 0) {
        close(fd); g_server_fd = -1; return 1;
    }

    /* Handle PWMODE if present (v4 protocol) */
    if (strncmp(line, "PWMODE ", 7) == 0) {
        if (strcmp(line + 7, "user") == 0) g_password_mode = PW_MODE_USER;
        else if (strcmp(line + 7, "owner") == 0) g_password_mode = PW_MODE_OWNER;
        else g_password_mode = PW_MODE_BOTH;
        fprintf(stderr, "Password mode: %s\n", line + 7);
        /* Read the next line (should be PDF) */
        if (sock_readline(fd, line, sizeof(line)) < 0) {
            close(fd); g_server_fd = -1; return 1;
        }
    }

    /* Skip any other unknown protocol lines until we get PDF */
    while (strncmp(line, "PDF ", 4) != 0) {
        fprintf(stderr, "Ignoring unknown config line: %s\n", line);
        if (sock_readline(fd, line, sizeof(line)) < 0) {
            close(fd); g_server_fd = -1; return 1;
        }
    }

    long pdf_size = 0;
    if (sscanf(line, "PDF %ld", &pdf_size) != 1 || pdf_size <= 0) {
        fprintf(stderr, "Bad PDF header: %s\n", line);
        close(fd); g_server_fd = -1; return 1;
    }

    unsigned char *pdf_buf = malloc((size_t)pdf_size);
    if (!pdf_buf) { perror("malloc"); close(fd); g_server_fd = -1; return 1; }
    if (read_exact(fd, pdf_buf, (size_t)pdf_size) < 0) {
        fprintf(stderr, "Failed to receive PDF (%ld bytes)\n", pdf_size);
        free(pdf_buf); close(fd); g_server_fd = -1; return 1;
    }

    /* Save to temp file (unpredictable name, restricted permissions) */
    snprintf(g_pdf_path, sizeof(g_pdf_path), "/tmp/pdfcrack_XXXXXX");
    int tmpfd = mkstemp(g_pdf_path);
    if (tmpfd < 0) {
        perror("mkstemp");
        free(pdf_buf); close(fd); g_server_fd = -1; return 1;
    }
    fchmod(tmpfd, 0600);
    FILE *pf = fdopen(tmpfd, "wb");
    if (!pf) {
        perror(g_pdf_path);
        close(tmpfd);
        free(pdf_buf); close(fd); g_server_fd = -1; return 1;
    }
    fwrite(pdf_buf, 1, (size_t)pdf_size, pf);
    fclose(pf);

    /* Parse encryption params from raw bytes before freeing */
    g_enc_params = pdf_parse_encrypt(pdf_buf, (size_t)pdf_size);
    if (g_enc_params.valid) {
        g_fast_crypto = 1;
        if (g_enc_params.revision >= 5)
            fprintf(stderr, "Crypto : direct SHA-256+AES (R%d, %d-bit)\n",
                    g_enc_params.revision, g_enc_params.key_length);
        else
            fprintf(stderr, "Crypto : direct MD5+RC4 (R%d, %d-bit)\n",
                    g_enc_params.revision, g_enc_params.key_length);
    } else {
        fprintf(stderr, "Crypto : CGPDFDocument fallback\n");
    }
    free(pdf_buf);

    /* Try GPU acceleration */
    if (g_fast_crypto && !g_no_gpu && g_enc_params.revision <= 4) {
        g_gpu_ctx = metal_keygen_init(&g_enc_params, NULL);
        if (g_gpu_ctx) {
            if (benchmark_gpu()) {
                g_use_gpu = 1;
            } else {
                metal_keygen_free(g_gpu_ctx);
                g_gpu_ctx = NULL;
            }
        }
    } else if (g_fast_crypto && !g_no_gpu && g_enc_params.revision == 5) {
        int check_owner = (g_password_mode == PW_MODE_OWNER) ? 1 :
                           (g_password_mode == PW_MODE_BOTH) ? 2 : 0;
        g_sha256_ctx = metal_sha256_init(&g_enc_params, check_owner, NULL);
        if (g_sha256_ctx) {
            if (benchmark_gpu()) {
                g_use_gpu = 1;
            } else {
                metal_sha256_free(g_sha256_ctx);
                g_sha256_ctx = NULL;
            }
        }
    } else if (g_fast_crypto && !g_no_gpu && g_enc_params.revision == 6) {
        int check_owner = (g_password_mode == PW_MODE_OWNER) ? 1 :
                           (g_password_mode == PW_MODE_BOTH) ? 2 : 0;
        g_r6_ctx = metal_r6_init(&g_enc_params, check_owner, NULL);
        if (g_r6_ctx) {
            if (benchmark_gpu()) {
                g_use_gpu = 1;
            } else {
                metal_r6_free(g_r6_ctx);
                g_r6_ctx = NULL;
            }
        }
    }

    fprintf(stderr, "PDF received (%ld bytes) -> %s\n", pdf_size, g_pdf_path);

    /* Verify we can open it */
    CGPDFDocumentRef probe = open_pdf();
    if (!probe) {
        fprintf(stderr, "Cannot open received PDF\n");
        close(fd); g_server_fd = -1; return 1;
    }
    CGPDFDocumentRelease(probe);

    /* ── Signal ready ──────────────────────────────────────────── */
    sock_printf(fd, "READY");
    fprintf(stderr, "Using %d threads. Requesting work...\n\n", g_nthreads);

    /* ── Work loop ─────────────────────────────────────────────── */
    long   prev_tested  = 0;
    double prev_elapsed = 0.0;
    int    chunks_done  = 0;

    for (;;) {
        if (g_shutdown_requested) {
            /* Stop worker threads from main thread (async-signal-safe) */
            atomic_store(&g_chunk_found, 1);
            /* If we have an active lease, send PARTIAL with high-water mark */
            if (g_current_lease_id > 0) {
                long hwm = atomic_load(&g_next_idx);
                sock_printf(fd, "PARTIAL %lu %ld", (unsigned long)g_current_lease_id, hwm);
            }
            close(fd); g_server_fd = -1;
            return 2;
        }

        /* Request next chunk, reporting stats from previous */
        sock_printf(fd, "GETWORK %ld %.2f", prev_tested, prev_elapsed);

        if (sock_readline(fd, line, sizeof(line)) < 0) {
            fprintf(stderr, "\nLost connection to server\n");
            close(fd); g_server_fd = -1;
            return 1;
        }

        /* ── BRUTE <length> <start> <end> <lease_id> ──────────── */
        int      blen = 0;
        long     bstart = 0, bend = 0;
        uint64_t lease_id = 0;

        if (sscanf(line, "BRUTE %d %ld %ld %lu", &blen, &bstart, &bend,
                   (unsigned long *)&lease_id) == 4) {
            g_current_lease_id = lease_id;
            fprintf(stderr, "\r  chunk %d: brute len=%d [%ld..%ld) (%ld passwords) lease=%lu   \n",
                    ++chunks_done, blen, bstart, bend, bend - bstart,
                    (unsigned long)lease_id);
            fflush(stderr);

            double t0 = mono_time();
            int found = crack_brute_chunk(blen, bstart, bend);
            double elapsed = mono_time() - t0;

            if (found) {
                sock_printf(fd, "FOUND %s %lu", g_chunk_pass,
                            (unsigned long)lease_id);
                /* Wait for OK */
                sock_readline(fd, line, sizeof(line));
                fprintf(stderr,
                    "\n\n  *** PASSWORD FOUND: %s ***\n\n", g_chunk_pass);
                close(fd); g_server_fd = -1;
                return 0;
            }

            if (g_shutdown_requested) {
                long hwm = atomic_load(&g_next_idx);
                sock_printf(fd, "PARTIAL %lu %ld",
                            (unsigned long)lease_id, hwm);
                close(fd); g_server_fd = -1;
                return 2;
            }

            prev_tested = atomic_load(&g_chunk_tested);
            prev_elapsed = elapsed;

            /* Send COMPLETE for this lease */
            sock_printf(fd, "COMPLETE %lu %ld",
                        (unsigned long)lease_id, prev_tested);
            g_current_lease_id = 0;

            fprintf(stderr, "\r  chunk %d done (%.1fs, %ld tested)   ",
                    chunks_done, elapsed, prev_tested);
            fflush(stderr);
        }

        /* ── DICT <count> <lease_id> followed by words ─────────── */
        else if (strncmp(line, "DICT ", 5) == 0) {
            long count = 0;
            if (sscanf(line, "DICT %ld %lu", &count,
                       (unsigned long *)&lease_id) != 2) {
                fprintf(stderr, "Bad DICT line: %s\n", line);
                close(fd); g_server_fd = -1;
                return 1;
            }
            g_current_lease_id = lease_id;

            #define MAX_DICT_CHUNK 1000000
            if (count <= 0 || count > MAX_DICT_CHUNK) {
                fprintf(stderr, "Bad dict count: %ld\n", count);
                close(fd); g_server_fd = -1; return 1;
            }
            char **words = malloc((size_t)count * sizeof(char *));
            if (!words) { perror("malloc"); close(fd); g_server_fd = -1; return 1; }
            SockBuf sbuf;
            sockbuf_init(&sbuf, fd);
            long loaded = 0;
            for (long i = 0; i < count; i++) {
                char word[MAX_PASS_LEN + 4];
                if (sockbuf_readline(&sbuf, word, sizeof(word)) < 0) break;
                words[loaded] = strdup(word);
                if (words[loaded]) loaded++;
            }

            fprintf(stderr, "\r  chunk %d: dict (%ld words) lease=%lu   \n",
                    ++chunks_done, loaded, (unsigned long)lease_id);
            fflush(stderr);

            double t0 = mono_time();
            int found = crack_dict_chunk(words, loaded);
            double elapsed = mono_time() - t0;

            if (found) {
                sock_printf(fd, "FOUND %s %lu", g_chunk_pass,
                            (unsigned long)lease_id);
                sock_readline(fd, line, sizeof(line));
                fprintf(stderr,
                    "\n\n  *** PASSWORD FOUND: %s ***\n\n", g_chunk_pass);
                for (long i = 0; i < loaded; i++) free(words[i]);
                free(words);
                close(fd); g_server_fd = -1;
                return 0;
            }

            if (g_shutdown_requested) {
                long hwm = atomic_load(&g_next_idx);
                sock_printf(fd, "PARTIAL %lu %ld",
                            (unsigned long)lease_id, hwm);
                for (long i = 0; i < loaded; i++) free(words[i]);
                free(words);
                close(fd); g_server_fd = -1;
                return 2;
            }

            prev_tested = atomic_load(&g_chunk_tested);
            prev_elapsed = elapsed;

            /* Send COMPLETE for this lease */
            sock_printf(fd, "COMPLETE %lu %ld",
                        (unsigned long)lease_id, prev_tested);
            g_current_lease_id = 0;

            fprintf(stderr, "\r  chunk %d done (%.1fs, %ld tested)   ",
                    chunks_done, elapsed, prev_tested);
            fflush(stderr);

            for (long i = 0; i < loaded; i++) free(words[i]);
            free(words);
        }

        /* ── FOUND <password> ─────────────────────────────────── */
        else if (strncmp(line, "FOUND ", 6) == 0) {
            fprintf(stderr,
                "\n\n  *** PASSWORD FOUND (by another client): %s ***\n\n",
                line + 6);
            close(fd); g_server_fd = -1;
            return 0;
        }

        /* ── DONE ─────────────────────────────────────────────── */
        else if (strcmp(line, "DONE") == 0) {
            fprintf(stderr,
                "\n  All work exhausted. %d chunks tested.\n", chunks_done);
            close(fd); g_server_fd = -1;
            return 0;
        }

        /* ── ABORT ────────────────────────────────────────────── */
        else if (strcmp(line, "ABORT") == 0) {
            fprintf(stderr, "\n  Server sent ABORT (password found elsewhere).\n");
            close(fd); g_server_fd = -1;
            return 0;
        }

        else {
            fprintf(stderr, "\nUnexpected response: %s\n", line);
            close(fd); g_server_fd = -1;
            return 1;
        }
    }
}

/* ================================================================
 * reconnect_loop — retry with exponential backoff
 * Returns: 0 = done, 1 = gave up
 * ================================================================ */
static int reconnect_loop(const char *host, int port)
{
    int delay = RECONNECT_BASE_SEC;

    for (int attempt = 1; attempt <= RECONNECT_MAX_TRIES; attempt++) {
        int result = run_session(host, port);
        if (result == 0) return 0;  /* done/found */
        if (result == 2) return 0;  /* shutdown requested */

        /* result == 1: disconnected, retry */
        if (attempt < RECONNECT_MAX_TRIES) {
            fprintf(stderr, "Reconnecting in %ds (attempt %d/%d)...\n",
                    delay, attempt, RECONNECT_MAX_TRIES);
            sleep((unsigned)delay);
            delay *= 2;
            if (delay > RECONNECT_MAX_SEC) delay = RECONNECT_MAX_SEC;
        }
    }
    fprintf(stderr, "Max reconnection attempts (%d) reached. Giving up.\n",
            RECONNECT_MAX_TRIES);
    return 1;
}

/* ================================================================
 * Usage
 * ================================================================ */
static void usage(const char *p)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [-s <server_host>] [-p <port>] [-t <threads>] [-G]\n"
        "\nConnects to a pdfcrack server and cracks locally.\n"
        "Without -s, auto-discovers the server via Bonjour (mDNS).\n"
        "  -G  disable GPU acceleration\n", p);
    exit(1);
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    const char *host = NULL;
    int port     = DEFAULT_PORT;
    int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 4;

    int opt;
    while ((opt = getopt(argc, argv, "s:p:t:G")) != -1) {
        switch (opt) {
            case 's': host     = optarg;       break;
            case 'p': port     = atoi(optarg); break;
            case 't': nthreads = atoi(optarg); break;
            case 'G': g_no_gpu = 1;            break;
            default:  usage(argv[0]);
        }
    }

    if (nthreads > 64) nthreads = 64;
    g_nthreads = nthreads;
    atexit(cleanup);

    /* Install SIGINT handler for graceful shutdown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    /* Ensure we have a persistent UUID */
    ensure_uuid();
    fprintf(stderr, "Client UUID: %s\n", g_client_uuid);
    fprintf(stderr, "Threads: %d, GPU: %s\n", nthreads,
            g_no_gpu ? "disabled" : "auto");

    /* If no host specified, auto-discover via Bonjour */
    char discovered_host[256];
    if (!host) {
        if (discover_server(discovered_host, sizeof(discovered_host),
                            &port) < 0) {
            fprintf(stderr, "Auto-discovery failed. "
                            "Use -s <host> to specify manually.\n");
            return 1;
        }
        host = discovered_host;
    }

    /* Run with auto-reconnect */
    int rc = reconnect_loop(host, port);

    if (g_gpu_ctx) { metal_keygen_free(g_gpu_ctx); g_gpu_ctx = NULL; }
    return rc;
}
