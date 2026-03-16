/*
 * client.c — Distributed PDF cracker worker node
 *
 * Connects to a server, receives the PDF and work config, then cracks
 * locally using all CPU cores + optional Metal GPU via pthreads.
 *
 * Build:
 *   make client
 *
 * Usage:
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

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

/* Batch size for atomic counter updates — avoids cache-line thrashing */
#define TESTED_BATCH 256

/* ── Local state ──────────────────────────────────────────────── */
static int   g_nthreads = 0;
static char  g_pdf_path[256] = {0};  /* temp file */
static int   g_server_fd = -1;

/* ── Fast crypto path ─────────────────────────────────────────── */
static PDFEncryptParams g_enc_params;
static int              g_fast_crypto = 0;

/* ── GPU acceleration ──────────────────────────────────────────── */
#define GPU_BATCH_SIZE  65536
#define CPU_WORK_CHUNK  512
static MetalKeygenContext *g_gpu_ctx = NULL;
static int                 g_use_gpu = 0;
static atomic_long         g_next_idx = 0;

/* ── Mode config (received from server) ───────────────────────── */
static int   g_brute    = 0;
static int   g_max_len  = 0;
static char  g_charset[256] = {0};
static int   g_cs_len   = 0;

/* ── Per-chunk shared state (reset each chunk) ────────────────── */
static atomic_int  g_chunk_found  = 0;
static char        g_chunk_pass[MAX_PASS_LEN + 1] = {0};
static atomic_long g_chunk_tested = 0;

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
                int hit = g_fast_crypto ? pdf_verify_password(&g_enc_params, pass)
                                        : test_password(doc, pass);
                if (hit) {
                    if (!atomic_exchange(&g_chunk_found, 1))
                        strncpy(g_chunk_pass, pass, MAX_PASS_LEN);
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
            int hit = g_fast_crypto ? pdf_verify_password(&g_enc_params, pass)
                                    : test_password(doc, pass);
            if (hit) {
                if (!atomic_exchange(&g_chunk_found, 1))
                    strncpy(g_chunk_pass, pass, MAX_PASS_LEN);
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
                int hit = g_fast_crypto ? pdf_verify_password(&g_enc_params, a->words[i])
                                        : test_password(doc, a->words[i]);
                if (hit) {
                    if (!atomic_exchange(&g_chunk_found, 1))
                        strncpy(g_chunk_pass, a->words[i], MAX_PASS_LEN);
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
            int hit = g_fast_crypto ? pdf_verify_password(&g_enc_params, a->words[i])
                                    : test_password(doc, a->words[i]);
            if (hit) {
                if (!atomic_exchange(&g_chunk_found, 1))
                    strncpy(g_chunk_pass, a->words[i], MAX_PASS_LEN);
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
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);

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
        int n = metal_keygen_batch(g_gpu_ctx, pw_ptrs, count, keys);
        if (n <= 0) break;
        verify_keys_rc4(keys, pw_ptrs, n, key_bytes);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)n, memory_order_relaxed);
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
        int n = metal_keygen_batch(g_gpu_ctx, (const char **)pw_ptrs, count, keys);
        if (n <= 0) break;
        verify_keys_rc4(keys, pw_ptrs, n, key_bytes);
        atomic_fetch_add_explicit(&g_chunk_tested, (long)n, memory_order_relaxed);
    }
done:
    free(pw_ptrs); free(keys); free(arg);
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

    pthread_t threads[MAX_CLIENTS + 1];
    int spawned = 0;

    if (g_use_gpu) {
        GPUBruteLocalArg *ga = malloc(sizeof(GPUBruteLocalArg));
        ga->length = length;
        ga->total_end = end;
        pthread_create(&threads[spawned++], NULL, gpu_brute_local_worker, ga);

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

    pthread_t threads[MAX_CLIENTS + 1];
    int spawned = 0;

    if (g_use_gpu) {
        GPUDictLocalArg *ga = malloc(sizeof(GPUDictLocalArg));
        ga->words = words;
        ga->count = count;
        pthread_create(&threads[spawned++], NULL, gpu_dict_local_worker, ga);
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
    if (g_server_fd >= 0) close(g_server_fd);
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
 * Usage
 * ================================================================ */
static void usage(const char *p)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s -s <server_host> [-p <port>] [-t <threads>] [-G]\n"
        "\nConnects to a pdfcrack server and cracks locally.\n"
        "  -G  disable GPU acceleration\n", p);
    exit(1);
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    const char *host = NULL;
    int port     = DEFAULT_PORT;
    int no_gpu   = 0;
    int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 4;

    int opt;
    while ((opt = getopt(argc, argv, "s:p:t:G")) != -1) {
        switch (opt) {
            case 's': host     = optarg;       break;
            case 'p': port     = atoi(optarg); break;
            case 't': nthreads = atoi(optarg); break;
            case 'G': no_gpu   = 1;            break;
            default:  usage(argv[0]);
        }
    }

    if (!host) { fprintf(stderr, "-s required\n"); usage(argv[0]); }
    g_nthreads = nthreads;
    atexit(cleanup);

    fprintf(stderr, "Connecting to %s:%d ...\n", host, port);

    /* ── Connect ───────────────────────────────────────────────── */
    int fd = connect_to_server(host, port);
    if (fd < 0) return 1;
    g_server_fd = fd;
    fprintf(stderr, "Connected.\n");

    /* ── Handshake ─────────────────────────────────────────────── */
    sock_printf(fd, "HELLO %d", nthreads);

    char line[MAX_LINE];

    /* ── Receive CONFIG ────────────────────────────────────────── */
    if (sock_readline(fd, line, sizeof(line)) < 0) {
        fprintf(stderr, "Lost connection during config\n"); return 1;
    }

    if (sscanf(line, "CONFIG BRUTE %d", &g_max_len) == 1) {
        g_brute = 1;
        /* Read CHARSET line */
        if (sock_readline(fd, line, sizeof(line)) < 0) return 1;
        if (strncmp(line, "CHARSET ", 8) != 0) {
            fprintf(stderr, "Expected CHARSET, got: %s\n", line);
            return 1;
        }
        strncpy(g_charset, line + 8, sizeof(g_charset) - 1);
        g_cs_len = (int)strlen(g_charset);
        fprintf(stderr, "Mode: brute-force (len 1..%d, charset \"%s\")\n",
                g_max_len, g_charset);
    } else if (strcmp(line, "CONFIG DICT") == 0) {
        g_brute = 0;
        fprintf(stderr, "Mode: dictionary\n");
    } else {
        fprintf(stderr, "Unknown config: %s\n", line);
        return 1;
    }

    /* ── Receive PDF ───────────────────────────────────────────── */
    if (sock_readline(fd, line, sizeof(line)) < 0) return 1;
    long pdf_size = 0;
    if (sscanf(line, "PDF %ld", &pdf_size) != 1 || pdf_size <= 0) {
        fprintf(stderr, "Bad PDF header: %s\n", line);
        return 1;
    }

    unsigned char *pdf_buf = malloc((size_t)pdf_size);
    if (!pdf_buf) { perror("malloc"); return 1; }
    if (read_exact(fd, pdf_buf, (size_t)pdf_size) < 0) {
        fprintf(stderr, "Failed to receive PDF (%ld bytes)\n", pdf_size);
        return 1;
    }

    /* Save to temp file */
    snprintf(g_pdf_path, sizeof(g_pdf_path), "/tmp/pdfcrack_%d.pdf", getpid());
    FILE *pf = fopen(g_pdf_path, "wb");
    if (!pf) { perror(g_pdf_path); return 1; }
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

    /* Try GPU acceleration (only for R2-R4, Metal shader does MD5) */
    if (g_fast_crypto && !no_gpu && g_enc_params.revision <= 4) {
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

    fprintf(stderr, "PDF received (%ld bytes) → %s\n", pdf_size, g_pdf_path);

    /* Verify we can open it */
    CGPDFDocumentRef probe = open_pdf();
    if (!probe) {
        fprintf(stderr, "Cannot open received PDF\n");
        return 1;
    }
    CGPDFDocumentRelease(probe);

    /* ── Signal ready ──────────────────────────────────────────── */
    sock_printf(fd, "READY");
    fprintf(stderr, "Using %d threads. Requesting work...\n\n", nthreads);

    /* ── Work loop ─────────────────────────────────────────────── */
    long prev_tested = 0;
    int  chunks_done = 0;
    time_t t0 = time(NULL);

    for (;;) {
        /* Request next chunk, reporting tested count from previous */
        sock_printf(fd, "GETWORK %ld", prev_tested);

        if (sock_readline(fd, line, sizeof(line)) < 0) {
            fprintf(stderr, "\nLost connection to server\n");
            break;
        }

        /* ── BRUTE <length> <start> <end> ─────────────────────── */
        int  blen = 0;
        long bstart = 0, bend = 0;
        if (sscanf(line, "BRUTE %d %ld %ld", &blen, &bstart, &bend) == 3) {
            fprintf(stderr, "\r  chunk %d: brute len=%d [%ld..%ld) (%ld passwords)   \n",
                    ++chunks_done, blen, bstart, bend, bend - bstart);
            fflush(stderr);

            if (crack_brute_chunk(blen, bstart, bend)) {
                sock_printf(fd, "FOUND %s", g_chunk_pass);
                /* Wait for OK */
                sock_readline(fd, line, sizeof(line));
                fprintf(stderr,
                    "\n\n  *** PASSWORD FOUND: %s ***\n\n", g_chunk_pass);
                break;
            }

            prev_tested = atomic_load(&g_chunk_tested);

            long elapsed = (long)(time(NULL) - t0);
            if (elapsed > 0)
                fprintf(stderr, "\r  chunk %d done. avg rate: ~%ld/s   ",
                        chunks_done, prev_tested);
            fflush(stderr);
        }

        /* ── DICT <count> followed by words ───────────────────── */
        else if (strncmp(line, "DICT ", 5) == 0) {
            long count = 0;
            sscanf(line, "DICT %ld", &count);

            char **words = malloc((size_t)count * sizeof(char *));
            long loaded = 0;
            for (long i = 0; i < count; i++) {
                char word[MAX_PASS_LEN + 4];
                if (sock_readline(fd, word, sizeof(word)) < 0) break;
                words[loaded] = strdup(word);
                if (words[loaded]) loaded++;
            }

            fprintf(stderr, "\r  chunk %d: dict (%ld words)   \n",
                    ++chunks_done, loaded);
            fflush(stderr);

            if (crack_dict_chunk(words, loaded)) {
                sock_printf(fd, "FOUND %s", g_chunk_pass);
                sock_readline(fd, line, sizeof(line));
                fprintf(stderr,
                    "\n\n  *** PASSWORD FOUND: %s ***\n\n", g_chunk_pass);
                for (long i = 0; i < loaded; i++) free(words[i]);
                free(words);
                break;
            }

            prev_tested = atomic_load(&g_chunk_tested);
            for (long i = 0; i < loaded; i++) free(words[i]);
            free(words);
        }

        /* ── FOUND <password> ─────────────────────────────────── */
        else if (strncmp(line, "FOUND ", 6) == 0) {
            fprintf(stderr,
                "\n\n  *** PASSWORD FOUND (by another client): %s ***\n\n",
                line + 6);
            break;
        }

        /* ── DONE ─────────────────────────────────────────────── */
        else if (strcmp(line, "DONE") == 0) {
            fprintf(stderr,
                "\n  All work exhausted. %d chunks tested.\n", chunks_done);
            break;
        }

        else {
            fprintf(stderr, "\nUnexpected response: %s\n", line);
            break;
        }
    }

    if (g_gpu_ctx) metal_keygen_free(g_gpu_ctx);
    return 0;
}
