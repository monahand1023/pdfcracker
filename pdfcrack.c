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
 *   pdfcrack -f file.pdf -m "?u?u?u?d?d?d?d?d"     # mask attack
 *   pdfcrack -f file.pdf -d words.txt -R             # rules mutation
 *   pdfcrack -f file.pdf -d words.txt -H 3           # hybrid dict+suffix
 *   pdfcrack -f file.pdf -d words.txt -H "?d?d?d?s"  # hybrid dict+mask
 *   pdfcrack -f file.pdf -B                          # benchmark mode
 *   pdfcrack -f file.pdf -b -l 6 -F                  # freq-ordered brute
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
#include <signal.h>
#include <mach/mach_time.h>
#include <ctype.h>
#include <getopt.h>
#include "pdf_encrypt.h"
#include "metal_keygen.h"
#include "md5_simd.h"

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
#define CKPT_INTERVAL 5  /* seconds between checkpoint saves */

/* ── async-safe interrupt flag ────────────────────────────────── */
static volatile sig_atomic_t g_interrupted = 0;

/* ── shared state ─────────────────────────────────────────────── */
static atomic_int  g_found   = 0;
static char        g_password[MAX_PASS_LEN + 1] = {0};
static atomic_long g_tested  = 0;
static atomic_long g_total   = 0;   /* 0 = unknown */

/* ── overall progress (brute-force across all lengths) ─────────── */
static long        g_overall_total  = 0;  /* precomputed total across all lengths */
static atomic_int  g_current_len    = 0;  /* current password length being tested */
static long        g_completed_prior = 0; /* completed candidates from prior lengths */

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
static MetalKeygenContext *g_gpu_ctx     = NULL;
static MetalSHA256Context *g_sha256_ctx __attribute__((unused)) = NULL;  /* R5 SHA-256 GPU pipeline */
static MetalR6Context     *g_r6_ctx    __attribute__((unused)) = NULL;  /* R6 GPU pipeline */
static int                 g_use_gpu    = 0;
static atomic_long         g_next_idx   = 0; /* shared work counter for GPU+CPU */

/* ── NEON SIMD batch mode (R2-R4 only) ────────────────────────── */
static int                 g_use_neon  = 0;

/* ── dictionary word list ─────────────────────────────────────── */
static char **g_words  = NULL;
static long   g_nwords = 0;

/* ── checkpoint/resume ────────────────────────────────────────── */
static char g_ckpt_path[1024] = {0};
static int  g_is_brute = 0;  /* 1 = brute-force, 0 = dictionary (for checkpoint) */

/* Attack mode identifiers for checkpoint */
#define ATTACK_BRUTE   0
#define ATTACK_DICT    1
#define ATTACK_MASK    2
#define ATTACK_RULE    3
#define ATTACK_HYBRID  4
#define ATTACK_AUTO    5
static int g_attack_mode = ATTACK_BRUTE;  /* current attack mode for checkpoint */
static int g_auto_phase  = 0;             /* current phase within auto mode */

/* ── prefix/suffix for guided brute-force ─────────────────────── */
static char g_prefix[MAX_PASS_LEN + 1] = {0};
static char g_suffix[MAX_PASS_LEN + 1] = {0};
static int  g_prefix_len = 0;
static int  g_suffix_len = 0;

/* ── Mask attack ─────────────────────────────────────────────── */
typedef struct { char *chars; int nchars; int is_word; } MaskPos;
static MaskPos  g_mask[MAX_PASS_LEN];
static int      g_mask_len   = 0;
static long     g_mask_keyspace = 0;
static int      g_mask_mode  = 0;
static char     g_mask_str[256] = {0};  /* original mask pattern for checkpoint */

/* ── Custom mask charsets (?1 through ?4) ────────────────────── */
static char *g_custom_charset[4] = { NULL, NULL, NULL, NULL };
static char  g_custom_charset_str[4][256] = {{0}}; /* for checkpoint */

/* ── Rule-based mutations ────────────────────────────────────── */
#define MAX_RULES 4096
#define MAX_OPS_PER_RULE 8
typedef enum {
    RULE_NOOP,           /* : (as-is) */
    RULE_LOWER,          /* l */
    RULE_UPPER,          /* u */
    RULE_CAPITALIZE,     /* c */
    RULE_REVERSE,        /* r */
    RULE_DUPLICATE,      /* d */
    RULE_APPEND_CHAR,    /* $X */
    RULE_PREPEND_CHAR,   /* ^X */
    RULE_CAP_APPEND,     /* cX (capitalize + append) — built-in only */
    RULE_TOGGLE_AT,      /* TN: toggle case at position N */
    RULE_INSERT_AT,      /* iNX: insert char X at position N */
    RULE_OVERWRITE_AT,   /* oNX: overwrite position N with X */
    RULE_DELETE_AT,      /* DN: delete char at position N */
    RULE_TRUNCATE_LEFT,  /* [N: remove first N chars */
    RULE_TRUNCATE_RIGHT, /* ]N: keep only first N chars */
    RULE_REPLACE,        /* sXY: replace all X with Y */
    RULE_PURGE,          /* @X: remove all X */
    RULE_DUPLICATE_N,    /* pN: repeat word N times */
    RULE_DUP_FIRST_N,    /* yN: duplicate first N chars, prepend */
    RULE_DUP_LAST_N,     /* YN: duplicate last N chars, append */
    RULE_SWAP,           /* *NM: swap positions N and M */
    RULE_LEET,           /* common l33t substitutions */
} RuleType;
typedef struct {
    int nops;
    struct { RuleType type; char ch; char ch2; int pos; } ops[MAX_OPS_PER_RULE];
} Rule;
static Rule g_rules[MAX_RULES];
static int  g_nrules = 0;
static int  g_rule_mode = 0;
static const char *g_rules_file = NULL;

/* ── Hybrid attack ───────────────────────────────────────────── */
static int  g_hybrid_mode = 0;
static int  g_hybrid_suffix_len = 0;
static long g_hybrid_suffix_keyspace = 0;
static int  g_hybrid_mask_mode = 0;          /* 1 = mask-based suffix */
static MaskPos g_hybrid_mask[MAX_PASS_LEN];
static int  g_hybrid_mask_len = 0;
static char g_hybrid_mask_str[256] = {0};

/* ── Benchmark mode ──────────────────────────────────────────── */
static int  g_benchmark_mode = 0;

/* ── Frequency-ordered charset ───────────────────────────────── */
#define FREQ_CHARSET \
    "eariotnslcudpmhgbfywkvxzjq0123456789EARIOTNSLCUDPMHGBFYWKVXZJQ"
static int  g_freq_mode = 0;

/* ── Auto mode ───────────────────────────────────────────────── */
static int  g_auto_mode = 0;

/* ── Password mode (user/owner/both) ─────────────────────────── */
#define PW_MODE_BOTH  0
#define PW_MODE_USER  1
#define PW_MODE_OWNER 2
static int  g_password_mode = PW_MODE_BOTH;
static const char *g_found_type = NULL;  /* "User" or "Owner" */

/* ── Markov chain ordering ────────────────────────────────────── */
#define MARKOV_MAGIC 0x4D4B5631  /* "MKV1" */
typedef struct {
    uint32_t magic;
    int      charset_size;
    char     charset[256];
    uint8_t  first_rank[256];   /* first_rank[rank] = char */
    uint8_t  bigram[256][256];  /* bigram[prev_char][rank] = next_char */
    int      threshold;         /* prune branches below this rank */
} MarkovModel;
static MarkovModel *g_markov = NULL;

/* Train a Markov model from a wordlist and write binary file */
static void markov_train(const char *wordlist_path, const char *model_path)
{
    FILE *f = fopen(wordlist_path, "r");
    if (!f) { perror(wordlist_path); exit(1); }

    /* Count frequencies */
    long first_freq[256] = {0};
    long bigram_freq[256][256] = {{0}};

    char line[MAX_PASS_LEN + 4];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (!len) continue;

        first_freq[(unsigned char)line[0]]++;
        for (size_t i = 1; i < len; i++)
            bigram_freq[(unsigned char)line[i-1]][(unsigned char)line[i]]++;
    }
    fclose(f);

    /* Build charset: all chars that appear as first or in any bigram */
    char charset[256];
    int cs_len = 0;
    int char_present[256] = {0};
    for (int i = 0; i < 256; i++) {
        if (first_freq[i] > 0) char_present[i] = 1;
        for (int j = 0; j < 256; j++) {
            if (bigram_freq[i][j] > 0) {
                char_present[i] = 1;
                char_present[j] = 1;
            }
        }
    }
    for (int i = 0; i < 256; i++) {
        if (char_present[i])
            charset[cs_len++] = (char)i;
    }
    charset[cs_len] = '\0';

    /* Sort first_rank by frequency (descending) */
    MarkovModel model;
    memset(&model, 0, sizeof(model));
    model.magic = MARKOV_MAGIC;
    model.charset_size = cs_len;
    memcpy(model.charset, charset, (size_t)cs_len + 1);
    model.threshold = cs_len; /* default: no pruning */

    /* Build first_rank: sorted indices by frequency */
    int sorted[256];
    for (int i = 0; i < 256; i++) sorted[i] = i;
    for (int i = 0; i < 255; i++) {
        for (int j = i + 1; j < 256; j++) {
            if (first_freq[sorted[j]] > first_freq[sorted[i]]) {
                int tmp = sorted[i]; sorted[i] = sorted[j]; sorted[j] = tmp;
            }
        }
    }
    for (int r = 0; r < 256; r++)
        model.first_rank[r] = (uint8_t)sorted[r];

    /* Build bigram[prev][rank] = next_char, sorted by frequency */
    for (int prev = 0; prev < 256; prev++) {
        int bi_sorted[256];
        for (int i = 0; i < 256; i++) bi_sorted[i] = i;
        for (int i = 0; i < 255; i++) {
            for (int j = i + 1; j < 256; j++) {
                if (bigram_freq[prev][bi_sorted[j]] > bigram_freq[prev][bi_sorted[i]]) {
                    int tmp = bi_sorted[i]; bi_sorted[i] = bi_sorted[j]; bi_sorted[j] = tmp;
                }
            }
        }
        for (int r = 0; r < 256; r++)
            model.bigram[prev][r] = (uint8_t)bi_sorted[r];
    }

    /* Write binary model */
    FILE *out = fopen(model_path, "wb");
    if (!out) { perror(model_path); exit(1); }
    fwrite(&model, sizeof(model), 1, out);
    fclose(out);

    fprintf(stderr, "Markov model trained: %d chars, written to %s\n",
            cs_len, model_path);
}

/* Load a Markov model from binary file */
static MarkovModel *markov_load(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }

    MarkovModel *m = malloc(sizeof(MarkovModel));
    if (!m) { fclose(f); return NULL; }

    if (fread(m, sizeof(MarkovModel), 1, f) != 1) {
        fprintf(stderr, "Failed to read Markov model from %s\n", path);
        free(m); fclose(f); return NULL;
    }
    fclose(f);

    if (m->magic != MARKOV_MAGIC) {
        fprintf(stderr, "Bad Markov model magic in %s\n", path);
        free(m); return NULL;
    }

    fprintf(stderr, "Markov model loaded: %d chars from %s\n",
            m->charset_size, path);
    return m;
}

/* Convert index to password using Markov model ordering.
 * Index 0 = all rank-0 choices = most probable password. */
static void markov_index_to_pass(long idx, int length, char *out)
{
    int cs = g_markov->charset_size;
    int threshold = g_markov->threshold;
    int effective_cs = (threshold < cs) ? threshold : cs;
    if (effective_cs < 1) effective_cs = 1;

    /* Decompose index into per-position rank choices */
    int ranks[MAX_PASS_LEN];
    for (int i = length - 1; i >= 0; i--) {
        ranks[i] = (int)(idx % effective_cs);
        idx /= effective_cs;
    }

    /* Position 0: use first_rank */
    out[0] = (char)g_markov->first_rank[ranks[0]];

    /* Position 1+: use bigram[prev_char][rank] */
    for (int i = 1; i < length; i++) {
        unsigned char prev = (unsigned char)out[i - 1];
        out[i] = (char)g_markov->bigram[prev][ranks[i]];
    }
    out[length] = '\0';
}

/* ── Function pointer for index-to-password (mask vs brute) ─── */
static void (*g_idx_to_pass)(long idx, int length, char *out) = NULL;

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
    if (g_password_mode == PW_MODE_USER) {
        if (pdf_verify_user_password(&g_enc_params, pass)) {
            g_found_type = "User";
            return 1;
        }
        return 0;
    }
    if (g_password_mode == PW_MODE_OWNER) {
        if (pdf_verify_owner_password(&g_enc_params, pass)) {
            g_found_type = "Owner";
            return 1;
        }
        return 0;
    }
    /* PW_MODE_BOTH: try user first, then owner */
    if (pdf_verify_user_password(&g_enc_params, pass)) {
        g_found_type = "User";
        return 1;
    }
    if (pdf_verify_owner_password(&g_enc_params, pass)) {
        g_found_type = "Owner";
        return 1;
    }
    return 0;
}

static inline int test_password_cg(CGPDFDocumentRef doc, const char *pass)
{
    return CGPDFDocumentUnlockWithPassword(doc, pass);
}

/* ================================================================
 * Human-readable number formatting
 * ================================================================ */
static void fmt_num(long n, char *buf, size_t sz)
{
    if (n >= 1000000000L)
        snprintf(buf, sz, "%.1fB", (double)n / 1e9);
    else if (n >= 1000000L)
        snprintf(buf, sz, "%.1fM", (double)n / 1e6);
    else if (n >= 10000L)
        snprintf(buf, sz, "%.1fK", (double)n / 1e3);
    else
        snprintf(buf, sz, "%ld", n);
}

static void fmt_time(long secs, char *buf, size_t sz)
{
    if (secs >= 3600)
        snprintf(buf, sz, "%ldh%02ldm", secs / 3600, (secs % 3600) / 60);
    else if (secs >= 60)
        snprintf(buf, sz, "%ldm%02lds", secs / 60, secs % 60);
    else
        snprintf(buf, sz, "%lds", secs);
}

/* ================================================================
 * Checkpoint save/load/delete
 * ================================================================ */
static void ckpt_make_path(const char *pdf_path)
{
    /* Place checkpoint file next to the PDF: <name>.ckpt */
    const char *dot = strrchr(pdf_path, '.');
    if (dot) {
        size_t base = (size_t)(dot - pdf_path);
        if (base >= sizeof(g_ckpt_path) - 6) base = sizeof(g_ckpt_path) - 6;
        memcpy(g_ckpt_path, pdf_path, base);
        strcpy(g_ckpt_path + base, ".ckpt");
    } else {
        snprintf(g_ckpt_path, sizeof(g_ckpt_path), "%s.ckpt", pdf_path);
    }
}

static void ckpt_save(void)
{
    if (!g_ckpt_path[0]) return;

    char tmp[1040];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_ckpt_path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;

    /* Save attack mode */
    static const char *mode_names[] = {
        "brute", "dict", "mask", "rule", "hybrid", "auto"
    };
    fprintf(f, "attack_mode=%s\n", mode_names[g_attack_mode]);

    long cur_idx = atomic_load(&g_next_idx);
    fprintf(f, "current_idx=%ld\n", cur_idx);

    if (g_is_brute || g_attack_mode == ATTACK_BRUTE ||
        g_attack_mode == ATTACK_MASK || g_attack_mode == ATTACK_AUTO) {
        int cur_len = atomic_load(&g_current_len);
        fprintf(f, "charset=%s\n", g_charset);
        fprintf(f, "current_len=%d\n", cur_len);
        fprintf(f, "completed_prior=%ld\n", g_completed_prior);
    }

    /* Mode-specific data */
    if (g_attack_mode == ATTACK_MASK && g_mask_str[0])
        fprintf(f, "mask_pattern=%s\n", g_mask_str);
    if (g_attack_mode == ATTACK_HYBRID) {
        fprintf(f, "hybrid_suffix_len=%d\n", g_hybrid_suffix_len);
        if (g_hybrid_mask_mode && g_hybrid_mask_str[0])
            fprintf(f, "hybrid_mask=%s\n", g_hybrid_mask_str);
    }
    if (g_attack_mode == ATTACK_AUTO)
        fprintf(f, "auto_phase=%d\n", g_auto_phase);
    if (g_freq_mode)
        fprintf(f, "freq_mode=1\n");
    if (g_password_mode != PW_MODE_BOTH)
        fprintf(f, "password_mode=%d\n", g_password_mode);

    for (int ci = 0; ci < 4; ci++) {
        if (g_custom_charset_str[ci][0])
            fprintf(f, "custom_charset_%d=%s\n", ci + 1, g_custom_charset_str[ci]);
    }

    if (g_prefix_len) fprintf(f, "prefix=%s\n", g_prefix);
    if (g_suffix_len) fprintf(f, "suffix=%s\n", g_suffix);
    fclose(f);
    rename(tmp, g_ckpt_path);  /* atomic replace */
}

typedef struct {
    int  valid;
    int  is_brute;
    int  attack_mode;
    char charset[256];
    int  resume_len;
    long resume_idx;
    long completed_prior;
    long dict_idx;
    char prefix[MAX_PASS_LEN + 1];
    char suffix[MAX_PASS_LEN + 1];
    char mask_pattern[256];
    int  hybrid_suffix_len;
    char hybrid_mask[256];
    int  auto_phase;
    int  freq_mode;
    int  password_mode;
    char custom_charsets[4][256];
} Checkpoint;

static Checkpoint ckpt_load(void)
{
    Checkpoint ck = {0};
    ck.attack_mode = -1;  /* not set */
    if (!g_ckpt_path[0]) return ck;

    FILE *f = fopen(g_ckpt_path, "r");
    if (!f) return ck;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        /* Legacy mode= support */
        if (strncmp(line, "mode=brute", 10) == 0) {
            ck.is_brute = 1;
            if (ck.attack_mode < 0) ck.attack_mode = ATTACK_BRUTE;
        } else if (strncmp(line, "mode=dict", 9) == 0) {
            ck.is_brute = 0;
            if (ck.attack_mode < 0) ck.attack_mode = ATTACK_DICT;
        /* New attack_mode= */
        } else if (strncmp(line, "attack_mode=brute", 17) == 0) {
            ck.attack_mode = ATTACK_BRUTE; ck.is_brute = 1;
        } else if (strncmp(line, "attack_mode=dict", 16) == 0) {
            ck.attack_mode = ATTACK_DICT; ck.is_brute = 0;
        } else if (strncmp(line, "attack_mode=mask", 16) == 0) {
            ck.attack_mode = ATTACK_MASK; ck.is_brute = 1;
        } else if (strncmp(line, "attack_mode=rule", 16) == 0) {
            ck.attack_mode = ATTACK_RULE; ck.is_brute = 0;
        } else if (strncmp(line, "attack_mode=hybrid", 18) == 0) {
            ck.attack_mode = ATTACK_HYBRID; ck.is_brute = 0;
        } else if (strncmp(line, "attack_mode=auto", 16) == 0) {
            ck.attack_mode = ATTACK_AUTO;
        } else if (strncmp(line, "charset=", 8) == 0) {
            strncpy(ck.charset, line + 8, sizeof(ck.charset) - 1);
        } else if (strncmp(line, "current_len=", 12) == 0) {
            ck.resume_len = atoi(line + 12);
        } else if (strncmp(line, "current_idx=", 12) == 0) {
            ck.resume_idx = atol(line + 12);
            ck.dict_idx = ck.resume_idx;
        } else if (strncmp(line, "completed_prior=", 16) == 0) {
            ck.completed_prior = atol(line + 16);
        } else if (strncmp(line, "prefix=", 7) == 0) {
            strncpy(ck.prefix, line + 7, MAX_PASS_LEN);
        } else if (strncmp(line, "suffix=", 7) == 0) {
            strncpy(ck.suffix, line + 7, MAX_PASS_LEN);
        } else if (strncmp(line, "mask_pattern=", 13) == 0) {
            strncpy(ck.mask_pattern, line + 13, sizeof(ck.mask_pattern) - 1);
        } else if (strncmp(line, "hybrid_suffix_len=", 18) == 0) {
            ck.hybrid_suffix_len = atoi(line + 18);
        } else if (strncmp(line, "hybrid_mask=", 12) == 0) {
            strncpy(ck.hybrid_mask, line + 12, sizeof(ck.hybrid_mask) - 1);
        } else if (strncmp(line, "auto_phase=", 11) == 0) {
            ck.auto_phase = atoi(line + 11);
        } else if (strncmp(line, "freq_mode=", 10) == 0) {
            ck.freq_mode = atoi(line + 10);
        } else if (strncmp(line, "password_mode=", 14) == 0) {
            ck.password_mode = atoi(line + 14);
        } else if (strncmp(line, "custom_charset_", 15) == 0 &&
                   line[15] >= '1' && line[15] <= '4' && line[16] == '=') {
            int ci = line[15] - '1';
            strncpy(ck.custom_charsets[ci], line + 17, sizeof(ck.custom_charsets[ci]) - 1);
        }
    }
    fclose(f);
    ck.valid = 1;
    return ck;
}

static void ckpt_delete(void)
{
    if (g_ckpt_path[0])
        unlink(g_ckpt_path);
}

static void sigint_handler(int sig)
{
    (void)sig;
    g_interrupted = 1;
    const char msg[] = "\nInterrupted — saving checkpoint...\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
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
    time_t last_ckpt = t0;
    long   avg_buf[16] = {0};
    int    avg_i     = 0;
    int    avg_fill  = 0;
    double ema_rate  = 0.0;

    while (!atomic_load(&g_found)) {
        struct timespec ts = {0, 500000000L}; /* 0.5s */
        nanosleep(&ts, NULL);

        long cur     = atomic_load(&g_tested);
        long total   = atomic_load(&g_total);
        long rate    = (cur - prev) * 2; /* per 0.5s → per sec */
        prev         = cur;
        long elapsed = (long)(time(NULL) - t0);

        /* rolling average + EMA for stable ETA */
        avg_buf[avg_i % 16] = rate;
        avg_i++;
        if (avg_fill < 16) avg_fill++;
        long avg_sum = 0;
        for (int i = 0; i < avg_fill; i++) avg_sum += avg_buf[i];
        long raw_avg = avg_fill > 0 ? avg_sum / avg_fill : 0;

        double alpha = (avg_fill < 8) ? 0.4 : 0.15;
        ema_rate = alpha * (double)raw_avg + (1.0 - alpha) * ema_rate;
        long avg_rate = (avg_fill >= 4) ? (long)ema_rate : -1;

        char s_cur[16], s_total[16], s_rate[16], s_elapsed[16], s_eta[16];
        fmt_num(rate, s_rate, sizeof(s_rate));
        fmt_time(elapsed, s_elapsed, sizeof(s_elapsed));

        /* Overall progress line (brute-force only, when we have overall totals) */
        long ov_total = g_overall_total;
        if (ov_total > 0) {
            long ov_cur = g_completed_prior + cur;
            double ov_pct = (double)ov_cur / (double)ov_total * 100.0;
            if (ov_pct > 100.0) ov_pct = 100.0;

            char s_ov_cur[16], s_ov_total[16], s_ov_eta[16];
            fmt_num(ov_cur, s_ov_cur, sizeof(s_ov_cur));
            fmt_num(ov_total, s_ov_total, sizeof(s_ov_total));

            long ov_eta = -1;
            if (avg_rate > 0 && ov_total > ov_cur)
                ov_eta = (ov_total - ov_cur) / avg_rate;

            fprintf(stderr, "\r\033[K  Overall ");
            print_bar(ov_pct);
            if (ov_eta >= 0) {
                fmt_time(ov_eta, s_ov_eta, sizeof(s_ov_eta));
                fprintf(stderr, " %5.1f%%  %s/%s  ETA %s",
                        ov_pct, s_ov_cur, s_ov_total, s_ov_eta);
            } else {
                fprintf(stderr, " %5.1f%%  %s/%s",
                        ov_pct, s_ov_cur, s_ov_total);
            }

            /* Current length line */
            int cur_len = atomic_load(&g_current_len);
            if (total > 0 && cur_len > 0) {
                double pct = (double)cur / (double)total * 100.0;
                if (pct > 100.0) pct = 100.0;
                fmt_num(cur, s_cur, sizeof(s_cur));
                fmt_num(total, s_total, sizeof(s_total));

                fprintf(stderr, "\n\033[K  Len %d  ", cur_len);
                print_bar(pct);
                fprintf(stderr, " %5.1f%%  %s/%s  %s/s  %s",
                        pct, s_cur, s_total, s_rate, s_elapsed);

                long eta = -1;
                if (avg_rate > 0 && total > cur)
                    eta = (total - cur) / avg_rate;
                if (eta >= 0) {
                    fmt_time(eta, s_eta, sizeof(s_eta));
                    fprintf(stderr, "  ETA %s", s_eta);
                }
                fprintf(stderr, "   \033[A"); /* move cursor back up */
            }
        } else if (total > 0) {
            /* Single-level progress (dictionary mode) */
            double pct = (double)cur / (double)total * 100.0;
            if (pct > 100.0) pct = 100.0;
            fmt_num(cur, s_cur, sizeof(s_cur));
            fmt_num(total, s_total, sizeof(s_total));

            fprintf(stderr, "\r\033[K  ");
            print_bar(pct);

            long eta = -1;
            if (avg_rate > 0 && total > cur)
                eta = (total - cur) / avg_rate;

            if (eta >= 0) {
                fmt_time(eta, s_eta, sizeof(s_eta));
                fprintf(stderr, " %5.1f%%  %s/%s  %s/s  %s  ETA %s",
                        pct, s_cur, s_total, s_rate, s_elapsed, s_eta);
            } else {
                fprintf(stderr, " %5.1f%%  %s/%s  %s/s  %s",
                        pct, s_cur, s_total, s_rate, s_elapsed);
            }
        } else {
            fmt_num(cur, s_cur, sizeof(s_cur));
            fprintf(stderr, "\r\033[K  tested: %s  %s/s  %s",
                    s_cur, s_rate, s_elapsed);
        }
        fflush(stderr);

        /* Periodic checkpoint */
        time_t now = time(NULL);
        if (now - last_ckpt >= CKPT_INTERVAL) {
            ckpt_save();
            last_ckpt = now;
        }

        /* Check async-safe interrupt flag */
        if (g_interrupted) {
            ckpt_save();
            _exit(1);
        }
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
    /* If prefix/suffix set, build: prefix + brute_middle + suffix
     * 'length' here is the length of the brute-force middle part */
    int pos = 0;
    if (g_prefix_len) {
        memcpy(out, g_prefix, g_prefix_len);
        pos = g_prefix_len;
    }
    for (int i = length - 1; i >= 0; i--) {
        out[pos + i] = g_charset[idx % g_cs_len];
        idx /= g_cs_len;
    }
    pos += length;
    if (g_suffix_len) {
        memcpy(out + pos, g_suffix, g_suffix_len);
        pos += g_suffix_len;
    }
    out[pos] = '\0';
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

/* ================================================================
 * Mask attack: parse mask and generate passwords
 * ================================================================ */
static const char SPECIAL_CHARS[] = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

static int parse_mask_into(const char *mask, MaskPos *target, int *out_len, long *out_keyspace)
{
    *out_len = 0;
    const char *p = mask;
    while (*p && *out_len < MAX_PASS_LEN) {
        MaskPos *mp = &target[*out_len];
        mp->is_word = 0;
        if (*p == '?' && *(p + 1)) {
            char code = *(p + 1);
            p += 2;
            switch (code) {
                case 'w': {
                    /* Word placeholder — expands to dictionary words */
                    if (g_nwords <= 0) {
                        fprintf(stderr, "?w requires -d <wordlist>\n");
                        return 0;
                    }
                    mp->is_word = 1;
                    mp->nchars = (int)g_nwords;
                    mp->chars = NULL;
                    break;
                }
                case 'l': {
                    mp->nchars = 26;
                    mp->chars = malloc(27);
                    for (int i = 0; i < 26; i++) mp->chars[i] = (char)('a' + i);
                    mp->chars[26] = '\0';
                    break;
                }
                case 'u': {
                    mp->nchars = 26;
                    mp->chars = malloc(27);
                    for (int i = 0; i < 26; i++) mp->chars[i] = (char)('A' + i);
                    mp->chars[26] = '\0';
                    break;
                }
                case 'd': {
                    mp->nchars = 10;
                    mp->chars = malloc(11);
                    for (int i = 0; i < 10; i++) mp->chars[i] = (char)('0' + i);
                    mp->chars[10] = '\0';
                    break;
                }
                case 's': {
                    int n = (int)strlen(SPECIAL_CHARS);
                    mp->nchars = n;
                    mp->chars = malloc((size_t)n + 1);
                    memcpy(mp->chars, SPECIAL_CHARS, (size_t)n + 1);
                    break;
                }
                case 'a': {
                    mp->nchars = 95; /* ASCII 32-126 */
                    mp->chars = malloc(96);
                    for (int i = 0; i < 95; i++) mp->chars[i] = (char)(32 + i);
                    mp->chars[95] = '\0';
                    break;
                }
                case 'h': {
                    /* hex lowercase: 0-9a-f */
                    mp->nchars = 16;
                    mp->chars = malloc(17);
                    memcpy(mp->chars, "0123456789abcdef", 17);
                    break;
                }
                case 'H': {
                    /* hex uppercase: 0-9A-F */
                    mp->nchars = 16;
                    mp->chars = malloc(17);
                    memcpy(mp->chars, "0123456789ABCDEF", 17);
                    break;
                }
                case '1': case '2': case '3': case '4': {
                    int ci = code - '1'; /* 0-3 */
                    if (!g_custom_charset[ci]) {
                        fprintf(stderr, "Custom charset ?%c not defined (use -%c)\n",
                                code, code);
                        return 0;
                    }
                    int n = (int)strlen(g_custom_charset[ci]);
                    mp->nchars = n;
                    mp->chars = malloc((size_t)n + 1);
                    memcpy(mp->chars, g_custom_charset[ci], (size_t)n + 1);
                    break;
                }
                default:
                    fprintf(stderr, "Unknown mask code: ?%c\n", code);
                    return 0;
            }
        } else if (*p == '[') {
            /* Inline range syntax: [a-f], [0-9A-F], [abc] */
            p++; /* skip '[' */
            char range_chars[256];
            int rn = 0;
            while (*p && *p != ']' && rn < 255) {
                if (*(p + 1) == '-' && *(p + 2) && *(p + 2) != ']') {
                    /* Range: x-y */
                    char from = *p, to = *(p + 2);
                    if (from > to) { char tmp = from; from = to; to = tmp; }
                    for (char c = from; c <= to && rn < 255; c++)
                        range_chars[rn++] = c;
                    p += 3;
                } else {
                    range_chars[rn++] = *p;
                    p++;
                }
            }
            if (*p == ']') p++;
            range_chars[rn] = '\0';
            mp->nchars = rn;
            mp->chars = malloc((size_t)rn + 1);
            memcpy(mp->chars, range_chars, (size_t)rn + 1);
        } else {
            /* literal character */
            mp->nchars = 1;
            mp->chars = malloc(2);
            mp->chars[0] = *p;
            mp->chars[1] = '\0';
            p++;
        }
        (*out_len)++;
    }
    /* Compute keyspace */
    *out_keyspace = 1;
    for (int i = 0; i < *out_len; i++) {
        if (*out_keyspace > (long)2e18 / target[i].nchars) {
            *out_keyspace = (long)2e18;
            break;
        }
        *out_keyspace *= target[i].nchars;
    }
    return 1;
}

static int parse_mask(const char *mask)
{
    return parse_mask_into(mask, g_mask, &g_mask_len, &g_mask_keyspace);
}

static int g_mask_has_words = 0;  /* 1 if mask contains ?w */

static void mask_index_to_pass(long idx, int length, char *out)
{
    (void)length; /* mask length is fixed */
    for (int i = g_mask_len - 1; i >= 0; i--) {
        out[i] = g_mask[i].chars[idx % g_mask[i].nchars];
        idx /= g_mask[i].nchars;
    }
    out[g_mask_len] = '\0';
}

/* Combo mode: mask with ?w word placeholders. Variable-length output. */
static void combo_index_to_pass(long idx, int length, char *out)
{
    (void)length;
    /* Decompose index into per-position indices (right-to-left) */
    int indices[MAX_PASS_LEN];
    for (int i = g_mask_len - 1; i >= 0; i--) {
        indices[i] = (int)(idx % g_mask[i].nchars);
        idx /= g_mask[i].nchars;
    }
    /* Build password */
    int pos = 0;
    for (int i = 0; i < g_mask_len; i++) {
        if (g_mask[i].is_word) {
            const char *word = g_words[indices[i]];
            size_t wlen = strlen(word);
            if (pos + (int)wlen > MAX_PASS_LEN) wlen = (size_t)(MAX_PASS_LEN - pos);
            memcpy(out + pos, word, wlen);
            pos += (int)wlen;
        } else {
            if (pos < MAX_PASS_LEN)
                out[pos++] = g_mask[i].chars[indices[i]];
        }
    }
    out[pos] = '\0';
}

/* ================================================================
 * Rule-based mutations
 * ================================================================ */
/* Helper to add a single-op rule */
static void add_rule_1(RuleType type, char ch, char ch2, int pos)
{
    if (g_nrules >= MAX_RULES) return;
    Rule *r = &g_rules[g_nrules++];
    r->nops = 1;
    r->ops[0] = (typeof(r->ops[0])){ .type = type, .ch = ch, .ch2 = ch2, .pos = pos };
}

/* Helper to add a two-op rule */
static void add_rule_2(RuleType t1, char c1, char c1b, int p1,
                       RuleType t2, char c2, char c2b, int p2)
{
    if (g_nrules >= MAX_RULES) return;
    Rule *r = &g_rules[g_nrules++];
    r->nops = 2;
    r->ops[0] = (typeof(r->ops[0])){ .type = t1, .ch = c1, .ch2 = c1b, .pos = p1 };
    r->ops[1] = (typeof(r->ops[1])){ .type = t2, .ch = c2, .ch2 = c2b, .pos = p2 };
}

/* Parse a hashcat-style rule char, returning number of chars consumed.
 * Appends op to rule->ops[rule->nops] and increments nops. */
static int parse_rule_op(const char *p, Rule *rule)
{
    if (rule->nops >= MAX_OPS_PER_RULE) return 0;
    typeof(rule->ops[0]) *op = &rule->ops[rule->nops];
    memset(op, 0, sizeof(*op));

    switch (*p) {
        case ':': op->type = RULE_NOOP; rule->nops++; return 1;
        case 'l': op->type = RULE_LOWER; rule->nops++; return 1;
        case 'u': op->type = RULE_UPPER; rule->nops++; return 1;
        case 'c': op->type = RULE_CAPITALIZE; rule->nops++; return 1;
        case 'r': op->type = RULE_REVERSE; rule->nops++; return 1;
        case 'd': op->type = RULE_DUPLICATE; rule->nops++; return 1;
        case '$':
            if (!*(p+1)) return 0;
            op->type = RULE_APPEND_CHAR; op->ch = *(p+1);
            rule->nops++; return 2;
        case '^':
            if (!*(p+1)) return 0;
            op->type = RULE_PREPEND_CHAR; op->ch = *(p+1);
            rule->nops++; return 2;
        case 'T':
            if (!*(p+1)) return 0;
            op->type = RULE_TOGGLE_AT;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 0;
            rule->nops++; return 2;
        case 'i':
            if (!*(p+1) || !*(p+2)) return 0;
            op->type = RULE_INSERT_AT;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 0;
            op->ch = *(p+2);
            rule->nops++; return 3;
        case 'o':
            if (!*(p+1) || !*(p+2)) return 0;
            op->type = RULE_OVERWRITE_AT;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 0;
            op->ch = *(p+2);
            rule->nops++; return 3;
        case 'D':
            if (!*(p+1)) return 0;
            op->type = RULE_DELETE_AT;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 0;
            rule->nops++; return 2;
        case '[':
            if (!*(p+1)) return 0;
            op->type = RULE_TRUNCATE_LEFT;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 1;
            rule->nops++; return 2;
        case ']':
            if (!*(p+1)) return 0;
            op->type = RULE_TRUNCATE_RIGHT;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 1;
            rule->nops++; return 2;
        case 's':
            if (!*(p+1) || !*(p+2)) return 0;
            op->type = RULE_REPLACE; op->ch = *(p+1); op->ch2 = *(p+2);
            rule->nops++; return 3;
        case '@':
            if (!*(p+1)) return 0;
            op->type = RULE_PURGE; op->ch = *(p+1);
            rule->nops++; return 2;
        case 'p':
            if (!*(p+1)) return 0;
            op->type = RULE_DUPLICATE_N;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 1;
            rule->nops++; return 2;
        case 'y':
            if (!*(p+1)) return 0;
            op->type = RULE_DUP_FIRST_N;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 1;
            rule->nops++; return 2;
        case 'Y':
            if (!*(p+1)) return 0;
            op->type = RULE_DUP_LAST_N;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 1;
            rule->nops++; return 2;
        case '*':
            if (!*(p+1) || !*(p+2)) return 0;
            op->type = RULE_SWAP;
            op->pos = (*(p+1) >= '0' && *(p+1) <= '9') ? *(p+1) - '0' : 0;
            op->ch = *(p+2);  /* second position stored in ch */
            rule->nops++; return 3;
        case 'L': /* Leet speak */
            op->type = RULE_LEET;
            rule->nops++; return 1;
        default:
            return 0;
    }
}

/* Load rules from a file (one rule per line, hashcat-compatible) */
static int load_rules_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    char line[256];
    g_nrules = 0;
    while (fgets(line, sizeof(line), f) && g_nrules < MAX_RULES) {
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (!len || line[0] == '#') continue;

        Rule *r = &g_rules[g_nrules];
        memset(r, 0, sizeof(*r));
        const char *p = line;
        int ok = 1;
        while (*p && r->nops < MAX_OPS_PER_RULE) {
            int consumed = parse_rule_op(p, r);
            if (consumed <= 0) { ok = 0; break; }
            p += consumed;
        }
        if (ok && r->nops > 0) g_nrules++;
    }
    fclose(f);
    fprintf(stderr, "Loaded %d rules from %s\n", g_nrules, path);
    return 1;
}

static void init_rules(void)
{
    g_nrules = 0;
    /* : (as-is) */
    add_rule_1(RULE_NOOP, 0, 0, 0);
    /* l (lowercase) */
    add_rule_1(RULE_LOWER, 0, 0, 0);
    /* u (uppercase) */
    add_rule_1(RULE_UPPER, 0, 0, 0);
    /* c (capitalize first) */
    add_rule_1(RULE_CAPITALIZE, 0, 0, 0);
    /* r (reverse) */
    add_rule_1(RULE_REVERSE, 0, 0, 0);
    /* d (duplicate) */
    add_rule_1(RULE_DUPLICATE, 0, 0, 0);
    /* $0 through $9 (append digit) */
    for (int i = 0; i <= 9; i++)
        add_rule_1(RULE_APPEND_CHAR, (char)('0' + i), 0, 0);
    /* ^1 through ^9 (prepend digit) */
    for (int i = 1; i <= 9; i++)
        add_rule_1(RULE_PREPEND_CHAR, (char)('0' + i), 0, 0);
    /* c$1 through c$9 (capitalize + append digit) */
    for (int i = 1; i <= 9; i++)
        add_rule_2(RULE_CAPITALIZE, 0, 0, 0,
                   RULE_APPEND_CHAR, (char)('0' + i), 0, 0);
}

/* Apply a single rule op in-place on buf[0..len-1]. Returns new length. */
static size_t apply_one_op(char *buf, size_t len, const typeof(((Rule *)0)->ops[0]) *op)
{
    switch (op->type) {
        case RULE_NOOP:
            break;
        case RULE_LOWER:
            for (size_t i = 0; i < len; i++) buf[i] = (char)tolower((unsigned char)buf[i]);
            break;
        case RULE_UPPER:
            for (size_t i = 0; i < len; i++) buf[i] = (char)toupper((unsigned char)buf[i]);
            break;
        case RULE_CAPITALIZE:
            if (len > 0) buf[0] = (char)toupper((unsigned char)buf[0]);
            for (size_t i = 1; i < len; i++) buf[i] = (char)tolower((unsigned char)buf[i]);
            break;
        case RULE_REVERSE: {
            for (size_t i = 0; i < len / 2; i++) {
                char tmp = buf[i]; buf[i] = buf[len - 1 - i]; buf[len - 1 - i] = tmp;
            }
            break;
        }
        case RULE_DUPLICATE:
            if (len * 2 <= MAX_PASS_LEN) {
                memcpy(buf + len, buf, len);
                len *= 2;
            }
            break;
        case RULE_APPEND_CHAR:
            if (len < MAX_PASS_LEN) buf[len++] = op->ch;
            break;
        case RULE_PREPEND_CHAR:
            if (len < MAX_PASS_LEN) {
                memmove(buf + 1, buf, len);
                buf[0] = op->ch;
                len++;
            }
            break;
        case RULE_CAP_APPEND:
            if (len > 0) buf[0] = (char)toupper((unsigned char)buf[0]);
            for (size_t i = 1; i < len; i++) buf[i] = (char)tolower((unsigned char)buf[i]);
            if (len < MAX_PASS_LEN) buf[len++] = op->ch;
            break;
        case RULE_TOGGLE_AT:
            if ((size_t)op->pos < len) {
                unsigned char c = (unsigned char)buf[op->pos];
                buf[op->pos] = (char)(islower(c) ? toupper(c) : tolower(c));
            }
            break;
        case RULE_INSERT_AT:
            if ((size_t)op->pos <= len && len < MAX_PASS_LEN) {
                memmove(buf + op->pos + 1, buf + op->pos, len - (size_t)op->pos);
                buf[op->pos] = op->ch;
                len++;
            }
            break;
        case RULE_OVERWRITE_AT:
            if ((size_t)op->pos < len)
                buf[op->pos] = op->ch;
            break;
        case RULE_DELETE_AT:
            if ((size_t)op->pos < len) {
                memmove(buf + op->pos, buf + op->pos + 1, len - (size_t)op->pos - 1);
                len--;
            }
            break;
        case RULE_TRUNCATE_LEFT: {
            int n = op->pos;
            if ((size_t)n >= len) { len = 0; }
            else { memmove(buf, buf + n, len - (size_t)n); len -= (size_t)n; }
            break;
        }
        case RULE_TRUNCATE_RIGHT:
            if ((size_t)op->pos < len) len = (size_t)op->pos;
            break;
        case RULE_REPLACE: {
            for (size_t i = 0; i < len; i++)
                if (buf[i] == op->ch) buf[i] = op->ch2;
            break;
        }
        case RULE_PURGE: {
            size_t w = 0;
            for (size_t i = 0; i < len; i++)
                if (buf[i] != op->ch) buf[w++] = buf[i];
            len = w;
            break;
        }
        case RULE_DUPLICATE_N: {
            int n = op->pos;
            if (n > 0 && len * (size_t)(n + 1) <= MAX_PASS_LEN) {
                size_t orig = len;
                for (int j = 0; j < n; j++) {
                    memcpy(buf + len, buf, orig);
                    len += orig;
                }
            }
            break;
        }
        case RULE_DUP_FIRST_N: {
            int n = op->pos;
            if (n > 0 && (size_t)n <= len && len + (size_t)n <= MAX_PASS_LEN) {
                memmove(buf + n, buf, len);
                memcpy(buf, buf + n, (size_t)n); /* copy from original position */
                len += (size_t)n;
            }
            break;
        }
        case RULE_DUP_LAST_N: {
            int n = op->pos;
            if (n > 0 && (size_t)n <= len && len + (size_t)n <= MAX_PASS_LEN) {
                memcpy(buf + len, buf + len - (size_t)n, (size_t)n);
                len += (size_t)n;
            }
            break;
        }
        case RULE_SWAP: {
            size_t p1 = (size_t)op->pos;
            size_t p2 = (size_t)(unsigned char)op->ch;
            if (op->ch >= '0' && op->ch <= '9') p2 = (size_t)(op->ch - '0');
            if (p1 < len && p2 < len) {
                char tmp = buf[p1]; buf[p1] = buf[p2]; buf[p2] = tmp;
            }
            break;
        }
        case RULE_LEET: {
            static const char from[] = "aeiostAEIOST";
            static const char to[]   = "@310$7@310$7";
            for (size_t i = 0; i < len; i++) {
                const char *f = strchr(from, buf[i]);
                if (f) buf[i] = to[f - from];
            }
            break;
        }
    }
    return len;
}

static void apply_rule(const char *word, int rule_idx, char *out)
{
    size_t len = strlen(word);
    if (len > MAX_PASS_LEN) len = MAX_PASS_LEN;
    memcpy(out, word, len);
    out[len] = '\0';

    const Rule *r = &g_rules[rule_idx];
    for (int i = 0; i < r->nops; i++) {
        len = apply_one_op(out, len, &r->ops[i]);
    }
    out[len] = '\0';
}

/* ================================================================
 * Hybrid attack: dictionary word + brute-force suffix
 * ================================================================ */
static long hybrid_total_suffix_keyspace(int max_slen, int cs_len)
{
    long total = 0;
    for (int l = 1; l <= max_slen; l++)
        total += count_for_length(l);
    return total;
}

static void hybrid_gen_pass(long word_idx, long suffix_idx, char *out)
{
    const char *word = g_words[word_idx];
    size_t wlen = strlen(word);
    memcpy(out, word, wlen);

    if (g_hybrid_mask_mode) {
        /* Fixed-length mask suffix */
        long rem = suffix_idx;
        for (int i = g_hybrid_mask_len - 1; i >= 0; i--) {
            out[wlen + (size_t)i] = g_hybrid_mask[i].chars[rem % g_hybrid_mask[i].nchars];
            rem /= g_hybrid_mask[i].nchars;
        }
        out[wlen + (size_t)g_hybrid_mask_len] = '\0';
    } else {
        /* Map suffix_idx across lengths 1..g_hybrid_suffix_len */
        long remaining = suffix_idx;
        int slen = 0;
        for (int sl = 1; sl <= g_hybrid_suffix_len; sl++) {
            long ks = count_for_length(sl);
            if (remaining < ks) {
                slen = sl;
                break;
            }
            remaining -= ks;
        }
        if (slen > 0) {
            for (int i = slen - 1; i >= 0; i--) {
                out[wlen + (size_t)i] = g_charset[remaining % g_cs_len];
                remaining /= g_cs_len;
            }
            out[wlen + (size_t)slen] = '\0';
        } else {
            out[wlen] = '\0';
        }
    }
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
                g_idx_to_pass(i, a->length, pass);
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
            g_idx_to_pass(i, a->length, pass);
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
 * NEON SIMD brute-force worker: processes 4 passwords at a time
 * using pdf_verify_user_batch4 for ~3-4x MD5 throughput.
 * Only used for R2-R4 on ARM NEON platforms.
 * ================================================================ */
#ifdef __ARM_NEON
static void *brute_worker_neon(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    BruteArg *a = (BruteArg *)arg;
    char pass[4][MAX_PASS_LEN + 1];
    long local_count = 0;

    if (a->use_shared) {
        /* Shared work counter mode — grab CPU_WORK_CHUNK at a time,
         * then process 4 at a time within each chunk */
        for (;;) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            long chunk_start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
            if (chunk_start >= a->end) break;
            long chunk_end = chunk_start + CPU_WORK_CHUNK;
            if (chunk_end > a->end) chunk_end = a->end;

            long i = chunk_start;
            /* Process groups of 4 */
            for (; i + 3 < chunk_end; i += 4) {
                if (__builtin_expect(atomic_load_explicit(&g_found,
                                     memory_order_relaxed), 0))
                    break;
                g_idx_to_pass(i + 0, a->length, pass[0]);
                g_idx_to_pass(i + 1, a->length, pass[1]);
                g_idx_to_pass(i + 2, a->length, pass[2]);
                g_idx_to_pass(i + 3, a->length, pass[3]);

                const char *pw[4] = { pass[0], pass[1], pass[2], pass[3] };
                int pwlen[4] = {
                    (int)strlen(pass[0]), (int)strlen(pass[1]),
                    (int)strlen(pass[2]), (int)strlen(pass[3])
                };

                /* Dispatch to appropriate batch4 based on password mode */
                int hits = 0;
                if (g_password_mode == PW_MODE_OWNER)
                    hits = pdf_verify_owner_batch4(&g_enc_params, pw, pwlen);
                else if (g_password_mode == PW_MODE_USER)
                    hits = pdf_verify_user_batch4(&g_enc_params, pw, pwlen);
                else {
                    /* BOTH: try user first, then owner for non-hits */
                    hits = pdf_verify_user_batch4(&g_enc_params, pw, pwlen);
                    if (hits) g_found_type = "User";
                    int remaining_mask = (~hits) & 0xF;
                    if (remaining_mask) {
                        int owner_hits = pdf_verify_owner_batch4(&g_enc_params, pw, pwlen);
                        owner_hits &= remaining_mask;
                        if (owner_hits) g_found_type = "Owner";
                        hits |= owner_hits;
                    }
                }
                if (g_password_mode == PW_MODE_OWNER && hits)
                    g_found_type = "Owner";
                else if (g_password_mode == PW_MODE_USER && hits)
                    g_found_type = "User";

                local_count += 4;
                if (local_count >= TESTED_BATCH) {
                    atomic_fetch_add_explicit(&g_tested, local_count,
                                              memory_order_relaxed);
                    local_count = 0;
                }
                if (__builtin_expect(hits, 0)) {
                    for (int b = 0; b < 4; b++) {
                        if (hits & (1 << b)) {
                            if (!atomic_exchange(&g_found, 1))
                                strncpy(g_password, pass[b], MAX_PASS_LEN);
                        }
                    }
                }
            }
            /* Handle remaining 1-3 passwords with scalar path */
            for (; i < chunk_end; i++) {
                if (__builtin_expect(atomic_load_explicit(&g_found,
                                     memory_order_relaxed), 0))
                    break;
                char p[MAX_PASS_LEN + 1];
                g_idx_to_pass(i, a->length, p);
                local_count++;
                if (local_count >= TESTED_BATCH) {
                    atomic_fetch_add_explicit(&g_tested, local_count,
                                              memory_order_relaxed);
                    local_count = 0;
                }
                if (test_password_fast(p)) {
                    if (!atomic_exchange(&g_found, 1))
                        strncpy(g_password, p, MAX_PASS_LEN);
                }
            }
        }
    } else {
        /* Pre-partitioned range mode (CPU-only) */
        long i = a->start;
        for (; i + 3 < a->end; i += 4) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            g_idx_to_pass(i + 0, a->length, pass[0]);
            g_idx_to_pass(i + 1, a->length, pass[1]);
            g_idx_to_pass(i + 2, a->length, pass[2]);
            g_idx_to_pass(i + 3, a->length, pass[3]);

            const char *pw[4] = { pass[0], pass[1], pass[2], pass[3] };
            int pwlen[4] = {
                (int)strlen(pass[0]), (int)strlen(pass[1]),
                (int)strlen(pass[2]), (int)strlen(pass[3])
            };

            int hits = 0;
            if (g_password_mode == PW_MODE_OWNER)
                hits = pdf_verify_owner_batch4(&g_enc_params, pw, pwlen);
            else if (g_password_mode == PW_MODE_USER)
                hits = pdf_verify_user_batch4(&g_enc_params, pw, pwlen);
            else {
                hits = pdf_verify_user_batch4(&g_enc_params, pw, pwlen);
                if (hits) g_found_type = "User";
                int remaining_mask = (~hits) & 0xF;
                if (remaining_mask) {
                    int owner_hits = pdf_verify_owner_batch4(&g_enc_params, pw, pwlen);
                    owner_hits &= remaining_mask;
                    if (owner_hits) g_found_type = "Owner";
                    hits |= owner_hits;
                }
            }
            if (g_password_mode == PW_MODE_OWNER && hits)
                g_found_type = "Owner";
            else if (g_password_mode == PW_MODE_USER && hits)
                g_found_type = "User";

            local_count += 4;
            if (local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count,
                                          memory_order_relaxed);
                local_count = 0;
            }
            if (__builtin_expect(hits, 0)) {
                for (int b = 0; b < 4; b++) {
                    if (hits & (1 << b)) {
                        if (!atomic_exchange(&g_found, 1))
                            strncpy(g_password, pass[b], MAX_PASS_LEN);
                    }
                }
            }
        }
        /* Handle remaining 1-3 with scalar */
        for (; i < a->end; i++) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            char p[MAX_PASS_LEN + 1];
            g_idx_to_pass(i, a->length, p);
            local_count++;
            if (local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count,
                                          memory_order_relaxed);
                local_count = 0;
            }
            if (test_password_fast(p)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, p, MAX_PASS_LEN);
            }
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_tested, local_count);

    free(arg);
    return NULL;
}
#endif /* __ARM_NEON */

/* ================================================================
 * Benchmark gate: compare GPU, NEON, and scalar CPU for R2-R4.
 *
 * Strategy: time a fixed batch through each available engine to
 * determine the best per-core throughput.  For GPU this includes
 * the RC4 verification step (CPU bottleneck).  For NEON this uses
 * the 4-way parallel MD5 path.
 *
 * The result is stored in g_use_gpu / g_use_neon — only one is
 * enabled, or neither if scalar CPU wins.
 * ================================================================ */

/* Benchmark GPU MD5-keygen + CPU RC4-verify pipeline.
 * Returns estimated passwords/sec for the GPU pipeline. */
static double benchmark_gpu_rate(void)
{
    if (!g_gpu_ctx) return 0;

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
    double secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;

    free(passwords); free(pw_storage); free(keys);
    return secs > 0 ? N / secs : 0;
}

/* Benchmark NEON 4-way SIMD path for a single core.
 * Returns estimated passwords/sec per core. */
static double benchmark_neon_rate(void)
{
#ifdef __ARM_NEON
    const int N = 2000;
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    /* Generate dummy passwords */
    char pw_buf[4][16];
    const char *pw[4] = { pw_buf[0], pw_buf[1], pw_buf[2], pw_buf[3] };
    int pwlen[4];
    for (int j = 0; j < 4; j++) {
        snprintf(pw_buf[j], 16, "bench%03d", j);
        pwlen[j] = (int)strlen(pw_buf[j]);
    }

    uint64_t t0 = mach_absolute_time();
    for (int i = 0; i < N; i += 4) {
        /* Vary passwords to avoid caching effects */
        for (int j = 0; j < 4; j++) {
            pw_buf[j][5] = (char)('0' + ((i + j) / 100) % 10);
            pw_buf[j][6] = (char)('0' + ((i + j) / 10) % 10);
            pw_buf[j][7] = (char)('0' + (i + j) % 10);
            pwlen[j] = 8;
        }
        pdf_verify_user_batch4(&g_enc_params, pw, pwlen);
    }
    uint64_t t1 = mach_absolute_time();
    double secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    return secs > 0 ? N / secs : 0;
#else
    return 0;
#endif
}

/* Benchmark scalar CPU (single-core baseline).
 * Returns estimated passwords/sec. */
static double benchmark_scalar_rate(void)
{
    const int N = 2000;
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    char pw[16];
    uint64_t t0 = mach_absolute_time();
    for (int i = 0; i < N; i++) {
        snprintf(pw, 16, "bench%d", i);
        pdf_verify_user_password(&g_enc_params, pw);
    }
    uint64_t t1 = mach_absolute_time();
    double secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    return secs > 0 ? N / secs : 0;
}

/* Select the best engine for R2-R4 (MD5+RC4).
 * Sets g_use_gpu and g_use_neon based on benchmarking.
 * The GPU runs as a single pipeline alongside CPU threads, so we
 * compare GPU throughput against per-core NEON throughput scaled by
 * the number of cores — whichever gives higher total throughput wins. */
static void select_best_engine(int nthreads)
{
    double scalar = benchmark_scalar_rate();
    double gpu    = benchmark_gpu_rate();
    double neon   = benchmark_neon_rate();

    fprintf(stderr, "Bench  : scalar %.0f/s, NEON %.0f/s, GPU %.0f/s (per-core)",
            scalar, neon, gpu);

    /* Estimate total throughput for each strategy:
     * - GPU mode:  GPU pipeline + nthreads * scalar  (CPU does RC4 only)
     * - NEON mode: nthreads * neon_per_core
     * - Scalar:    nthreads * scalar_per_core
     *
     * For R2-R4, NEON gives ~4x per-core improvement because it runs
     * 4 independent MD5 computations per core.  GPU does MD5 on chip
     * but RC4 verification creates a CPU bottleneck, so it typically
     * loses to NEON on Apple Silicon. */
    double gpu_total  = gpu + (double)nthreads * scalar;
    double neon_total = (double)nthreads * neon;
    double cpu_total  = (double)nthreads * scalar;

    if (neon >= scalar && neon_total >= gpu_total) {
        /* NEON wins — disable GPU, enable NEON */
        g_use_neon = 1;
        g_use_gpu  = 0;
        if (g_gpu_ctx) { metal_keygen_free(g_gpu_ctx); g_gpu_ctx = NULL; }
        fprintf(stderr, " — NEON selected (%.0f/s est.)\n", neon_total);
    } else if (gpu_total > cpu_total && gpu > scalar * 0.5) {
        /* GPU wins */
        g_use_gpu  = 1;
        g_use_neon = 0;
        fprintf(stderr, " — GPU selected (%.0f/s est.)\n", gpu_total);
    } else {
        /* Scalar CPU wins (shouldn't happen in practice) */
        g_use_gpu  = 0;
        g_use_neon = 0;
        if (g_gpu_ctx) { metal_keygen_free(g_gpu_ctx); g_gpu_ctx = NULL; }
        fprintf(stderr, " — scalar CPU (%.0f/s est.)\n", cpu_total);
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
            g_idx_to_pass(start + i, a->length, pw);
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
 * Rule-based mutation worker
 * ================================================================ */
static void *rule_worker(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    (void)arg;
    CGPDFDocumentRef doc = NULL;
    if (!g_fast_crypto) {
        doc = open_pdf();
        if (!doc) { free(arg); return NULL; }
    }

    long total = g_nwords * g_nrules;
    long local_count = 0;
    char pass[MAX_PASS_LEN * 2 + 2];

    for (;;) {
        if (__builtin_expect(atomic_load_explicit(&g_found,
                             memory_order_relaxed), 0))
            break;
        long chunk_start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (chunk_start >= total) break;
        long chunk_end = chunk_start + CPU_WORK_CHUNK;
        if (chunk_end > total) chunk_end = total;

        for (long i = chunk_start; i < chunk_end; i++) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            long word_idx = i / g_nrules;
            int  rule_idx = (int)(i % g_nrules);
            apply_rule(g_words[word_idx], rule_idx, pass);

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

/* GPU rule worker */
static void *gpu_rule_worker(void *arg)
{
    (void)arg;
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);
    long total = g_nwords * g_nrules;

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    char *pw_storage = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));
    uint8_t *keys = malloc((size_t)GPU_BATCH_SIZE * key_bytes);

    if (!pw_ptrs || !pw_storage || !keys) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / g_nrules;
            int  rule_idx = (int)(idx % g_nrules);
            char *pw = pw_storage + i * (MAX_PASS_LEN * 2 + 2);
            apply_rule(g_words[word_idx], rule_idx, pw);
            pw_ptrs[i] = pw;
        }

        int n = metal_keygen_batch(g_gpu_ctx, pw_ptrs, count, keys);
        if (n <= 0) break;

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
 * Hybrid attack worker (dict + brute-force suffix)
 * ================================================================ */
static void *hybrid_worker(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    (void)arg;
    CGPDFDocumentRef doc = NULL;
    if (!g_fast_crypto) {
        doc = open_pdf();
        if (!doc) { free(arg); return NULL; }
    }

    long total = g_nwords * g_hybrid_suffix_keyspace;
    long local_count = 0;
    char pass[MAX_PASS_LEN * 2 + 2];

    for (;;) {
        if (__builtin_expect(atomic_load_explicit(&g_found,
                             memory_order_relaxed), 0))
            break;
        long chunk_start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (chunk_start >= total) break;
        long chunk_end = chunk_start + CPU_WORK_CHUNK;
        if (chunk_end > total) chunk_end = total;

        for (long i = chunk_start; i < chunk_end; i++) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            long word_idx = i / g_hybrid_suffix_keyspace;
            long suffix_idx = i % g_hybrid_suffix_keyspace;
            hybrid_gen_pass(word_idx, suffix_idx, pass);

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

/* GPU hybrid worker */
static void *gpu_hybrid_worker(void *arg)
{
    (void)arg;
    int key_bytes = metal_keygen_key_bytes(g_gpu_ctx);
    long total = g_nwords * g_hybrid_suffix_keyspace;

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    char *pw_storage = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));
    uint8_t *keys = malloc((size_t)GPU_BATCH_SIZE * key_bytes);

    if (!pw_ptrs || !pw_storage || !keys) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / g_hybrid_suffix_keyspace;
            long suffix_idx = idx % g_hybrid_suffix_keyspace;
            char *pw = pw_storage + i * (MAX_PASS_LEN * 2 + 2);
            hybrid_gen_pass(word_idx, suffix_idx, pw);
            pw_ptrs[i] = pw;
        }

        int n = metal_keygen_batch(g_gpu_ctx, pw_ptrs, count, keys);
        if (n <= 0) break;

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
 * R5 SHA-256 GPU workers — full verification on GPU, no CPU step
 * ================================================================ */

static void *gpu_sha256_brute_worker(void *arg)
{
    GPUBruteArg *a = (GPUBruteArg *)arg;

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    char *pw_storage = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));

    if (!pw_ptrs || !pw_storage) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->total) end = a->total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage + i * (MAX_PASS_LEN + 1);
            g_idx_to_pass(start + i, a->length, pw);
            pw_ptrs[i] = pw;
        }

        int match = metal_sha256_verify_batch(g_sha256_ctx, pw_ptrs, count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[match], MAX_PASS_LEN);
        }

        atomic_fetch_add_explicit(&g_tested, (long)count, memory_order_relaxed);
    }

done:
    free(pw_ptrs);
    free(pw_storage);
    free(arg);
    return NULL;
}

static void *gpu_sha256_dict_worker(void *arg)
{
    (void)arg;

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    if (!pw_ptrs) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= g_nwords) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > g_nwords) end = g_nwords;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++)
            pw_ptrs[i] = g_words[start + i];

        int match = metal_sha256_verify_batch(g_sha256_ctx,
                                               (const char **)pw_ptrs, count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[match], MAX_PASS_LEN);
        }

        atomic_fetch_add_explicit(&g_tested, (long)count, memory_order_relaxed);
    }

done:
    free(pw_ptrs);
    free(arg);
    return NULL;
}

static void *gpu_sha256_rule_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_nrules;

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    char *pw_storage = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));

    if (!pw_ptrs || !pw_storage) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / g_nrules;
            int  rule_idx = (int)(idx % g_nrules);
            char *pw = pw_storage + i * (MAX_PASS_LEN * 2 + 2);
            apply_rule(g_words[word_idx], rule_idx, pw);
            pw_ptrs[i] = pw;
        }

        int match = metal_sha256_verify_batch(g_sha256_ctx, pw_ptrs, count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[match], MAX_PASS_LEN);
        }

        atomic_fetch_add_explicit(&g_tested, (long)count, memory_order_relaxed);
    }

done:
    free(pw_ptrs);
    free(pw_storage);
    free(arg);
    return NULL;
}

static void *gpu_sha256_hybrid_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_hybrid_suffix_keyspace;

    const char **pw_ptrs = malloc(sizeof(char *) * GPU_BATCH_SIZE);
    char *pw_storage = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));

    if (!pw_ptrs || !pw_storage) goto done;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / g_hybrid_suffix_keyspace;
            long suffix_idx = idx % g_hybrid_suffix_keyspace;
            char *pw = pw_storage + i * (MAX_PASS_LEN * 2 + 2);
            hybrid_gen_pass(word_idx, suffix_idx, pw);
            pw_ptrs[i] = pw;
        }

        int match = metal_sha256_verify_batch(g_sha256_ctx, pw_ptrs, count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[match], MAX_PASS_LEN);
        }

        atomic_fetch_add_explicit(&g_tested, (long)count, memory_order_relaxed);
    }

done:
    free(pw_ptrs);
    free(pw_storage);
    free(arg);
    return NULL;
}

/* ================================================================
 * R6 GPU workers (Algorithm 2.B — SHA-256/384/512 + AES on GPU)
 * ================================================================ */

static void *gpu_r6_brute_worker(void *arg)
{
    GPUBruteArg *a = (GPUBruteArg *)arg;
    int batch = metal_r6_max_batch(g_r6_ctx);

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

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= a->total) break;
        long end = start + batch;
        if (end > a->total) end = a->total;
        int count = (int)(end - start);

        /* Prepare passwords on current buffer */
        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            g_idx_to_pass(start + i, a->length, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        /* Wait for previous batch if any */
        if (pending_handle) {
            int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
            pending_handle = NULL;
            if (match >= 0) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
            }
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        /* Submit current batch asynchronously */
        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    /* Wait for final batch */
    if (pending_handle) {
        int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
        }
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) {
        free(pw_ptrs[b]);
        free(pw_storage[b]);
    }
    free(arg);
    return NULL;
}

static void *gpu_r6_dict_worker(void *arg)
{
    (void)arg;
    int batch = metal_r6_max_batch(g_r6_ctx);

    const char **pw_ptrs[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        if (!pw_ptrs[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= g_nwords) break;
        long end = start + batch;
        if (end > g_nwords) end = g_nwords;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++)
            pw_ptrs[cur_buf][i] = g_words[start + i];

        if (pending_handle) {
            int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
            pending_handle = NULL;
            if (match >= 0) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
            }
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
        }
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) free(pw_ptrs[b]);
    free(arg);
    return NULL;
}

static void *gpu_r6_rule_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_nrules;
    int batch = metal_r6_max_batch(g_r6_ctx);

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= total) break;
        long end = start + batch;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / g_nrules;
            int  rule_idx = (int)(idx % g_nrules);
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            apply_rule(g_words[word_idx], rule_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
            pending_handle = NULL;
            if (match >= 0) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
            }
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
        }
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) {
        free(pw_ptrs[b]);
        free(pw_storage[b]);
    }
    free(arg);
    return NULL;
}

static void *gpu_r6_hybrid_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_hybrid_suffix_keyspace;
    int batch = metal_r6_max_batch(g_r6_ctx);

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= total) break;
        long end = start + batch;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / g_hybrid_suffix_keyspace;
            long suffix_idx = idx % g_hybrid_suffix_keyspace;
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            hybrid_gen_pass(word_idx, suffix_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
            pending_handle = NULL;
            if (match >= 0) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
            }
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        int match = metal_r6_wait_results(g_r6_ctx, pending_handle, pending_count);
        if (match >= 0) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw_ptrs[pending_buf][match], MAX_PASS_LEN);
        }
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
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
 * Benchmark mode: measure passwords/second on all engines
 * ================================================================ */
static void run_benchmark(int nthreads)
{
    fprintf(stderr, "\n── Benchmark Mode ─────────────────────────────────\n");

    const int BENCH_SECS = 2;
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    /* Generate dummy passwords for benchmarking */
    char dummy_buf[10000][16];
    for (int i = 0; i < 10000; i++)
        snprintf(dummy_buf[i], 16, "bench%07d", i);

    /* ── Single-core benchmark ─────────────────────────────────── */
    uint64_t t0 = mach_absolute_time();
    long count = 0;
    for (;;) {
        for (int i = 0; i < 10000; i++) {
            pdf_verify_password(&g_enc_params, dummy_buf[i]);
            count++;
        }
        uint64_t now = mach_absolute_time();
        double elapsed = (double)(now - t0) * tb.numer / tb.denom / 1e9;
        if (elapsed >= BENCH_SECS) break;
    }
    uint64_t t1 = mach_absolute_time();
    double single_secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    double single_rate = single_secs > 0 ? (double)count / single_secs : 0;
    fprintf(stderr, "  Single-core : %.0f passwords/sec\n", single_rate);

    /* ── Multi-core benchmark ──────────────────────────────────── */
    /* Use brute_worker with a fake keyspace */
    atomic_store(&g_found, 0);
    atomic_store(&g_tested, 0);
    atomic_store(&g_next_idx, 0);

    const char *saved_charset = g_charset;
    int saved_cs_len = g_cs_len;
    g_charset = "abcdefghij";
    g_cs_len  = 10;
    void (*saved_fn)(long, int, char *) = g_idx_to_pass;
    g_idx_to_pass = index_to_pass;

    long bench_total = 10000000L; /* large enough for 2 seconds */
    pthread_t thr[MAX_THREADS];
    int spawned = 0;

    for (int t = 0; t < nthreads && t < MAX_THREADS; t++) {
        BruteArg *a = malloc(sizeof(BruteArg));
        *a = (BruteArg){ .id = t, .length = 7,
                         .start = 0, .end = bench_total, .use_shared = 1 };
        pthread_create(&thr[spawned++], NULL, brute_worker, a);
    }

    /* Let them run for BENCH_SECS seconds */
    t0 = mach_absolute_time();
    for (;;) {
        struct timespec sl = {0, 100000000L}; /* 100ms */
        nanosleep(&sl, NULL);
        t1 = mach_absolute_time();
        double elapsed = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
        if (elapsed >= BENCH_SECS) break;
    }
    atomic_store(&g_found, 1); /* signal stop */
    for (int t = 0; t < spawned; t++) pthread_join(thr[t], NULL);

    t1 = mach_absolute_time();
    double multi_secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
    long multi_tested = atomic_load(&g_tested);
    double multi_rate = multi_secs > 0 ? (double)multi_tested / multi_secs : 0;
    fprintf(stderr, "  Multi-core  : %.0f passwords/sec (%d threads)\n",
            multi_rate, nthreads);

    /* ── GPU benchmark ─────────────────────────────────────────── */
    if (g_gpu_ctx || g_sha256_ctx || g_r6_ctx) {
        atomic_store(&g_found, 0);
        atomic_store(&g_tested, 0);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        GPUBruteArg *ga = malloc(sizeof(GPUBruteArg));
        *ga = (GPUBruteArg){ .length = 7, .total = bench_total };
        void *(*gpu_worker)(void *) = gpu_brute_worker;
        if (g_r6_ctx)       gpu_worker = gpu_r6_brute_worker;
        else if (g_sha256_ctx) gpu_worker = gpu_sha256_brute_worker;
        pthread_create(&thr[spawned++], NULL, gpu_worker, ga);

        t0 = mach_absolute_time();
        for (;;) {
            struct timespec sl = {0, 100000000L};
            nanosleep(&sl, NULL);
            t1 = mach_absolute_time();
            double elapsed = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
            if (elapsed >= BENCH_SECS) break;
        }
        atomic_store(&g_found, 1);
        for (int t = 0; t < spawned; t++) pthread_join(thr[t], NULL);

        t1 = mach_absolute_time();
        double gpu_secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
        long gpu_tested = atomic_load(&g_tested);
        double gpu_rate = gpu_secs > 0 ? (double)gpu_tested / gpu_secs : 0;
        fprintf(stderr, "  GPU         : %.0f passwords/sec\n", gpu_rate);

        /* ── GPU+CPU cooperative benchmark ─────────────────────── */
        atomic_store(&g_found, 0);
        atomic_store(&g_tested, 0);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        GPUBruteArg *ga2 = malloc(sizeof(GPUBruteArg));
        *ga2 = (GPUBruteArg){ .length = 7, .total = bench_total };
        void *(*gpu_worker2)(void *) = gpu_brute_worker;
        if (g_r6_ctx)          gpu_worker2 = gpu_r6_brute_worker;
        else if (g_sha256_ctx) gpu_worker2 = gpu_sha256_brute_worker;
        pthread_create(&thr[spawned++], NULL, gpu_worker2, ga2);

        for (int t = 0; t < nthreads && spawned < MAX_THREADS; t++) {
            BruteArg *a = malloc(sizeof(BruteArg));
            *a = (BruteArg){ .id = t, .length = 7,
                             .start = 0, .end = bench_total, .use_shared = 1 };
            pthread_create(&thr[spawned++], NULL, brute_worker, a);
        }

        t0 = mach_absolute_time();
        for (;;) {
            struct timespec sl = {0, 100000000L};
            nanosleep(&sl, NULL);
            t1 = mach_absolute_time();
            double elapsed = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
            if (elapsed >= BENCH_SECS) break;
        }
        atomic_store(&g_found, 1);
        for (int t = 0; t < spawned; t++) pthread_join(thr[t], NULL);

        t1 = mach_absolute_time();
        double coop_secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
        long coop_tested = atomic_load(&g_tested);
        double coop_rate = coop_secs > 0 ? (double)coop_tested / coop_secs : 0;
        fprintf(stderr, "  GPU+CPU     : %.0f passwords/sec (cooperative, %d threads)\n",
                coop_rate, nthreads);
    } else {
        fprintf(stderr, "  GPU         : not available\n");
    }

    fprintf(stderr, "───────────────────────────────────────────────────\n\n");

    /* Restore state */
    g_charset = saved_charset;
    g_cs_len  = saved_cs_len;
    g_idx_to_pass = saved_fn;
    atomic_store(&g_found, 0);
    atomic_store(&g_tested, 0);
    atomic_store(&g_next_idx, 0);
}

/* ================================================================
 * Wordlist loader
 * ================================================================ */

/* Compare for qsort: shorter words first, then alphabetical */
static int word_cmp(const void *a, const void *b)
{
    const char *wa = *(const char *const *)a;
    const char *wb = *(const char *const *)b;
    size_t la = strlen(wa);
    size_t lb = strlen(wb);
    if (la != lb) return (la < lb) ? -1 : 1;
    return strcmp(wa, wb);
}

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
    fclose(f);

    /* Sort by length (shorter first), then alphabetically */
    qsort(g_words, (size_t)idx, sizeof(char *), word_cmp);

    /* Remove adjacent duplicates */
    long unique = 0;
    for (long i = 0; i < idx; i++) {
        if (i > 0 && strcmp(g_words[i], g_words[unique - 1]) == 0) {
            free(g_words[i]);
        } else {
            g_words[unique++] = g_words[i];
        }
    }
    long dups = idx - unique;
    g_nwords = unique;

    fprintf(stderr, "Loaded %ld words (%ld duplicates removed, sorted by length)\n",
            unique, dups);
    return 1;
}

/* ================================================================
 * Interactive password interview
 * ================================================================ */
typedef struct {
    char charset[256];
    int  min_len;
    int  max_len;
    char prefix[MAX_PASS_LEN + 1];
    char suffix[MAX_PASS_LEN + 1];
    int  configured;
} PasswordHints;

static void read_line(char *buf, size_t sz)
{
    if (!fgets(buf, (int)sz, stdin)) buf[0] = '\0';
    buf[strcspn(buf, "\n")] = '\0';
}

static PasswordHints interactive_interview(void)
{
    PasswordHints h = {0};
    h.min_len = 1;
    h.max_len = 8;
    strcpy(h.charset, DEFAULT_CHARSET);

    char buf[256];

    fprintf(stderr, "\n── Password Interview ──────────────────────────────\n");
    fprintf(stderr, "Answer what you can. Press Enter to skip any question.\n");
    fprintf(stderr, "These hints guide the search order but won't prevent\n");
    fprintf(stderr, "trying other possibilities if they don't work.\n\n");

    /* Character types */
    fprintf(stderr, "What characters might the password contain?\n");
    fprintf(stderr, "  1) Digits only (0-9)\n");
    fprintf(stderr, "  2) Lowercase letters + digits\n");
    fprintf(stderr, "  3) Letters + digits (mixed case)\n");
    fprintf(stderr, "  4) Letters + digits + symbols\n");
    fprintf(stderr, "  5) Custom charset\n");
    fprintf(stderr, "  [Enter = try all, starting with digits]\n");
    fprintf(stderr, "> ");
    read_line(buf, sizeof(buf));

    if (buf[0] == '1') {
        strcpy(h.charset, "0123456789");
    } else if (buf[0] == '2') {
        strcpy(h.charset, "abcdefghijklmnopqrstuvwxyz0123456789");
    } else if (buf[0] == '3') {
        strcpy(h.charset, DEFAULT_CHARSET);
    } else if (buf[0] == '4') {
        strcpy(h.charset, DEFAULT_CHARSET "!@#$%^&*()-_=+[]{}|;:',.<>?/`~");
    } else if (buf[0] == '5') {
        fprintf(stderr, "Enter charset: ");
        read_line(buf, sizeof(buf));
        if (buf[0]) strncpy(h.charset, buf, sizeof(h.charset) - 1);
    }

    /* Length */
    fprintf(stderr, "\nApproximate password length? (e.g. \"4\", \"6-8\")\n");
    fprintf(stderr, "  [Enter = try 1 to 8]\n");
    fprintf(stderr, "> ");
    read_line(buf, sizeof(buf));

    if (buf[0]) {
        char *dash = strchr(buf, '-');
        if (dash) {
            h.min_len = atoi(buf);
            h.max_len = atoi(dash + 1);
        } else {
            int n = atoi(buf);
            if (n > 0) { h.min_len = n; h.max_len = n; }
        }
        if (h.min_len < 1) h.min_len = 1;
        if (h.max_len < h.min_len) h.max_len = h.min_len;
        if (h.max_len > MAX_PASS_LEN) h.max_len = MAX_PASS_LEN;
    }

    /* Known prefix/suffix */
    fprintf(stderr, "\nDoes the password start with anything known? (e.g. \"pass\")\n");
    fprintf(stderr, "  [Enter = unknown]\n");
    fprintf(stderr, "> ");
    read_line(buf, sizeof(buf));
    if (buf[0]) strncpy(h.prefix, buf, MAX_PASS_LEN);

    fprintf(stderr, "\nDoes the password end with anything known? (e.g. \"2024\")\n");
    fprintf(stderr, "  [Enter = unknown]\n");
    fprintf(stderr, "> ");
    read_line(buf, sizeof(buf));
    if (buf[0]) strncpy(h.suffix, buf, MAX_PASS_LEN);

    /* Summary */
    fprintf(stderr, "\n── Plan ────────────────────────────────────────────\n");
    fprintf(stderr, "  Charset: \"%s\" (%d chars)\n", h.charset, (int)strlen(h.charset));
    fprintf(stderr, "  Length : %d", h.min_len);
    if (h.max_len != h.min_len) fprintf(stderr, "-%d", h.max_len);
    fprintf(stderr, "\n");
    if (h.prefix[0]) fprintf(stderr, "  Prefix : \"%s\"\n", h.prefix);
    if (h.suffix[0]) fprintf(stderr, "  Suffix : \"%s\"\n", h.suffix);
    fprintf(stderr, "────────────────────────────────────────────────────\n\n");

    h.configured = 1;
    return h;
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
        "  %s -f <pdf> -m <mask>                    mask attack\n"
        "  %s -f <pdf> -d <wordlist> -R             rule-based mutations\n"
        "  %s -f <pdf> -d <wordlist> -H <sufflen>   hybrid dict+suffix\n"
        "  %s -f <pdf> -A -d <wordlist> [-b] [-l N] auto mode (chains attacks)\n"
        "  %s -f <pdf> -B                           benchmark mode\n"
        "\nOptions:\n"
        "  -f  PDF file\n"
        "  -d  wordlist (one password per line)\n"
        "  -b  brute-force mode\n"
        "  -l  max password length (default: 4)\n"
        "  -c  charset (default: a-zA-Z0-9)\n"
        "  -t  threads (default: CPU core count)\n"
        "  -G  disable GPU acceleration\n"
        "  -r  resume from checkpoint\n"
        "  -i  interactive mode (ask about password)\n"
        "  -m  mask attack (e.g. \"?u?u?u?d?d?d\" = 3 upper + 3 digits)\n"
        "        ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all\n"
        "        ?h=hex-lower ?H=hex-upper ?w=dict word ?1..?4=custom charset\n"
        "        [a-f]=inline range, other characters are literal\n"
        "  -1  custom charset 1 (e.g. -1 abc)\n"
        "  -2  custom charset 2\n"
        "  -3  custom charset 3\n"
        "  -4  custom charset 4\n"
        "  -R [file]  rule-based mutations (use with -d; file=rules file, omit for built-in)\n"
        "        rules file: one rule per line, hashcat-compatible op codes, # for comments\n"
        "        ops: l u c r d $X ^X TN iNX oNX DN [N ]N sXY @X pN yN YN *NM L(leet)\n"
        "  -H  hybrid attack (use with -d, e.g. -H 3 or -H \"?d?d?d?s\")\n"
        "        argument is max suffix length\n"
        "  -A  auto mode: chains dict -> rules -> freq brute 1-6 -> brute 7-max\n"
        "  -B  benchmark mode (measure speed, no cracking)\n"
        "  -F  frequency-ordered brute-force charset\n"
        "  -O  crack owner password only\n"
        "  -U  crack user password only\n"
        "  -M  load Markov model for probability-ordered brute-force\n"
        "  --markov-train <wordlist>   train a Markov model from a wordlist\n"
        "  --markov-output <file>      output file for trained model (default: markov.model)\n"
        "  --markov-threshold <N>      prune to top-N chars per position\n"
        "  --markov-generate <N>       output top-N candidates from model\n"
        "  --generate-wordlist <pat>   generate wordlist from pattern (e.g. \"Name{1990-2000}\")\n"
        "  --combine                   merge and dedup wordlists from remaining args\n",
        p, p, p, p, p, p, p);
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
    const char *mask_str  = NULL;
    int         brute     = 0;
    int         max_len   = 4;
    int         no_gpu    = 0;
    int         resume    = 0;
    int         interactive = 0;
    int         min_len   = 1;
    int         nthreads  = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 4;

    /* Long options for Markov and wordlist tooling */
    const char *markov_train_wordlist = NULL;
    const char *markov_train_output   = NULL;
    const char *markov_model_path     = NULL;
    int         markov_threshold      = 0;
    const char *generate_pattern      = NULL;
    int         markov_generate_n     = 0;
    int         combine_mode          = 0;

    static struct option long_opts[] = {
        {"markov-train",     required_argument, NULL, 0x100},
        {"markov-output",    required_argument, NULL, 0x101},
        {"markov-threshold", required_argument, NULL, 0x102},
        {"generate-wordlist",required_argument, NULL, 0x103},
        {"combine",          no_argument,       NULL, 0x104},
        {"markov-generate",  required_argument, NULL, 0x105},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:d:bl:c:t:Grim:R::H:BFAOU1:2:3:4:M:",
                              long_opts, NULL)) != -1) {
        switch (opt) {
            case 'f': pdf_path    = optarg;       break;
            case 'd': dict_path   = optarg;       break;
            case 'b': brute       = 1;            break;
            case 'l': max_len     = atoi(optarg); break;
            case 'c': charset     = optarg;       break;
            case 't': nthreads    = atoi(optarg); break;
            case 'G': no_gpu      = 1;            break;
            case 'r': resume      = 1;            break;
            case 'i': interactive = 1;            break;
            case 'm': mask_str    = optarg; g_mask_mode = 1;
                      strncpy(g_mask_str, optarg, sizeof(g_mask_str) - 1);
                      break;
            case 'R': g_rule_mode = 1;
                      if (optarg) g_rules_file = optarg;
                      break;
            case 'H': g_hybrid_mode = 1;
                      if (strchr(optarg, '?') || strchr(optarg, '[')) {
                          g_hybrid_mask_mode = 1;
                          strncpy(g_hybrid_mask_str, optarg, sizeof(g_hybrid_mask_str) - 1);
                      } else {
                          g_hybrid_suffix_len = atoi(optarg);
                      }
                      break;
            case 'B': g_benchmark_mode = 1;       break;
            case 'F': g_freq_mode = 1;            break;
            case 'A': g_auto_mode = 1;            break;
            case 'O': g_password_mode = PW_MODE_OWNER; break;
            case 'U': g_password_mode = PW_MODE_USER;  break;
            case '1': case '2': case '3': case '4': {
                int ci = opt - '1';
                g_custom_charset[ci] = optarg;
                strncpy(g_custom_charset_str[ci], optarg,
                        sizeof(g_custom_charset_str[ci]) - 1);
                break;
            }
            case 'M': markov_model_path = optarg; break;
            case 0x100: markov_train_wordlist = optarg; break;
            case 0x101: markov_train_output   = optarg; break;
            case 0x102: markov_threshold      = atoi(optarg); break;
            case 0x103: generate_pattern      = optarg; break;
            case 0x104: combine_mode          = 1; break;
            case 0x105: markov_generate_n     = atoi(optarg); break;
            default:  usage(argv[0]);
        }
    }

    /* ── Handle standalone utility modes (no PDF needed) ─────── */

    /* Markov training mode */
    if (markov_train_wordlist) {
        const char *out_path = markov_train_output ? markov_train_output : "markov.model";
        markov_train(markov_train_wordlist, out_path);
        return 0;
    }

    /* Generate wordlist from pattern: "Name{1990-2000}" → Name1990..Name2000 */
    if (generate_pattern) {
        const char *p = generate_pattern;
        char prefix[256] = {0};
        int pi = 0;

        while (*p && *p != '{' && pi < 255)
            prefix[pi++] = *p++;
        prefix[pi] = '\0';

        if (*p == '{') {
            p++; /* skip '{' */
            /* Parse ranges and literals inside braces, support multiple {..} */
            /* For simplicity: handle "prefix{N-M}" → prefix N, prefix N+1, ..., prefix M */
            /* Also support "prefix{N-M}{N2-M2}" → nested iteration */
            /* Single brace for now */
            long range_start = 0, range_end = 0;
            char suffix[256] = {0};

            range_start = strtol(p, (char **)&p, 10);
            if (*p == '-') {
                p++;
                range_end = strtol(p, (char **)&p, 10);
            } else {
                range_end = range_start;
            }
            if (*p == '}') p++;
            strncpy(suffix, p, sizeof(suffix) - 1);

            /* Handle nested second brace */
            const char *brace2 = strchr(suffix, '{');
            if (brace2) {
                char suffix_pre[256] = {0};
                memcpy(suffix_pre, suffix, (size_t)(brace2 - suffix));
                const char *q = brace2 + 1;
                long r2_start = strtol(q, (char **)&q, 10);
                long r2_end = r2_start;
                if (*q == '-') { q++; r2_end = strtol(q, (char **)&q, 10); }
                if (*q == '}') q++;

                for (long i = range_start; i <= range_end; i++) {
                    for (long j = r2_start; j <= r2_end; j++) {
                        printf("%s%ld%s%ld%s\n", prefix, i, suffix_pre, j, q);
                    }
                }
            } else {
                for (long i = range_start; i <= range_end; i++)
                    printf("%s%ld%s\n", prefix, i, suffix);
            }
        } else {
            /* No braces — just output the pattern as-is */
            printf("%s\n", generate_pattern);
        }
        return 0;
    }

    /* Combine and dedup wordlists from remaining args */
    if (combine_mode) {
        /* FNV-1a hash set for dedup */
        #define COMBINE_HASH_SIZE (1 << 20)  /* 1M buckets */
        typedef struct CombineNode {
            char *word;
            struct CombineNode *next;
        } CombineNode;

        CombineNode **buckets = calloc(COMBINE_HASH_SIZE, sizeof(CombineNode *));
        if (!buckets) { perror("calloc"); return 1; }

        long total = 0, unique = 0;

        for (int fi = optind; fi < argc; fi++) {
            FILE *f = fopen(argv[fi], "r");
            if (!f) { perror(argv[fi]); continue; }

            char line[MAX_PASS_LEN + 4];
            while (fgets(line, sizeof(line), f)) {
                size_t len = strlen(line);
                while (len && (line[len-1] == '\n' || line[len-1] == '\r'))
                    line[--len] = '\0';
                if (!len) continue;
                total++;

                /* FNV-1a hash */
                uint32_t h = 2166136261u;
                for (size_t i = 0; i < len; i++) {
                    h ^= (uint8_t)line[i];
                    h *= 16777619u;
                }
                int bucket = (int)(h & (COMBINE_HASH_SIZE - 1));

                /* Check for duplicate */
                int found = 0;
                for (CombineNode *n = buckets[bucket]; n; n = n->next) {
                    if (strcmp(n->word, line) == 0) { found = 1; break; }
                }
                if (found) continue;

                /* Add to hash set and output */
                CombineNode *node = malloc(sizeof(CombineNode));
                node->word = strdup(line);
                node->next = buckets[bucket];
                buckets[bucket] = node;
                unique++;
                printf("%s\n", line);
            }
            fclose(f);
        }

        /* Cleanup */
        for (int i = 0; i < COMBINE_HASH_SIZE; i++) {
            CombineNode *n = buckets[i];
            while (n) {
                CombineNode *next = n->next;
                free(n->word);
                free(n);
                n = next;
            }
        }
        free(buckets);

        fprintf(stderr, "Combined: %ld total, %ld unique (%ld duplicates removed)\n",
                total, unique, total - unique);
        return 0;
    }

    /* Markov generate: output top-N candidates from model */
    if (markov_generate_n > 0) {
        const char *model_path = markov_model_path;
        if (!model_path && markov_train_output) model_path = markov_train_output;
        if (!model_path) model_path = "markov.model";

        MarkovModel *m = markov_load(model_path);
        if (!m) return 1;
        g_markov = m;

        if (markov_threshold > 0)
            g_markov->threshold = markov_threshold;

        /* Generate passwords of varying lengths */
        int gen_max_len = max_len > 0 ? max_len : 8;
        int gen_min_len = min_len > 0 ? min_len : 1;
        int generated = 0;

        for (int len = gen_min_len; len <= gen_max_len && generated < markov_generate_n; len++) {
            int effective_cs = g_markov->threshold < g_markov->charset_size
                             ? g_markov->threshold : g_markov->charset_size;
            long ks = 1;
            for (int i = 0; i < len; i++) {
                if (ks > (long)2e18 / effective_cs) { ks = (long)2e18; break; }
                ks *= effective_cs;
            }
            long limit = markov_generate_n - generated;
            if (limit > ks) limit = ks;

            char pass[MAX_PASS_LEN + 1];
            for (long idx = 0; idx < limit; idx++) {
                markov_index_to_pass(idx, len, pass);
                printf("%s\n", pass);
                generated++;
            }
        }

        free(g_markov);
        g_markov = NULL;
        return 0;
    }

    if (!pdf_path) { fprintf(stderr, "-f required\n"); usage(argv[0]); }

    /* ── Interactive interview ─────────────────────────────────── */
    PasswordHints hints = {0};
    if (interactive) {
        hints = interactive_interview();
        charset = hints.charset;
        min_len = hints.min_len;
        max_len = hints.max_len;
        brute   = 1;
        if (hints.prefix[0]) {
            strncpy(g_prefix, hints.prefix, MAX_PASS_LEN);
            g_prefix_len = (int)strlen(g_prefix);
        }
        if (hints.suffix[0]) {
            strncpy(g_suffix, hints.suffix, MAX_PASS_LEN);
            g_suffix_len = (int)strlen(g_suffix);
        }
        /* Adjust lengths: user specifies total, we brute-force the middle */
        min_len = min_len - g_prefix_len - g_suffix_len;
        max_len = max_len - g_prefix_len - g_suffix_len;
        if (min_len < 0) min_len = 0;
        if (max_len < 0) max_len = 0;
    }

    /* ── Validate new mode combinations ──────────────────────────── */
    if (g_rule_mode && !dict_path) {
        fprintf(stderr, "-R requires -d <wordlist>\n");
        usage(argv[0]);
    }
    if (g_hybrid_mode && !dict_path) {
        fprintf(stderr, "-H requires -d <wordlist>\n");
        usage(argv[0]);
    }
    if (g_hybrid_mode && g_hybrid_mask_mode) {
        if (!parse_mask_into(g_hybrid_mask_str, g_hybrid_mask,
                             &g_hybrid_mask_len, &g_hybrid_suffix_keyspace)) {
            fprintf(stderr, "Invalid hybrid mask: %s\n", g_hybrid_mask_str);
            return 1;
        }
        g_hybrid_suffix_len = g_hybrid_mask_len;
    } else if (g_hybrid_suffix_len < 1 && g_hybrid_mode) {
        fprintf(stderr, "-H requires suffix length >= 1 or mask pattern\n");
        usage(argv[0]);
    }

    /* -A: auto mode validation */
    if (g_auto_mode) {
        if (!dict_path && !brute) {
            fprintf(stderr, "-A requires -d <wordlist> and/or -b\n");
            usage(argv[0]);
        }
    }

    /* -F: frequency-ordered charset for brute-force */
    if (g_freq_mode) {
        charset = FREQ_CHARSET;
    }

    /* -m: mask attack implies brute-force-like mode */
    if (g_mask_mode) {
        /* If mask contains ?w, load wordlist first for combo mode */
        if (strstr(mask_str, "?w")) {
            if (!dict_path) {
                fprintf(stderr, "?w in mask requires -d <wordlist>\n");
                return 1;
            }
            if (!load_wordlist(dict_path)) return 1;
        }
        if (!parse_mask(mask_str)) {
            fprintf(stderr, "Invalid mask: %s\n", mask_str);
            return 1;
        }
    }

    /* When resuming, peek at checkpoint to determine mode before validation */
    if (resume && !brute && !dict_path && !g_mask_mode && !g_auto_mode) {
        ckpt_make_path(pdf_path);
        Checkpoint peek = ckpt_load();
        if (peek.valid) {
            if (peek.attack_mode == ATTACK_BRUTE) brute = 1;
            else if (peek.attack_mode == ATTACK_MASK) {
                g_mask_mode = 1;
                if (peek.mask_pattern[0]) {
                    strncpy(g_mask_str, peek.mask_pattern, sizeof(g_mask_str) - 1);
                    mask_str = g_mask_str;
                    parse_mask(mask_str);
                }
            } else if (peek.attack_mode == ATTACK_AUTO) g_auto_mode = 1;
            else if (peek.attack_mode == ATTACK_RULE) g_rule_mode = 1;
            else if (peek.attack_mode == ATTACK_HYBRID) g_hybrid_mode = 1;
        }
    }

    if (!brute && !dict_path && !g_mask_mode && !g_benchmark_mode && !g_auto_mode && !resume) {
        fprintf(stderr, "-d, -b, -m, -A, or -B required\n");
        usage(argv[0]);
    }
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

    /* Load Markov model if specified */
    if (markov_model_path) {
        g_markov = markov_load(markov_model_path);
        if (!g_markov) return 1;
        if (markov_threshold > 0)
            g_markov->threshold = markov_threshold;
        /* Override charset with Markov charset */
        charset = g_markov->charset;
    }

    /* Set default index-to-password function (mask/markov overrides below) */
    if (g_markov)
        g_idx_to_pass = markov_index_to_pass;
    else
        if (g_mask_mode) {
            /* Check if mask has any ?w word positions */
            g_mask_has_words = 0;
            for (int i = 0; i < g_mask_len; i++) {
                if (g_mask[i].is_word) { g_mask_has_words = 1; break; }
            }
            g_idx_to_pass = g_mask_has_words ? combo_index_to_pass : mask_index_to_pass;
        } else {
            g_idx_to_pass = index_to_pass;
        }

    /* ── Try fast crypto path (direct MD5+RC4) ─────────────────── */
    g_enc_params = pdf_parse_encrypt_file(pdf_path);
    if (g_enc_params.valid) {
        g_fast_crypto = 1;
        if (g_enc_params.revision >= 5)
            fprintf(stderr, "Crypto : direct SHA-256+AES (R%d, %d-bit key)\n",
                    g_enc_params.revision, g_enc_params.key_length);
        else
            fprintf(stderr, "Crypto : direct MD5+RC4 (R%d, %d-bit key)\n",
                    g_enc_params.revision, g_enc_params.key_length);
    } else {
        fprintf(stderr, "Crypto : CGPDFDocument fallback (unsupported encryption)\n");
    }

    /* ── Select best acceleration engine ─────────────────────── */
    if (g_fast_crypto && !no_gpu && g_enc_params.revision <= 4) {
        /* R2-R4: benchmark GPU, NEON, and scalar to pick the best */
        g_gpu_ctx = metal_keygen_init(&g_enc_params, NULL);
        select_best_engine(nthreads);
    } else if (g_fast_crypto && !no_gpu && g_enc_params.revision == 5) {
        /* R5: full SHA-256 verification on GPU (user password) */
        /* check_owner: 0=user, 1=owner. For BOTH mode, start with user pass. */
        int check_owner = (g_password_mode == PW_MODE_OWNER) ? 1 : 0;
        g_sha256_ctx = metal_sha256_init(&g_enc_params, check_owner, NULL);
        if (g_sha256_ctx)
            g_use_gpu = 1;
    } else if (g_fast_crypto && !no_gpu && g_enc_params.revision == 6) {
        /* R6: full Algorithm 2.B verification on GPU */
        int check_owner = (g_password_mode == PW_MODE_OWNER) ? 1 : 0;
        g_r6_ctx = metal_r6_init(&g_enc_params, check_owner, NULL);
        if (g_r6_ctx)
            g_use_gpu = 1;
    } else if (g_fast_crypto && no_gpu && g_enc_params.revision >= 2 &&
               g_enc_params.revision <= 4) {
        /* GPU explicitly disabled — use NEON if available */
#ifdef __ARM_NEON
        g_use_neon = 1;
#endif
    }
    /* If no engine was selected for R2-R4 and GPU not available, try NEON */
#ifdef __ARM_NEON
    if (g_fast_crypto && !g_use_gpu && !g_use_neon &&
        g_enc_params.revision >= 2 && g_enc_params.revision <= 4) {
        g_use_neon = 1;
    }
#endif

    fprintf(stderr, "Target : %s\n", pdf_path);
    fprintf(stderr, "Threads: %d%s%s\n", nthreads,
            g_use_gpu ? " + GPU" : "",
            g_use_neon ? " + NEON SIMD" : "");

    /* ── Benchmark mode: measure speed and exit ───────────────── */
    if (g_benchmark_mode) {
        if (!g_fast_crypto) {
            fprintf(stderr, "Benchmark requires direct crypto (unsupported encryption)\n");
            return 1;
        }
        run_benchmark(nthreads);
        if (g_gpu_ctx) metal_keygen_free(g_gpu_ctx);
        if (g_sha256_ctx) metal_sha256_free(g_sha256_ctx);
        if (g_r6_ctx) metal_r6_free(g_r6_ctx);
        return 0;
    }

    /* ── Checkpoint setup ─────────────────────────────────────── */
    ckpt_make_path(pdf_path);
    Checkpoint ck = {0};
    if (resume) {
        ck = ckpt_load();
        if (ck.valid) {
            static const char *mode_labels[] = {
                "brute-force", "dictionary", "mask", "rule", "hybrid", "auto"
            };
            const char *label = (ck.attack_mode >= 0 && ck.attack_mode <= 5)
                ? mode_labels[ck.attack_mode] : "unknown";
            fprintf(stderr, "Resume : checkpoint found — %s", label);

            if (ck.attack_mode == ATTACK_BRUTE || ck.attack_mode == ATTACK_MASK)
                fprintf(stderr, " len %d idx %ld", ck.resume_len, ck.resume_idx);
            else if (ck.attack_mode == ATTACK_AUTO)
                fprintf(stderr, " phase %d idx %ld", ck.auto_phase, ck.resume_idx);
            else
                fprintf(stderr, " idx %ld", ck.dict_idx);

            if (ck.mask_pattern[0])
                fprintf(stderr, " mask=\"%s\"", ck.mask_pattern);
            fputc('\n', stderr);

            /* Restore prefix/suffix from checkpoint */
            if (ck.prefix[0]) {
                strncpy(g_prefix, ck.prefix, MAX_PASS_LEN);
                g_prefix_len = (int)strlen(g_prefix);
            }
            if (ck.suffix[0]) {
                strncpy(g_suffix, ck.suffix, MAX_PASS_LEN);
                g_suffix_len = (int)strlen(g_suffix);
            }

            /* Restore custom charsets from checkpoint */
            for (int ci = 0; ci < 4; ci++) {
                if (ck.custom_charsets[ci][0] && !g_custom_charset[ci]) {
                    strncpy(g_custom_charset_str[ci], ck.custom_charsets[ci],
                            sizeof(g_custom_charset_str[ci]) - 1);
                    g_custom_charset[ci] = g_custom_charset_str[ci];
                }
            }

            /* Restore mask pattern from checkpoint */
            if (ck.mask_pattern[0] && ck.attack_mode == ATTACK_MASK) {
                strncpy(g_mask_str, ck.mask_pattern, sizeof(g_mask_str) - 1);
                if (!g_mask_mode) {
                    /* Mask wasn't specified on command line — restore it */
                    g_mask_mode = 1;
                    mask_str = g_mask_str;
                    if (!parse_mask(g_mask_str)) {
                        fprintf(stderr, "Cannot parse saved mask: %s\n", g_mask_str);
                        return 1;
                    }
                    g_mask_has_words = 0;
                    for (int mi = 0; mi < g_mask_len; mi++) {
                        if (g_mask[mi].is_word) { g_mask_has_words = 1; break; }
                    }
                    g_idx_to_pass = g_mask_has_words ? combo_index_to_pass : mask_index_to_pass;
                }
            }

            /* Restore hybrid suffix length from checkpoint */
            if (ck.hybrid_suffix_len > 0 && ck.attack_mode == ATTACK_HYBRID) {
                if (!g_hybrid_mode) {
                    g_hybrid_mode = 1;
                    g_hybrid_suffix_len = ck.hybrid_suffix_len;
                }
                if (ck.hybrid_mask[0] && !g_hybrid_mask_mode) {
                    g_hybrid_mask_mode = 1;
                    strncpy(g_hybrid_mask_str, ck.hybrid_mask, sizeof(g_hybrid_mask_str) - 1);
                    parse_mask_into(g_hybrid_mask_str, g_hybrid_mask,
                                    &g_hybrid_mask_len, &g_hybrid_suffix_keyspace);
                }
            }

            /* Restore auto phase from checkpoint */
            if (ck.attack_mode == ATTACK_AUTO) {
                if (!g_auto_mode)
                    g_auto_mode = 1;
                g_auto_phase = ck.auto_phase;
            }

            /* Restore frequency mode from checkpoint */
            if (ck.freq_mode)
                g_freq_mode = 1;

            /* Restore password mode from checkpoint */
            if (ck.password_mode)
                g_password_mode = ck.password_mode;
        } else {
            fprintf(stderr, "Resume : no checkpoint found, starting fresh\n");
        }
    }

    /* ── Register signal handler for graceful shutdown ────────── */
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* ── Start progress thread ─────────────────────────────────── */
    pthread_t prog;
    pthread_create(&prog, NULL, progress_thread, NULL);

    pthread_t threads[MAX_THREADS];
    int       spawned = 0;

    /* ── Auto mode: chain multiple attack phases ──────────────── */
    if (g_auto_mode) {
        g_attack_mode = ATTACK_AUTO;
        int auto_phases = 0;
        int auto_total_phases = 0;

        /* Count how many phases we will run */
        if (dict_path) auto_total_phases++;          /* Phase: dictionary */
        if (dict_path) auto_total_phases++;          /* Phase: rules */
        auto_total_phases++;                         /* Phase: freq brute 1-6 */
        if (max_len > 6) auto_total_phases++;        /* Phase: brute 7-max */

        /* Load wordlist once if provided */
        if (dict_path) {
            if (!load_wordlist(dict_path)) {
                atomic_store(&g_found, 1);
                pthread_join(prog, NULL);
                return 1;
            }
        }

        /* Determine which phase to resume from */
        int resume_phase = (resume && ck.valid && ck.attack_mode == ATTACK_AUTO)
                           ? ck.auto_phase : 0;
        long resume_auto_idx = (resume && ck.valid && ck.attack_mode == ATTACK_AUTO)
                               ? ck.resume_idx : 0;

        /* ── Phase: Dictionary attack ──────────────────────────── */
        if (dict_path && !atomic_load(&g_found)) {
            auto_phases++;
            g_auto_phase = auto_phases;
            if (resume_phase <= auto_phases) {
                long dict_start = (resume_phase == auto_phases) ? resume_auto_idx : 0;
                fprintf(stderr,
                    "\n══ Phase %d/%d: Dictionary attack (%ld words%s) ══\n\n",
                    auto_phases, auto_total_phases, g_nwords,
                    dict_start > 0 ? ", resuming" : "");
                g_is_brute = 0;
                atomic_store(&g_tested, dict_start);
                atomic_store(&g_total, g_nwords);
                atomic_store(&g_next_idx, dict_start);
                g_overall_total = 0;
                g_completed_prior = 0;
                spawned = 0;

                if (g_use_gpu) {
                    pthread_create(&threads[spawned++], NULL,
                                g_r6_ctx ? gpu_r6_dict_worker : g_sha256_ctx ? gpu_sha256_dict_worker : gpu_dict_worker, NULL);
                }
                int limit = nthreads < (int)g_nwords ? nthreads : (int)g_nwords;
                for (int t = 0; t < limit; t++) {
                    DictArg *a = malloc(sizeof(DictArg));
                    a->id = t;
                    a->use_shared = g_use_gpu;
                    pthread_create(&threads[spawned++], NULL, dict_worker, a);
                }
                for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
            }
        }

        /* ── Phase: Rule-based mutations ───────────────────────── */
        if (dict_path && !atomic_load(&g_found)) {
            auto_phases++;
            g_auto_phase = auto_phases;
            if (resume_phase <= auto_phases) {
                if (g_rules_file) load_rules_file(g_rules_file);
                else init_rules();
                long rule_total = g_nwords * g_nrules;
                long rule_start = (resume_phase == auto_phases) ? resume_auto_idx : 0;
                fprintf(stderr,
                    "\n══ Phase %d/%d: Rule-based mutations (%ld words x %d rules = %ld candidates%s) ══\n\n",
                    auto_phases, auto_total_phases, g_nwords, g_nrules, rule_total,
                    rule_start > 0 ? ", resuming" : "");
                g_is_brute = 0;
                atomic_store(&g_tested, rule_start);
                atomic_store(&g_total, rule_total);
                atomic_store(&g_next_idx, rule_start);
                g_overall_total = 0;
                g_completed_prior = 0;
                spawned = 0;

                if (g_use_gpu) {
                    void *ga = malloc(1);
                    pthread_create(&threads[spawned++], NULL,
                                g_r6_ctx ? gpu_r6_rule_worker : g_sha256_ctx ? gpu_sha256_rule_worker : gpu_rule_worker, ga);
                }
                for (int t = 0; t < nthreads; t++) {
                    void *a = malloc(1);
                    pthread_create(&threads[spawned++], NULL, rule_worker, a);
                }
                for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
            }
        }

        /* Free wordlist now that dict-based phases are done */
        if (dict_path && g_words) {
            for (long i = 0; i < g_nwords; i++) free(g_words[i]);
            free(g_words);
            g_words = NULL;
            g_nwords = 0;
        }

        /* ── Phase: Frequency-ordered brute-force, lengths 1-6 ── */
        if (!atomic_load(&g_found)) {
            auto_phases++;
            g_auto_phase = auto_phases;
            int freq_max = max_len < 6 ? max_len : 6;

          if (resume_phase <= auto_phases) {
            /* Switch to frequency charset */
            const char *saved_charset = g_charset;
            int saved_cs_len = g_cs_len;
            g_charset = FREQ_CHARSET;
            g_cs_len  = (int)strlen(FREQ_CHARSET);
            g_idx_to_pass = index_to_pass;
            g_is_brute = 1;

            /* Resume: determine start length and index within this phase */
            int freq_start_len = 1;
            long freq_start_idx = 0;
            long freq_resume_completed = 0;
            if (resume_phase == auto_phases && ck.valid) {
                freq_start_len = ck.resume_len > 0 ? ck.resume_len : 1;
                freq_start_idx = resume_auto_idx;
                freq_resume_completed = ck.completed_prior;
            }

            long ov_sum = 0;
            for (int l = 1; l <= freq_max; l++)
                ov_sum += count_for_length(l);

            fprintf(stderr,
                "\n══ Phase %d/%d: Frequency brute-force (len 1..%d, %ld candidates%s) ══\n\n",
                auto_phases, auto_total_phases, freq_max, ov_sum,
                freq_start_idx > 0 ? ", resuming" : "");

            g_overall_total = ov_sum;
            g_completed_prior = freq_resume_completed;

            for (int len = freq_start_len; len <= freq_max && !atomic_load(&g_found); len++) {
                long total = count_for_length(len);
                long idx0 = (len == freq_start_len && freq_start_idx > 0)
                            ? freq_start_idx : 0;
                atomic_store(&g_current_len, len);
                atomic_store(&g_tested, idx0);
                atomic_store(&g_total, total);
                atomic_store(&g_next_idx, idx0);
                spawned = 0;

                if (g_use_gpu) {
                    GPUBruteArg *ga = malloc(sizeof(GPUBruteArg));
                    *ga = (GPUBruteArg){ .length = len, .total = total };
                    pthread_create(&threads[spawned++], NULL,
                            g_r6_ctx ? gpu_r6_brute_worker : g_sha256_ctx ? gpu_sha256_brute_worker : gpu_brute_worker, ga);
                    for (int t = 0; t < nthreads; t++) {
                        BruteArg *a = malloc(sizeof(BruteArg));
                        *a = (BruteArg){ .id = t, .length = len,
                                         .start = 0, .end = total, .use_shared = 1 };
                        pthread_create(&threads[spawned++], NULL, brute_worker, a);
                    }
                } else {
                    void *(*worker_fn)(void *) = brute_worker;
#ifdef __ARM_NEON
                    if (g_use_neon)
                        worker_fn = brute_worker_neon;
#endif
                    for (int t = 0; t < nthreads; t++) {
                        BruteArg *a = malloc(sizeof(BruteArg));
                        *a = (BruteArg){ .id = t, .length = len,
                                         .start = 0, .end = total, .use_shared = 1 };
                        pthread_create(&threads[spawned++], NULL, worker_fn, a);
                    }
                }
                for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
                g_completed_prior += total;
            }

            /* Restore charset */
            g_charset = saved_charset;
            g_cs_len  = saved_cs_len;
          }
        }

        /* ── Phase: Standard brute-force, lengths 7 to max_len ── */
        if (max_len > 6 && !atomic_load(&g_found)) {
            auto_phases++;
            g_auto_phase = auto_phases;

          if (resume_phase <= auto_phases) {
            g_idx_to_pass = index_to_pass;
            g_is_brute = 1;

            /* Resume: determine start length and index within this phase */
            int bf_start_len = 7;
            long bf_start_idx = 0;
            long bf_resume_completed = 0;
            if (resume_phase == auto_phases && ck.valid) {
                bf_start_len = ck.resume_len > 0 ? ck.resume_len : 7;
                bf_start_idx = resume_auto_idx;
                bf_resume_completed = ck.completed_prior;
            }

            long ov_sum = 0;
            for (int l = 7; l <= max_len; l++)
                ov_sum += count_for_length(l);

            fprintf(stderr,
                "\n══ Phase %d/%d: Standard brute-force (len 7..%d, %ld candidates%s) ══\n\n",
                auto_phases, auto_total_phases, max_len, ov_sum,
                bf_start_idx > 0 ? ", resuming" : "");

            g_overall_total = ov_sum;
            g_completed_prior = bf_resume_completed;

            for (int len = bf_start_len; len <= max_len && !atomic_load(&g_found); len++) {
                long total = count_for_length(len);
                long idx0 = (len == bf_start_len && bf_start_idx > 0)
                            ? bf_start_idx : 0;
                atomic_store(&g_current_len, len);
                atomic_store(&g_tested, idx0);
                atomic_store(&g_total, total);
                atomic_store(&g_next_idx, idx0);
                spawned = 0;

                if (g_use_gpu) {
                    GPUBruteArg *ga = malloc(sizeof(GPUBruteArg));
                    *ga = (GPUBruteArg){ .length = len, .total = total };
                    pthread_create(&threads[spawned++], NULL,
                            g_r6_ctx ? gpu_r6_brute_worker : g_sha256_ctx ? gpu_sha256_brute_worker : gpu_brute_worker, ga);
                    for (int t = 0; t < nthreads; t++) {
                        BruteArg *a = malloc(sizeof(BruteArg));
                        *a = (BruteArg){ .id = t, .length = len,
                                         .start = 0, .end = total, .use_shared = 1 };
                        pthread_create(&threads[spawned++], NULL, brute_worker, a);
                    }
                } else {
                    void *(*worker_fn)(void *) = brute_worker;
#ifdef __ARM_NEON
                    if (g_use_neon)
                        worker_fn = brute_worker_neon;
#endif
                    for (int t = 0; t < nthreads; t++) {
                        BruteArg *a = malloc(sizeof(BruteArg));
                        *a = (BruteArg){ .id = t, .length = len,
                                         .start = 0, .end = total, .use_shared = 1 };
                        pthread_create(&threads[spawned++], NULL, worker_fn, a);
                    }
                }
                for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
                g_completed_prior += total;
            }
          }
        }

        goto auto_done;
    }

    /* ── Mask attack ──────────────────────────────────────────── */
    if (g_mask_mode) {
        g_is_brute = 1;
        g_attack_mode = ATTACK_MASK;

        long total = g_mask_keyspace;
        long mask_start = 0;
        if (resume && ck.valid && ck.attack_mode == ATTACK_MASK)
            mask_start = ck.resume_idx;

        fprintf(stderr, "Mode   : mask attack (\"%s\", keyspace %ld)%s\n\n",
                g_mask_str, total, mask_start > 0 ? " [resuming]" : "");

        atomic_store(&g_tested, mask_start);
        atomic_store(&g_total, total);
        atomic_store(&g_next_idx, mask_start);
        spawned = 0;

        if (g_use_gpu) {
            GPUBruteArg *ga = malloc(sizeof(GPUBruteArg));
            *ga = (GPUBruteArg){ .length = g_mask_len, .total = total };
            pthread_create(&threads[spawned++], NULL,
                            g_r6_ctx ? gpu_r6_brute_worker : g_sha256_ctx ? gpu_sha256_brute_worker : gpu_brute_worker, ga);

            for (int t = 0; t < nthreads; t++) {
                BruteArg *a = malloc(sizeof(BruteArg));
                *a = (BruteArg){ .id = t, .length = g_mask_len,
                                 .start = 0, .end = total, .use_shared = 1 };
                pthread_create(&threads[spawned++], NULL, brute_worker, a);
            }
        } else {
            void *(*worker_fn)(void *) = brute_worker;
#ifdef __ARM_NEON
            if (g_use_neon)
                worker_fn = brute_worker_neon;
#endif
            for (int t = 0; t < nthreads; t++) {
                BruteArg *a = malloc(sizeof(BruteArg));
                *a = (BruteArg){ .id = t, .length = g_mask_len,
                                 .start = 0, .end = total, .use_shared = 1 };
                pthread_create(&threads[spawned++], NULL, worker_fn, a);
            }
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
    }

    /* ── Rule-based mutation attack ──────────────────────────── */
    else if (g_rule_mode && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_RULE;
        if (!load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }
        if (g_rules_file) load_rules_file(g_rules_file);
        else init_rules();
        long total = g_nwords * g_nrules;
        long rule_start = 0;
        if (resume && ck.valid && ck.attack_mode == ATTACK_RULE)
            rule_start = ck.dict_idx;
        fprintf(stderr, "Mode   : rule-based (%ld words x %d rules = %ld candidates)%s\n\n",
                g_nwords, g_nrules, total,
                rule_start > 0 ? " [resuming]" : "");
        atomic_store(&g_tested, rule_start);
        atomic_store(&g_total, total);
        atomic_store(&g_next_idx, rule_start);
        spawned = 0;

        if (g_use_gpu) {
            void *ga = malloc(1); /* dummy arg */
            pthread_create(&threads[spawned++], NULL,
                            g_r6_ctx ? gpu_r6_rule_worker : g_sha256_ctx ? gpu_sha256_rule_worker : gpu_rule_worker, ga);
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1); /* dummy arg */
            pthread_create(&threads[spawned++], NULL, rule_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
    }

    /* ── Hybrid attack (dict + brute-force suffix) ───────────── */
    else if (g_hybrid_mode && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_HYBRID;
        if (!load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }
        if (!g_hybrid_mask_mode)
            g_hybrid_suffix_keyspace = hybrid_total_suffix_keyspace(g_hybrid_suffix_len, g_cs_len);
        /* mask mode: g_hybrid_suffix_keyspace already set by parse_mask_into */
        long total = g_nwords * g_hybrid_suffix_keyspace;
        long hybrid_start = 0;
        if (resume && ck.valid && ck.attack_mode == ATTACK_HYBRID)
            hybrid_start = ck.dict_idx;
        fprintf(stderr, "Mode   : hybrid (%ld words x %ld suffixes = %ld candidates)%s\n\n",
                g_nwords, g_hybrid_suffix_keyspace, total,
                hybrid_start > 0 ? " [resuming]" : "");
        atomic_store(&g_tested, hybrid_start);
        atomic_store(&g_total, total);
        atomic_store(&g_next_idx, hybrid_start);
        spawned = 0;

        if (g_use_gpu) {
            void *ga = malloc(1);
            pthread_create(&threads[spawned++], NULL,
                            g_r6_ctx ? gpu_r6_hybrid_worker : g_sha256_ctx ? gpu_sha256_hybrid_worker : gpu_hybrid_worker, ga);
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, hybrid_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
    }

    /* ── Dictionary attack ─────────────────────────────────────── */
    else if (dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_DICT;
        if (!load_wordlist(dict_path)) {
            atomic_store(&g_found, 1); /* stop progress thread */
            pthread_join(prog, NULL);
            return 1;
        }
        long dict_start = (resume && ck.valid &&
                          (ck.attack_mode == ATTACK_DICT || !ck.is_brute))
                          ? ck.dict_idx : 0;
        fprintf(stderr, "Mode   : dictionary (%ld words%s)\n\n", g_nwords,
                dict_start > 0 ? ", resuming" : "");
        atomic_store(&g_total, g_nwords);
        atomic_store(&g_next_idx, dict_start);

        /* Spawn GPU worker if available */
        if (g_use_gpu) {
            pthread_create(&threads[spawned++], NULL,
                            g_r6_ctx ? gpu_r6_dict_worker : g_sha256_ctx ? gpu_sha256_dict_worker : gpu_dict_worker, NULL);
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
        g_is_brute = 1;
        g_attack_mode = ATTACK_BRUTE;

        /* Resume: determine start length and index */
        int  start_len = min_len > 0 ? min_len : 1;
        long start_idx = 0;
        long resume_completed = 0;
        if (resume && ck.valid &&
            (ck.attack_mode == ATTACK_BRUTE || ck.is_brute)) {
            start_len = ck.resume_len;
            start_idx = ck.resume_idx;
            resume_completed = ck.completed_prior;
        }

        /* Precompute overall total across all lengths */
        long ov_sum = 0;
        for (int l = (min_len > 0 ? min_len : 1); l <= max_len; l++)
            ov_sum += count_for_length(l);
        g_overall_total = ov_sum;
        g_completed_prior = resume_completed;

        if (g_prefix_len || g_suffix_len) {
            fprintf(stderr, "Mode   : brute-force (\"%s\" + %d..%d chars + \"%s\", charset \"%s\")%s\n\n",
                    g_prefix, start_len, max_len, g_suffix, charset,
                    start_idx > 0 ? " [resuming]" : "");
        } else {
            fprintf(stderr, "Mode   : brute-force (len %d..%d, charset \"%s\")%s\n\n",
                    start_len, max_len, charset,
                    start_idx > 0 ? " [resuming]" : "");
        }

        for (int len = start_len; len <= max_len && !atomic_load(&g_found); len++) {
            long total = count_for_length(len);
            atomic_store(&g_current_len, len);

            /* If resuming into this length, start from saved index */
            long idx0 = (len == start_len && start_idx > 0) ? start_idx : 0;

            atomic_store(&g_tested, idx0);
            atomic_store(&g_total, total);
            atomic_store(&g_next_idx, idx0);
            spawned = 0;

            if (g_use_gpu) {
                /* Shared work counter mode: GPU + CPU all pull from g_next_idx */
                GPUBruteArg *ga = malloc(sizeof(GPUBruteArg));
                *ga = (GPUBruteArg){ .length = len, .total = total };
                pthread_create(&threads[spawned++], NULL,
                            g_r6_ctx ? gpu_r6_brute_worker : g_sha256_ctx ? gpu_sha256_brute_worker : gpu_brute_worker, ga);

                for (int t = 0; t < nthreads; t++) {
                    BruteArg *a = malloc(sizeof(BruteArg));
                    *a = (BruteArg){ .id = t, .length = len,
                                     .start = 0, .end = total, .use_shared = 1 };
                    pthread_create(&threads[spawned++], NULL, brute_worker, a);
                }
            } else {
                /* Shared work counter mode (CPU-only, incl. NEON) */
                void *(*worker_fn)(void *) = brute_worker;
#ifdef __ARM_NEON
                if (g_use_neon)
                    worker_fn = brute_worker_neon;
#endif

                for (int t = 0; t < nthreads; t++) {
                    BruteArg *a = malloc(sizeof(BruteArg));
                    *a = (BruteArg){ .id = t, .length = len,
                                     .start = 0, .end = total, .use_shared = 1 };
                    pthread_create(&threads[spawned++], NULL, worker_fn, a);
                }
            }
            for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
            g_completed_prior += total;
        }
    }

auto_done:
    /* ── Stop progress thread and print result ─────────────────── */
    atomic_store(&g_found, 1); /* ensure progress thread exits */
    pthread_join(prog, NULL);
    fputs("\n\n", stderr);

    if (g_gpu_ctx) metal_keygen_free(g_gpu_ctx);
    if (g_sha256_ctx) metal_sha256_free(g_sha256_ctx);

    /* If interrupted during work, save checkpoint and exit */
    if (g_interrupted) {
        ckpt_save();
        fprintf(stderr, "Checkpoint saved to %s (use -r to resume)\n", g_ckpt_path);
        return 1;
    }

    if (g_password[0]) {
        if (g_found_type)
            printf("%s password found: %s\n", g_found_type, g_password);
        else
            printf("Password found: %s\n", g_password);
        ckpt_delete();  /* success — remove checkpoint */
        return 0;
    }

    /* Save final checkpoint before exiting (exhausted or interrupted) */
    ckpt_save();
    fprintf(stderr, "Checkpoint saved to %s (use -r to resume)\n", g_ckpt_path);

    printf("Password not found.\n");
    return 1;
}
