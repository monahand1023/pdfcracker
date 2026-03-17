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
 *   pdfcrack -f file.pdf -d words.txt --prince        # PRINCE word combos
 *   pdfcrack -f file.pdf --fingerprint                # smart pattern attack
 *   pdfcrack -f file.pdf -d words.txt -R --dedup      # rules with dedup
 */

#include <CoreGraphics/CoreGraphics.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <sys/qos.h>
#include <signal.h>
#include <mach/mach_time.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <dirent.h>
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

/* ── PRINCE attack mode ─────────────────────────────────────── */
#define ATTACK_PRINCE  6
static int  g_prince_mode = 0;
static int  g_prince_words = 0;  /* mask+prince combo: ?w expands to word pairs */

/* ── Fingerprint (smart) attack mode ────────────────────────── */
#define ATTACK_FINGERPRINT 7
static int  g_fingerprint_mode = 0;

/* ── Max rounds for R6 GPU ──────────────────────────────────── */
static int  g_max_rounds = 200;

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

/* -- Pot file -------------------------------------------------- */
static char g_pot_path[1024] = {0};
static const char *g_custom_pot_path = NULL;
static int  g_show_pot = 0;
static int  g_no_pot = 0;

/* -- Progress file for external monitoring --------------------- */
static const char *g_progress_file = NULL;

/* -- JSON output ----------------------------------------------- */
static int  g_json_mode = 0;
static double g_start_time = 0;

/* -- Session management ---------------------------------------- */
static char g_session_name[256] = {0};
static int  g_session_list = 0;

/* -- GPU batch size tuning ------------------------------------- */
static int  g_gpu_batch = GPU_BATCH_SIZE;

/* -- Incremental (probability) mode ---------------------------- */
#define INCR_RING_SIZE  8192
#define INCR_HEAP_CAP   (1 << 20)
typedef struct {
    int  indices[MAX_PASS_LEN];
    int  length;
    double log_prob;
} IncrEntry;
typedef struct {
    IncrEntry *entries;
    int size;
    int capacity;
} IncrHeap;
static char   g_incr_ring[INCR_RING_SIZE][MAX_PASS_LEN + 1];
static int    g_incr_head = 0;
static int    g_incr_tail = 0;
static int    g_incr_done = 0;
static pthread_mutex_t g_incr_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_incr_not_full  = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  g_incr_not_empty = PTHREAD_COND_INITIALIZER;
static int    g_incremental_mode = 0;

/* -- Toggle-case walk mode ------------------------------------ */
static int    g_toggle_mode = 0;

/* -- Combinator attack ---------------------------------------- */
#define ATTACK_COMBINATOR 8
static char  **g_words2 = NULL;
static long    g_nwords2 = 0;
static const char *g_dict2_path = NULL;

/* -- Mask+rules hybrid attack --------------------------------- */
#define ATTACK_MASK_RULE 9

/* -- Incremental resume (attack mode) ------------------------- */
#define ATTACK_INCREMENTAL 10

/* -- Date-based attack ---------------------------------------- */
#define ATTACK_DATES 11
static int  g_dates_mode = 0;
static int  g_date_year_start = 1940;
static int  g_date_year_end   = 2026;

/* -- Smart mutations attack ----------------------------------- */
#define ATTACK_MUTATE 12
static int  g_mutate_mode = 0;

/* -- L33tspeak substitutions attack --------------------------- */
#define ATTACK_LEET 13
static int  g_leet_mode = 0;
static int  g_metadata_seeds = 0;

/* -- Smart attack (intelligent multi-phase) ------------------- */
#define ATTACK_SMART 14
static int  g_smart_mode = 0;

/* -- Reverse flag for dict mode ------------------------------- */
static int  g_reverse_mode = 0;

/* -- Pattern attack (common name patterns) -------------------- */
#define ATTACK_PATTERN 15
static int  g_pattern_mode = 0;

/* -- Global incremental heap (for resume) --------------------- */
static IncrHeap *g_incr_heap = NULL;

/* Forward declarations for incremental save/load (defined later) */
static void incr_heap_save(const char *path);
static int incr_heap_load(const char *path);
static int extract_metadata_seeds(const char *pdf_path, char ***words_out);
static int extract_filename_seeds(const char *pdf_path, char ***words_out);
static int run_smart_attack(int nthreads, pthread_t *threads, int *spawned_out);
static int run_pattern_attack(int nthreads, pthread_t *threads, int *spawned_out);

/* ── Safe integer parsing with range checking ────────────────── */
static int safe_atoi(const char *s, int min_val, int max_val, const char *name)
{
    char *end;
    errno = 0;
    long val = strtol(s, &end, 10);
    if (errno == ERANGE || val < min_val || val > max_val || end == s || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: '%s' (must be %d..%d)\n", name, s, min_val, max_val);
        exit(1);
    }
    return (int)val;
}

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
        memcpy(g_ckpt_path + base, ".ckpt", 6);
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
        "brute", "dict", "mask", "rule", "hybrid", "auto", "prince", "fingerprint",
        "combinator", "mask_rule", "incremental", "dates", "mutate", "leet",
        "smart", "pattern"
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

    /* Session and PDF path info */
    if (g_session_name[0])
        fprintf(f, "session_name=%s\n", g_session_name);
    if (g_pdf_path)
        fprintf(f, "pdf_path=%s\n", g_pdf_path);

    fflush(f);
    fsync(fileno(f));
    fclose(f);
    if (rename(tmp, g_ckpt_path) != 0) perror("checkpoint rename");

    /* Also save incremental heap if in incremental mode */
    if (g_attack_mode == ATTACK_INCREMENTAL && g_incr_heap && g_ckpt_path[0]) {
        char incr_path[1040];
        snprintf(incr_path, sizeof(incr_path), "%s.incr", g_ckpt_path);
        incr_heap_save(incr_path);
    }
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
        } else if (strncmp(line, "attack_mode=prince", 18) == 0) {
            ck.attack_mode = ATTACK_PRINCE; ck.is_brute = 0;
        } else if (strncmp(line, "attack_mode=fingerprint", 23) == 0) {
            ck.attack_mode = ATTACK_FINGERPRINT; ck.is_brute = 1;
        } else if (strncmp(line, "attack_mode=dates", 17) == 0) {
            ck.attack_mode = ATTACK_DATES; ck.is_brute = 1;
        } else if (strncmp(line, "attack_mode=mutate", 18) == 0) {
            ck.attack_mode = ATTACK_MUTATE; ck.is_brute = 0;
        } else if (strncmp(line, "attack_mode=leet", 16) == 0) {
            ck.attack_mode = ATTACK_LEET; ck.is_brute = 0;
        } else if (strncmp(line, "attack_mode=auto", 16) == 0) {
            ck.attack_mode = ATTACK_AUTO;
        } else if (strncmp(line, "attack_mode=smart", 17) == 0) {
            ck.attack_mode = ATTACK_SMART; ck.is_brute = 1;
        } else if (strncmp(line, "attack_mode=pattern", 19) == 0) {
            ck.attack_mode = ATTACK_PATTERN; ck.is_brute = 0;
        } else if (strncmp(line, "charset=", 8) == 0) {
            strncpy(ck.charset, line + 8, sizeof(ck.charset) - 1);
        } else if (strncmp(line, "current_len=", 12) == 0) {
            ck.resume_len = safe_atoi(line + 12, 0, 127, "current_len");
        } else if (strncmp(line, "current_idx=", 12) == 0) {
            ck.resume_idx = atol(line + 12);
            ck.dict_idx = ck.resume_idx;
        } else if (strncmp(line, "completed_prior=", 16) == 0) {
            ck.completed_prior = atol(line + 16);
        } else if (strncmp(line, "prefix=", 7) == 0) {
            strncpy(ck.prefix, line + 7, MAX_PASS_LEN);
            ck.prefix[MAX_PASS_LEN] = '\0';
        } else if (strncmp(line, "suffix=", 7) == 0) {
            strncpy(ck.suffix, line + 7, MAX_PASS_LEN);
            ck.suffix[MAX_PASS_LEN] = '\0';
        } else if (strncmp(line, "mask_pattern=", 13) == 0) {
            strncpy(ck.mask_pattern, line + 13, sizeof(ck.mask_pattern) - 1);
        } else if (strncmp(line, "hybrid_suffix_len=", 18) == 0) {
            ck.hybrid_suffix_len = safe_atoi(line + 18, 0, 32, "hybrid_suffix_len");
        } else if (strncmp(line, "hybrid_mask=", 12) == 0) {
            strncpy(ck.hybrid_mask, line + 12, sizeof(ck.hybrid_mask) - 1);
        } else if (strncmp(line, "auto_phase=", 11) == 0) {
            ck.auto_phase = safe_atoi(line + 11, 0, 20, "auto_phase");
        } else if (strncmp(line, "freq_mode=", 10) == 0) {
            ck.freq_mode = safe_atoi(line + 10, 0, 1, "freq_mode");
        } else if (strncmp(line, "password_mode=", 14) == 0) {
            ck.password_mode = safe_atoi(line + 14, 0, 2, "password_mode");
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

static void write_progress_file(long cur, long total, long rate, long elapsed)
{
    if (!g_progress_file) return;
    char tmp[1040];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_progress_file);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    double pct = (total > 0) ? (double)cur / (double)total * 100.0 : 0.0;
    if (pct > 100.0) pct = 100.0;
    long eta = (rate > 0 && total > cur) ? (total - cur) / rate : -1;
    int cur_len = atomic_load(&g_current_len);
    fprintf(f, "{\"speed\":%ld,\"tested\":%ld,\"total\":%ld,"
               "\"progress_pct\":%.2f,\"elapsed_sec\":%ld,"
               "\"eta_sec\":%ld,\"current_length\":%d,"
               "\"timestamp\":%ld}\n",
            rate, cur, total, pct, elapsed, eta, cur_len, (long)time(NULL));
    fclose(f);
    rename(tmp, g_progress_file);
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

        /* JSON mode: still run for checkpointing but suppress display */
        if (g_json_mode) {
            time_t now = time(NULL);
            if (now - last_ckpt >= CKPT_INTERVAL) {
                ckpt_save();
                last_ckpt = now;
            }
            if (g_progress_file && (avg_i <= 1 || (avg_i % 4) == 0)) {
                long cur_j = atomic_load(&g_tested);
                long total_j = atomic_load(&g_total);
                long rate_j = (cur_j - prev) * 2;
                prev = cur_j;
                long elapsed_j = (long)(now - t0);
                avg_i++;
                write_progress_file(cur_j, total_j, rate_j, elapsed_j);
            } else {
                avg_i++;
            }
            if (g_interrupted) {
                ckpt_save();
                _exit(1);
            }
            continue;
        }

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

        /* Write progress file every 4th iteration (~2s), plus first iteration */
        if (g_progress_file && (avg_i <= 1 || (avg_i % 4) == 0))
            write_progress_file(cur, total, rate, elapsed);

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
 * Reverse string helper (for --reverse mode)
 * ================================================================ */
static void reverse_string(const char *src, char *dst, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = src[len - 1 - i];
    dst[len] = '\0';
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
                if (!hit && g_reverse_mode) {
                    char rev[MAX_PASS_LEN + 1];
                    size_t wlen = strlen(g_words[i]);
                    if (wlen > 0 && wlen <= MAX_PASS_LEN) {
                        reverse_string(g_words[i], rev, wlen);
                        if (strcmp(rev, g_words[i]) != 0) {
                            hit = g_fast_crypto ? test_password_fast(rev)
                                                : test_password_cg(doc, rev);
                            if (hit) {
                                if (!atomic_exchange(&g_found, 1))
                                    strncpy(g_password, rev, MAX_PASS_LEN);
                            }
                        }
                    }
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
            if (!hit && g_reverse_mode) {
                char rev[MAX_PASS_LEN + 1];
                size_t wlen = strlen(g_words[i]);
                if (wlen > 0 && wlen <= MAX_PASS_LEN) {
                    reverse_string(g_words[i], rev, wlen);
                    if (strcmp(rev, g_words[i]) != 0) {
                        hit = g_fast_crypto ? test_password_fast(rev)
                                            : test_password_cg(doc, rev);
                        if (hit) {
                            if (!atomic_exchange(&g_found, 1))
                                strncpy(g_password, rev, MAX_PASS_LEN);
                        }
                    }
                }
            }
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_tested, local_count);

    if (doc) CGPDFDocumentRelease(doc);
    free(arg);
    return NULL;
}

#ifdef __ARM_NEON
/* ================================================================
 * NEON dictionary attack — process 4 words at a time
 * ================================================================ */
static void *dict_worker_neon(void *arg)
{
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    (void)arg;
    long local_count = 0;

    /* Shared work counter mode — process 4 words per iteration */
    for (;;) {
        if (__builtin_expect(atomic_load_explicit(&g_found,
                             memory_order_relaxed), 0))
            break;
        long chunk_start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (chunk_start >= g_nwords) break;
        long chunk_end = chunk_start + CPU_WORK_CHUNK;
        if (chunk_end > g_nwords) chunk_end = g_nwords;

        long i = chunk_start;
        /* Process groups of 4 with NEON SIMD */
        for (; i + 3 < chunk_end; i += 4) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;

            const char *pw[4] = { g_words[i], g_words[i+1],
                                  g_words[i+2], g_words[i+3] };
            int pwlen[4] = {
                (int)strlen(pw[0]), (int)strlen(pw[1]),
                (int)strlen(pw[2]), (int)strlen(pw[3])
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
                            strncpy(g_password, pw[b], MAX_PASS_LEN);
                    }
                }
            }
            /* Reverse mode: try reversed versions of non-hit words */
            if (!hits && g_reverse_mode) {
                for (int b = 0; b < 4; b++) {
                    char rev[MAX_PASS_LEN + 1];
                    size_t wlen = (size_t)pwlen[b];
                    if (wlen > 0 && wlen <= MAX_PASS_LEN) {
                        reverse_string(pw[b], rev, wlen);
                        if (strcmp(rev, pw[b]) != 0 && test_password_fast(rev)) {
                            if (!atomic_exchange(&g_found, 1))
                                strncpy(g_password, rev, MAX_PASS_LEN);
                        }
                    }
                }
            }
        }
        /* Handle remaining 1-3 words with scalar path */
        for (; i < chunk_end; i++) {
            if (__builtin_expect(atomic_load_explicit(&g_found,
                                 memory_order_relaxed), 0))
                break;
            local_count++;
            if (local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count,
                                          memory_order_relaxed);
                local_count = 0;
            }
            if (test_password_fast(g_words[i])) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, g_words[i], MAX_PASS_LEN);
            } else if (g_reverse_mode) {
                char rev[MAX_PASS_LEN + 1];
                size_t wlen = strlen(g_words[i]);
                if (wlen > 0 && wlen <= MAX_PASS_LEN) {
                    reverse_string(g_words[i], rev, wlen);
                    if (strcmp(rev, g_words[i]) != 0 && test_password_fast(rev)) {
                        if (!atomic_exchange(&g_found, 1))
                            strncpy(g_password, rev, MAX_PASS_LEN);
                    }
                }
            }
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_tested, local_count);

    free(arg);
    return NULL;
}
#endif

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
                    if (g_prince_words)
                        mp->nchars = (int)(g_nwords * g_nwords);
                    else
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
            if (g_prince_words && g_nwords > 0) {
                /* PRINCE 2-word combo: word1 = words[idx/nwords], word2 = words[idx%nwords] */
                long pidx = (long)indices[i];
                long w1i = pidx / g_nwords;
                long w2i = pidx % g_nwords;
                const char *w1 = g_words[w1i];
                const char *w2 = g_words[w2i];
                size_t l1 = strlen(w1), l2 = strlen(w2);
                if (pos + (int)(l1 + l2) > MAX_PASS_LEN) {
                    l2 = (size_t)(MAX_PASS_LEN - pos) > l1 ? (size_t)(MAX_PASS_LEN - pos) - l1 : 0;
                    if ((int)l1 > MAX_PASS_LEN - pos) l1 = (size_t)(MAX_PASS_LEN - pos);
                }
                memcpy(out + pos, w1, l1);
                memcpy(out + pos + l1, w2, l2);
                pos += (int)(l1 + l2);
            } else {
                const char *word = g_words[indices[i]];
                size_t wlen = strlen(word);
                if (pos + (int)wlen > MAX_PASS_LEN) wlen = (size_t)(MAX_PASS_LEN - pos);
                memcpy(out + pos, word, wlen);
                pos += (int)wlen;
            }
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
    int line_num = 0, skipped = 0;
    while (fgets(line, sizeof(line), f) && g_nrules < MAX_RULES) {
        line_num++;
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
            if (consumed <= 0) {
                fprintf(stderr, "  Warning: %s:%d: unknown op '%c' in \"%s\" (skipped)\n",
                        path, line_num, *p, line);
                ok = 0;
                skipped++;
                break;
            }
            p += consumed;
        }
        if (ok && r->nops > 0) g_nrules++;
    }
    fclose(f);
    fprintf(stderr, "Loaded %d rules from %s", g_nrules, path);
    if (skipped) fprintf(stderr, " (%d lines skipped)", skipped);
    fputc('\n', stderr);
    if (g_nrules == 0) {
        fprintf(stderr, "Error: no valid rules found in %s\n", path);
        return 0;
    }
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

/* Deduplicate rule-generated candidates using a bloom filter.
 * Returns 1 if the password was already seen (skip), 0 if new. */
static uint64_t g_rule_bloom[65536]; /* 512KB bloom filter */
static int      g_rule_dedup = 0;

static inline int rule_dedup_check(const char *pw)
{
    if (!g_rule_dedup) return 0;
    /* FNV-1a hash */
    uint64_t h1 = 14695981039346656037ULL;
    for (const char *p = pw; *p; p++) {
        h1 ^= (uint8_t)*p;
        h1 *= 1099511628211ULL;
    }
    /* Second hash: rotate + xor */
    uint64_t h2 = h1 ^ (h1 >> 33);
    h2 *= 0xff51afd7ed558ccdULL;

    unsigned idx1 = (unsigned)(h1 >> 48) & 0xFFFF;
    unsigned bit1 = (unsigned)(h1 >> 6) & 63;
    unsigned idx2 = (unsigned)(h2 >> 48) & 0xFFFF;
    unsigned bit2 = (unsigned)(h2 >> 6) & 63;

    uint64_t mask1 = 1ULL << bit1;
    uint64_t mask2 = 1ULL << bit2;

    if ((g_rule_bloom[idx1] & mask1) && (g_rule_bloom[idx2] & mask2))
        return 1; /* probably seen */

    g_rule_bloom[idx1] |= mask1;
    g_rule_bloom[idx2] |= mask2;
    return 0;
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
 * Pot file helpers — cache cracked passwords
 * ================================================================ */
static void pot_init(void)
{
    if (g_custom_pot_path) {
        snprintf(g_pot_path, sizeof(g_pot_path), "%s", g_custom_pot_path);
        return;
    }
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/.pdfcracker", home);
    if (mkdir(dir, 0700) == -1 && errno != EEXIST) { perror(dir); return; }
    snprintf(g_pot_path, sizeof(g_pot_path), "%s/pdfcracker.pot", dir);
}

/* Compute SHA-256 hash of PDF encryption parameters for pot file key */
static void pot_compute_hash(const PDFEncryptParams *p, char *hex_out)
{
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, &p->revision, sizeof(p->revision));
    CC_SHA256_Update(&ctx, &p->key_length, sizeof(p->key_length));
    CC_SHA256_Update(&ctx, p->o_value, 48);
    CC_SHA256_Update(&ctx, p->u_value, 48);
    CC_SHA256_Update(&ctx, &p->permissions, sizeof(p->permissions));
    CC_SHA256_Update(&ctx, p->file_id, (CC_LONG)p->file_id_len);
    uint8_t hash[32];
    CC_SHA256_Final(hash, &ctx);
    for (int i = 0; i < 32; i++)
        snprintf(hex_out + i * 2, 3, "%02x", hash[i]);
    hex_out[64] = '\0';
}

/* Check if hash is already in pot file; if so, copy password to pw_out and return 1 */
static int pot_lookup(const char *hash, char *pw_out, size_t pw_sz)
{
    FILE *f = fopen(g_pot_path, "r");
    if (!f) return 0;
    char line[1200];
    size_t hlen = strlen(hash);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, hash, hlen) == 0 && line[hlen] == ':') {
            const char *pw = line + hlen + 1;
            size_t plen = strlen(pw);
            while (plen && (pw[plen-1] == '\n' || pw[plen-1] == '\r'))
                plen--;
            if (plen >= pw_sz) plen = pw_sz - 1;
            memcpy(pw_out, pw, plen);
            pw_out[plen] = '\0';
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* Append hash:password to pot file */
static void pot_append(const char *hash, const char *password)
{
    FILE *f = fopen(g_pot_path, "a");
    if (!f) return;
    fprintf(f, "%s:%s\n", hash, password);
    fclose(f);
}

/* Show all pot file entries */
static void pot_show(void)
{
    FILE *f = fopen(g_pot_path, "r");
    if (!f) {
        fprintf(stderr, "No pot file found at %s\n", g_pot_path);
        return;
    }
    char line[1200];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            printf("Hash: %s  Password: %s\n", line, colon + 1);
            count++;
        }
    }
    fclose(f);
    if (count == 0)
        printf("Pot file is empty.\n");
    else
        printf("\n%d cracked password(s) in pot file.\n", count);
}

/* ================================================================
 * JSON output helpers
 * ================================================================ */
static void json_escape(const char *in, char *out, size_t out_sz)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 6 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') { out[j++] = '\\'; out[j++] = '"'; }
        else if (c == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c < 0x20) {
            j += (size_t)snprintf(out + j, out_sz - j, "\\u%04x", c);
        }
        else out[j++] = (char)c;
    }
    out[j] = '\0';
}

/* ================================================================
 * Session management helpers
 * ================================================================ */
static void session_init_dir(void)
{
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/.pdfcracker", home);
    mkdir(dir, 0755);
    snprintf(dir, sizeof(dir), "%s/.pdfcracker/sessions", home);
    mkdir(dir, 0755);
}

static void session_set_ckpt_path(const char *name)
{
    session_init_dir();
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(g_ckpt_path, sizeof(g_ckpt_path),
             "%s/.pdfcracker/sessions/%s.ckpt", home, name);
}

static void session_list(void)
{
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/.pdfcracker/sessions", home);
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "No sessions directory found at %s\n", dir);
        return;
    }
    struct dirent *ent;
    int count = 0;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 6 || strcmp(ent->d_name + nlen - 5, ".ckpt") != 0)
            continue;
        char path[1280];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        /* Extract session name (filename without .ckpt) */
        char sname[256];
        size_t copy_len = nlen - 5;
        if (copy_len >= sizeof(sname)) copy_len = sizeof(sname) - 1;
        memcpy(sname, ent->d_name, copy_len);
        sname[copy_len] = '\0';

        char pdf_p[512] = "unknown";
        char mode[64] = "unknown";
        long idx = 0;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = '\0';
            if (strncmp(line, "pdf_path=", 9) == 0)
                strncpy(pdf_p, line + 9, sizeof(pdf_p) - 1);
            else if (strncmp(line, "attack_mode=", 12) == 0)
                strncpy(mode, line + 12, sizeof(mode) - 1);
            else if (strncmp(line, "current_idx=", 12) == 0)
                idx = atol(line + 12);
        }
        fclose(f);
        printf("  %-20s  mode=%-12s  idx=%-10ld  pdf=%s\n", sname, mode, idx, pdf_p);
        count++;
    }
    closedir(d);
    if (count == 0)
        printf("No saved sessions.\n");
    else
        printf("\n%d session(s) found.\n", count);
}

/* ================================================================
 * Keyboard walk generator for fingerprint attack
 * ================================================================ */
static const char kb_grid[4][14] = {
    "`1234567890-=\0",
    "qwertyuiop[]\\\0",
    "asdfghjkl;'\0\0\0",
    "zxcvbnm,./\0\0\0\0"
};

typedef struct {
    int row, col;
} KBPos;

static KBPos kb_pos_map[128];  /* char -> (row,col), row=-1 if not on grid */
static int   kb_adj[128][9];   /* adjacency: char -> up to 8 neighbor chars, -1 terminated */
static int   kb_map_ready = 0;

static void kb_build_map(void)
{
    if (kb_map_ready) return;
    for (int i = 0; i < 128; i++) kb_pos_map[i].row = -1;
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 13; c++) {
            unsigned char ch = (unsigned char)kb_grid[r][c];
            if (ch) {
                kb_pos_map[ch].row = r;
                kb_pos_map[ch].col = c;
            }
        }
    }
    /* Build adjacency */
    for (int ch = 0; ch < 128; ch++) {
        int ai = 0;
        if (kb_pos_map[ch].row < 0) {
            kb_adj[ch][0] = -1;
            continue;
        }
        int r = kb_pos_map[ch].row, cc = kb_pos_map[ch].col;
        for (int dr = -1; dr <= 1; dr++) {
            for (int dc = -1; dc <= 1; dc++) {
                if (dr == 0 && dc == 0) continue;
                int nr = r + dr, nc = cc + dc;
                if (nr < 0 || nr >= 4 || nc < 0 || nc >= 13) continue;
                unsigned char nch = (unsigned char)kb_grid[nr][nc];
                if (nch)
                    kb_adj[ch][ai++] = (int)nch;
            }
        }
        kb_adj[ch][ai] = -1;
    }
    kb_map_ready = 1;
}

/* DFS keyboard walk generator */
static int keywalk_dfs(char *path, int depth, int max_depth,
                       char walks[][MAX_PASS_LEN + 1], int max_walks, int walk_count)
{
    if (depth >= 4 && depth <= max_depth) {
        if (walk_count < max_walks) {
            memcpy(walks[walk_count], path, (size_t)depth);
            walks[walk_count][depth] = '\0';
            walk_count++;
        }
    }
    if (depth >= max_depth || walk_count >= max_walks)
        return walk_count;

    int last = (unsigned char)path[depth - 1];
    if (last >= 128) return walk_count;
    for (int i = 0; kb_adj[last][i] >= 0; i++) {
        int next = kb_adj[last][i];
        path[depth] = (char)next;
        walk_count = keywalk_dfs(path, depth + 1, max_depth, walks, max_walks, walk_count);
        if (walk_count >= max_walks) break;
    }
    return walk_count;
}

static int keywalk_generate(char walks[][MAX_PASS_LEN + 1], int max_walks)
{
    kb_build_map();
    int count = 0;
    char path[MAX_PASS_LEN + 1];
    for (int ch = 0; ch < 128 && count < max_walks; ch++) {
        if (kb_pos_map[ch].row < 0) continue;
        path[0] = (char)ch;
        count = keywalk_dfs(path, 1, 8, walks, max_walks, count);
    }
    return count;
}

/* ================================================================
 * Incremental mode: min-heap operations
 * ================================================================ */
static void heap_init(IncrHeap *h, int capacity)
{
    h->entries = malloc(sizeof(IncrEntry) * (size_t)capacity);
    h->size = 0;
    h->capacity = capacity;
}

static void heap_push(IncrHeap *h, const IncrEntry *e)
{
    if (h->size >= h->capacity) return;
    h->entries[h->size] = *e;
    int i = h->size;
    h->size++;
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (h->entries[parent].log_prob <= h->entries[i].log_prob) break;
        IncrEntry tmp = h->entries[parent];
        h->entries[parent] = h->entries[i];
        h->entries[i] = tmp;
        i = parent;
    }
}

static IncrEntry heap_pop(IncrHeap *h)
{
    IncrEntry top = h->entries[0];
    h->size--;
    if (h->size > 0) {
        h->entries[0] = h->entries[h->size];
        int i = 0;
        for (;;) {
            int left = 2 * i + 1, right = 2 * i + 2, smallest = i;
            if (left < h->size && h->entries[left].log_prob < h->entries[smallest].log_prob)
                smallest = left;
            if (right < h->size && h->entries[right].log_prob < h->entries[smallest].log_prob)
                smallest = right;
            if (smallest == i) break;
            IncrEntry tmp = h->entries[i];
            h->entries[i] = h->entries[smallest];
            h->entries[smallest] = tmp;
            i = smallest;
        }
    }
    return top;
}

static void heap_free(IncrHeap *h)
{
    free(h->entries);
    h->entries = NULL;
    h->size = 0;
}

/* Save incremental heap state to binary file */
#define INCR_MAGIC 0x494E4352
#define INCR_VERSION 1
static void incr_heap_save(const char *path)
{
    if (!g_incr_heap || !path) return;
    char tmp[1040];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return;

    uint32_t magic = INCR_MAGIC;
    uint32_t version = INCR_VERSION;
    fwrite(&magic, 4, 1, f);
    fwrite(&version, 4, 1, f);

    /* Heap state */
    pthread_mutex_lock(&g_incr_mutex);
    int heap_size = g_incr_heap->size;
    fwrite(&heap_size, sizeof(int), 1, f);
    fwrite(g_incr_heap->entries, sizeof(IncrEntry), (size_t)heap_size, f);

    /* Ring buffer state */
    fwrite(&g_incr_head, sizeof(int), 1, f);
    fwrite(&g_incr_tail, sizeof(int), 1, f);

    /* Tested count */
    long tested = atomic_load(&g_tested);
    fwrite(&tested, sizeof(long), 1, f);
    pthread_mutex_unlock(&g_incr_mutex);

    fclose(f);
    rename(tmp, path);
}

static int incr_heap_load(const char *path)
{
    if (!path) return 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    uint32_t magic, version;
    if (fread(&magic, 4, 1, f) != 1 || magic != INCR_MAGIC) { fclose(f); return 0; }
    if (fread(&version, 4, 1, f) != 1 || version != INCR_VERSION) { fclose(f); return 0; }

    int heap_size;
    if (fread(&heap_size, sizeof(int), 1, f) != 1 || heap_size < 0 || heap_size > INCR_HEAP_CAP) {
        fclose(f); return 0;
    }

    if (!g_incr_heap) {
        g_incr_heap = malloc(sizeof(IncrHeap));
        heap_init(g_incr_heap, INCR_HEAP_CAP);
    }
    if ((int)fread(g_incr_heap->entries, sizeof(IncrEntry), (size_t)heap_size, f) != heap_size) {
        fclose(f); return 0;
    }
    g_incr_heap->size = heap_size;

    /* Ring buffer (skip — we'll regenerate from heap) */
    int dummy_head, dummy_tail;
    fread(&dummy_head, sizeof(int), 1, f);
    fread(&dummy_tail, sizeof(int), 1, f);

    long tested;
    if (fread(&tested, sizeof(long), 1, f) == 1)
        atomic_store(&g_tested, tested);

    fclose(f);
    return 1;
}

/* Incremental producer thread */
static void *incr_producer_thread(void *arg)
{
    (void)arg;
    if (!g_markov) return NULL;

    int cs = g_markov->charset_size;
    int threshold = g_markov->threshold;
    int effective_cs = (threshold < cs) ? threshold : cs;
    if (effective_cs < 1) effective_cs = 1;
    double log_base = log((double)effective_cs);

    /* Use global heap (may be pre-loaded from checkpoint) */
    if (!g_incr_heap) {
        g_incr_heap = malloc(sizeof(IncrHeap));
        heap_init(g_incr_heap, INCR_HEAP_CAP);

        /* Seed with best candidate at each length 1..MAX_PASS_LEN */
        for (int len = 1; len <= MAX_PASS_LEN; len++) {
            IncrEntry e;
            memset(&e, 0, sizeof(e));
            e.length = len;
            e.log_prob = (double)len * log_base;
            heap_push(g_incr_heap, &e);
        }
    }

    while (g_incr_heap->size > 0 && !atomic_load_explicit(&g_found, memory_order_relaxed) && !g_interrupted) {
        IncrEntry e = heap_pop(g_incr_heap);

        /* Reconstruct index from indices array and generate password */
        char pass[MAX_PASS_LEN + 1];
        {
            long idx = 0;
            for (int i = 0; i < e.length; i++)
                idx = idx * effective_cs + e.indices[i];
            markov_index_to_pass(idx, e.length, pass);
        }

        /* Push to ring buffer */
        pthread_mutex_lock(&g_incr_mutex);
        while (((g_incr_head + 1) % INCR_RING_SIZE) == g_incr_tail &&
               !atomic_load_explicit(&g_found, memory_order_relaxed)) {
            pthread_cond_wait(&g_incr_not_full, &g_incr_mutex);
        }
        if (atomic_load_explicit(&g_found, memory_order_relaxed)) {
            pthread_mutex_unlock(&g_incr_mutex);
            break;
        }
        strncpy(g_incr_ring[g_incr_head], pass, MAX_PASS_LEN);
        g_incr_ring[g_incr_head][MAX_PASS_LEN] = '\0';
        g_incr_head = (g_incr_head + 1) % INCR_RING_SIZE;
        pthread_cond_signal(&g_incr_not_empty);
        pthread_mutex_unlock(&g_incr_mutex);

        /* Generate children: try incrementing each position right-to-left */
        for (int pos = e.length - 1; pos >= 0; pos--) {
            if (e.indices[pos] + 1 < effective_cs) {
                IncrEntry child = e;
                child.indices[pos]++;
                child.log_prob += log_base * 0.1;
                if (g_incr_heap->size < g_incr_heap->capacity)
                    heap_push(g_incr_heap, &child);
                break;
            }
        }
    }

    pthread_mutex_lock(&g_incr_mutex);
    g_incr_done = 1;
    pthread_cond_broadcast(&g_incr_not_empty);
    pthread_mutex_unlock(&g_incr_mutex);

    return NULL;
}

/* Incremental consumer worker */
static void *incr_consumer_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long local_count = 0;

    for (;;) {
        if (atomic_load_explicit(&g_found, memory_order_relaxed)) break;

        pthread_mutex_lock(&g_incr_mutex);
        while (g_incr_head == g_incr_tail && !g_incr_done &&
               !atomic_load_explicit(&g_found, memory_order_relaxed)) {
            pthread_cond_wait(&g_incr_not_empty, &g_incr_mutex);
        }
        if (g_incr_head == g_incr_tail && (g_incr_done ||
            atomic_load_explicit(&g_found, memory_order_relaxed))) {
            pthread_mutex_unlock(&g_incr_mutex);
            break;
        }
        char pass[MAX_PASS_LEN + 1];
        strncpy(pass, g_incr_ring[g_incr_tail], MAX_PASS_LEN);
        pass[MAX_PASS_LEN] = '\0';
        g_incr_tail = (g_incr_tail + 1) % INCR_RING_SIZE;
        pthread_cond_signal(&g_incr_not_full);
        pthread_mutex_unlock(&g_incr_mutex);

        if (test_password_fast(pass)) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pass, MAX_PASS_LEN);
            break;
        }
        if (++local_count >= TESTED_BATCH) {
            atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
            local_count = 0;
        }
    }
    if (local_count > 0)
        atomic_fetch_add(&g_tested, local_count);
    free(arg);
    return NULL;
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
    /* For R3/R4: MD5(padding+fileID) is identical for all passwords.
     * Compute once before the loop to avoid redundant MD5 calls. */
    uint8_t base_hash[16];
    if (g_enc_params.revision >= 3) {
        CC_MD5_CTX md5;
        CC_MD5_Init(&md5);
        CC_MD5_Update(&md5, PDF_PASSWORD_PADDING, 32);
        CC_MD5_Update(&md5, g_enc_params.file_id,
                      (CC_LONG)g_enc_params.file_id_len);
        CC_MD5_Final(base_hash, &md5);
    }

    for (int i = 0; i < count; i++) {
        const uint8_t *key = keys + i * key_bytes;
        int user_match = 0;

        if (g_enc_params.revision == 2) {
            /* Algorithm 4: RC4-encrypt padding, compare all 32 bytes of U */
            uint8_t computed_u[32];
            size_t out_len = 32;
            CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                    key, (size_t)key_bytes, NULL,
                    PDF_PASSWORD_PADDING, 32,
                    computed_u, 32, &out_len);
            if (memcmp(computed_u, g_enc_params.u_value, 32) == 0)
                user_match = 1;
        } else {
            /* Algorithm 5: RC4 with pre-computed MD5(padding+fileID),
             * 20 RC4 passes, compare 16 bytes */
            uint8_t encrypted[16];
            size_t out_len = 16;
            CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                    key, (size_t)key_bytes, NULL,
                    base_hash, 16, encrypted, 16, &out_len);

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

            if (memcmp(encrypted, g_enc_params.u_value, 16) == 0)
                user_match = 1;
        }

        /* GPU keygen computes user key (Algorithm 2). Check user match. */
        if (user_match && g_password_mode != PW_MODE_OWNER) {
            if (!atomic_exchange(&g_found, 1)) {
                strncpy(g_password, passwords[i], MAX_PASS_LEN);
                g_found_type = "User";
            }
            return 1;
        }

        /* For owner password: Algorithm 3 is different from Algorithm 2,
         * so GPU-derived keys won't work. Fall back to CPU verify. */
        if (g_password_mode == PW_MODE_OWNER || g_password_mode == PW_MODE_BOTH) {
            if (pdf_verify_owner_password(&g_enc_params, passwords[i])) {
                if (!atomic_exchange(&g_found, 1)) {
                    strncpy(g_password, passwords[i], MAX_PASS_LEN);
                    g_found_type = "Owner";
                }
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

    /* Double-buffered password arrays for pipelining */
    const char **pw_ptrs[2];
    char *pw_storage[2];
    uint8_t *keys[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));
        keys[b] = malloc((size_t)GPU_BATCH_SIZE * key_bytes);
        if (!pw_ptrs[b] || !pw_storage[b] || !keys[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->total) end = a->total;
        int count = (int)(end - start);

        /* Generate password strings on CPU while GPU processes previous batch */
        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            g_idx_to_pass(start + i, a->length, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        /* Wait for previous GPU batch and verify on CPU */
        if (pending_handle) {
            int n = metal_keygen_wait_results(g_gpu_ctx, pending_handle,
                                               pending_count, keys[pending_buf]);
            pending_handle = NULL;
            if (n > 0)
                verify_keys_rc4(keys[pending_buf], pw_ptrs[pending_buf], n, key_bytes);
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        /* Submit current batch to GPU (non-blocking) */
        pending_handle = metal_keygen_submit_async(g_gpu_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    /* Drain last pending batch */
    if (pending_handle) {
        int n = metal_keygen_wait_results(g_gpu_ctx, pending_handle,
                                           pending_count, keys[pending_buf]);
        if (n > 0)
            verify_keys_rc4(keys[pending_buf], pw_ptrs[pending_buf], n, key_bytes);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) {
        free(pw_ptrs[b]);
        free(pw_storage[b]);
        free(keys[b]);
    }
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

    /* Double-buffered for async GPU pipelining */
    const char **pw_ptrs[2];
    uint8_t *keys[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        keys[b] = malloc((size_t)GPU_BATCH_SIZE * key_bytes);
        if (!pw_ptrs[b] || !keys[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= g_nwords) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > g_nwords) end = g_nwords;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++)
            pw_ptrs[cur_buf][i] = g_words[start + i];

        if (pending_handle) {
            int n = metal_keygen_wait_results(g_gpu_ctx, pending_handle,
                                               pending_count, keys[pending_buf]);
            pending_handle = NULL;
            if (n > 0)
                verify_keys_rc4(keys[pending_buf], pw_ptrs[pending_buf], n, key_bytes);
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_keygen_submit_async(g_gpu_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        int n = metal_keygen_wait_results(g_gpu_ctx, pending_handle,
                                           pending_count, keys[pending_buf]);
        if (n > 0)
            verify_keys_rc4(keys[pending_buf], pw_ptrs[pending_buf], n, key_bytes);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) {
        free(pw_ptrs[b]);
        free(keys[b]);
    }
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
            /* Skip duplicate candidates */
            if (rule_dedup_check(pass)) continue;

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
 * R5 SHA-256 GPU workers — async double-buffered pipeline
 * ================================================================ */

/* Helper: wait for R5 async results with _ex support for BOTH mode */
static inline int sha256_wait_and_check(void *handle, int count, const char **pw_buf)
{
    int match_type = 0;
    int match = (g_password_mode == PW_MODE_BOTH)
        ? metal_sha256_wait_results_ex(g_sha256_ctx, handle, count, &match_type)
        : metal_sha256_wait_results(g_sha256_ctx, handle, count);
    if (match >= 0) {
        if (!atomic_exchange(&g_found, 1)) {
            strncpy(g_password, pw_buf[match], MAX_PASS_LEN);
            if (match_type == 1) g_found_type = "User";
            else if (match_type == 2) g_found_type = "Owner";
            else g_found_type = (g_password_mode == PW_MODE_OWNER) ? "Owner" : "User";
        }
    }
    return match;
}

static void *gpu_sha256_brute_worker(void *arg)
{
    GPUBruteArg *a = (GPUBruteArg *)arg;

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

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= a->total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > a->total) end = a->total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            g_idx_to_pass(start + i, a->length, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
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

static void *gpu_sha256_dict_worker(void *arg)
{
    (void)arg;

    const char **pw_ptrs[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        if (!pw_ptrs[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= g_nwords) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > g_nwords) end = g_nwords;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++)
            pw_ptrs[cur_buf][i] = g_words[start + i];

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }

done:
    for (int b = 0; b < 2; b++) free(pw_ptrs[b]);
    free(arg);
    return NULL;
}

static void *gpu_sha256_rule_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_nrules;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

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
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            apply_rule(g_words[word_idx], rule_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
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

static void *gpu_sha256_hybrid_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_hybrid_suffix_keyspace;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0;
    int pending_buf = 0;

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
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            hybrid_gen_pass(word_idx, suffix_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
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
 * R6 GPU workers (Algorithm 2.B — SHA-256/384/512 + AES on GPU)
 * ================================================================ */

/* Helper: wait for R6 async results with _ex support for BOTH mode */
static inline int r6_wait_and_check(void *handle, int count, const char **pw_buf)
{
    int match_type = 0;
    int match = (g_password_mode == PW_MODE_BOTH)
        ? metal_r6_wait_results_ex(g_r6_ctx, handle, count, &match_type)
        : metal_r6_wait_results(g_r6_ctx, handle, count);
    if (match >= 0) {
        if (!atomic_exchange(&g_found, 1)) {
            strncpy(g_password, pw_buf[match], MAX_PASS_LEN);
            if (match_type == 1) g_found_type = "User";
            else if (match_type == 2) g_found_type = "Owner";
            else g_found_type = (g_password_mode == PW_MODE_OWNER) ? "Owner" : "User";
        }
    }
    return match;
}

static void *gpu_r6_brute_worker(void *arg)
{
    GPUBruteArg *a = (GPUBruteArg *)arg;
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

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
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
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
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
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
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

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
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
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
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

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
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
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
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

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
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }

        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }

    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
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
/* ================================================================
 * PRINCE attack: combine 2-3 dictionary words
 * Keyspace: nwords^2 + nwords^3 (2-word and 3-word combos)
 * ================================================================ */
static long g_prince_2word_total = 0;
static long g_prince_total = 0;
static int  g_prince_max_words = 3;

static void prince_index_to_pass(long idx, char *out)
{
    /* Indices [0, nwords^2) → 2-word combos
     * Indices [nwords^2, nwords^2 + nwords^3) → 3-word combos */
    int pos = 0;
    if (idx < g_prince_2word_total) {
        long w2 = idx % g_nwords;
        long w1 = idx / g_nwords;
        const char *s1 = g_words[w1], *s2 = g_words[w2];
        size_t l1 = strlen(s1), l2 = strlen(s2);
        if (l1 + l2 <= MAX_PASS_LEN) {
            memcpy(out, s1, l1);
            memcpy(out + l1, s2, l2);
            pos = (int)(l1 + l2);
        }
    } else if (g_prince_max_words >= 3) {
        long rem = idx - g_prince_2word_total;
        long w3 = rem % g_nwords; rem /= g_nwords;
        long w2 = rem % g_nwords;
        long w1 = rem / g_nwords;
        const char *s1 = g_words[w1], *s2 = g_words[w2], *s3 = g_words[w3];
        size_t l1 = strlen(s1), l2 = strlen(s2), l3 = strlen(s3);
        if (l1 + l2 + l3 <= MAX_PASS_LEN) {
            memcpy(out, s1, l1);
            memcpy(out + l1, s2, l2);
            memcpy(out + l1 + l2, s3, l3);
            pos = (int)(l1 + l2 + l3);
        }
    }
    out[pos] = '\0';
}

static void *prince_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long local_count = 0;
    char pass[MAX_PASS_LEN * 3 + 1];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (start >= g_prince_total) break;
        long end = start + CPU_WORK_CHUNK;
        if (end > g_prince_total) end = g_prince_total;

        for (long idx = start; idx < end && !atomic_load_explicit(&g_found, memory_order_relaxed); idx++) {
            prince_index_to_pass(idx, pass);
            if (pass[0] && test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

/* ================================================================
 * Hybrid PRINCE + rules worker
 * ================================================================ */
static void *prince_rule_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long total = g_prince_total * g_nrules;
    long local_count = 0;
    char base[MAX_PASS_LEN * 3 + 1];
    char pass[MAX_PASS_LEN * 3 + 2];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (start >= total) break;
        long end = start + CPU_WORK_CHUNK;
        if (end > total) end = total;

        for (long idx = start; idx < end && !atomic_load_explicit(&g_found, memory_order_relaxed); idx++) {
            long prince_idx = idx / g_nrules;
            int  rule_idx = (int)(idx % g_nrules);
            prince_index_to_pass(prince_idx, base);
            if (!base[0]) goto pr_skip;
            apply_rule(base, rule_idx, pass);
            if (pass[0] && test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
        pr_skip:
            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

/* ================================================================
 * Toggle-case walk: enumerate all case variations of dict words
 * ================================================================ */
static void *toggle_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long local_count = 0;
    char pass[MAX_PASS_LEN + 1];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long word_idx = atomic_fetch_add(&g_next_idx, 1);
        if (word_idx >= g_nwords) break;

        const char *word = g_words[word_idx];
        size_t wlen = strlen(word);

        /* Count alpha chars (positions where case can be toggled) */
        int alpha_positions[MAX_PASS_LEN];
        int nalpha = 0;
        for (size_t j = 0; j < wlen && j < MAX_PASS_LEN; j++) {
            if (isalpha((unsigned char)word[j]))
                alpha_positions[nalpha++] = (int)j;
        }
        if (nalpha > 16) nalpha = 16; /* cap at 2^16 = 65536 variants */

        long nvariants = 1L << nalpha;
        strncpy(pass, word, MAX_PASS_LEN);
        pass[MAX_PASS_LEN] = '\0';

        for (long v = 0; v < nvariants && !atomic_load_explicit(&g_found, memory_order_relaxed); v++) {
            /* Apply toggle bits */
            for (int b = 0; b < nalpha; b++) {
                int pos = alpha_positions[b];
                char ch = word[pos];
                pass[pos] = (v & (1L << b)) ? (islower((unsigned char)ch) ? toupper((unsigned char)ch) : tolower((unsigned char)ch)) : ch;
            }

            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }

            if (test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

/* GPU toggle worker for R5/R6 */
static void *gpu_sha256_toggle_worker(void *arg)
{
    (void)arg;
    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }
    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    /* Each word generates up to 2^nalpha variants; iterate with a shared word counter */
    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        int count = 0;
        /* Fill a batch from toggle variants */
        while (count < GPU_BATCH_SIZE) {
            long idx = atomic_fetch_add(&g_next_idx, 1);
            if (idx >= atomic_load(&g_total)) goto submit;
            /* Decompose: idx encodes (word_idx, variant) pairs */
            /* We use a flat index: for each word, we store 2^nalpha variants sequentially */
            /* g_total = sum of 2^nalpha for all words, pre-computed */
            /* We need a different approach: flat linear index into combined space */
            long flat = idx;
            /* For simplicity, use test_password_fast path in CPU toggle_worker;
               GPU toggle fills batches of passwords from flat index space */
            /* decode: scan words to find which word and variant */
            /* This is slow; instead, precompute cumulative offsets */
            /* For now: generate password from flat index into pw_storage */
            char *pw = pw_storage[cur_buf] + count * (MAX_PASS_LEN + 1);
            /* Simple approach: each word gets 2^min(nalpha,16) variants */
            /* We stored cumulative count in g_total. Just generate inline. */
            long word_idx = 0, cumul = 0;
            for (long w = 0; w < g_nwords; w++) {
                size_t wlen = strlen(g_words[w]);
                int na = 0;
                for (size_t j = 0; j < wlen && j < MAX_PASS_LEN; j++)
                    if (isalpha((unsigned char)g_words[w][j])) na++;
                if (na > 16) na = 16;
                long nv = 1L << na;
                if (flat < cumul + nv) { word_idx = w; flat -= cumul; break; }
                cumul += nv;
            }
            const char *word = g_words[word_idx];
            size_t wlen = strlen(word);
            strncpy(pw, word, MAX_PASS_LEN);
            pw[MAX_PASS_LEN] = '\0';
            long v = flat;
            int bi = 0;
            for (size_t j = 0; j < wlen && j < MAX_PASS_LEN; j++) {
                if (isalpha((unsigned char)word[j])) {
                    if (bi < 16 && (v & (1L << bi)))
                        pw[j] = islower((unsigned char)word[j]) ? toupper((unsigned char)word[j]) : tolower((unsigned char)word[j]);
                    bi++;
                }
            }
            pw_ptrs[cur_buf][count] = pw;
            count++;
        }
    submit:
        if (count == 0) break;

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* ================================================================
 * Combinator attack: dict1 x dict2
 * ================================================================ */
static void *combinator_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long total = g_nwords * g_nwords2;
    long local_count = 0;
    char pass[MAX_PASS_LEN * 2 + 2];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (start >= total) break;
        long end = start + CPU_WORK_CHUNK;
        if (end > total) end = total;

        for (long i = start; i < end && !atomic_load_explicit(&g_found, memory_order_relaxed); i++) {
            long w1 = i / g_nwords2;
            long w2 = i % g_nwords2;
            size_t l1 = strlen(g_words[w1]);
            size_t l2 = strlen(g_words2[w2]);
            if (l1 + l2 > MAX_PASS_LEN) { if (++local_count >= TESTED_BATCH) { atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed); local_count = 0; } continue; }
            memcpy(pass, g_words[w1], l1);
            memcpy(pass + l1, g_words2[w2], l2);
            pass[l1 + l2] = '\0';

            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }

            if (test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

/* GPU combinator worker for R5 */
static void *gpu_sha256_combinator_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_nwords2;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long w1 = idx / g_nwords2;
            long w2 = idx % g_nwords2;
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            size_t l1 = strlen(g_words[w1]);
            size_t l2 = strlen(g_words2[w2]);
            if (l1 + l2 <= MAX_PASS_LEN) {
                memcpy(pw, g_words[w1], l1);
                memcpy(pw + l1, g_words2[w2], l2);
                pw[l1 + l2] = '\0';
            } else {
                pw[0] = '\0';
            }
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* GPU combinator worker for R6 */
static void *gpu_r6_combinator_worker(void *arg)
{
    (void)arg;
    long total = g_nwords * g_nwords2;
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= total) break;
        long end = start + batch;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long w1 = idx / g_nwords2;
            long w2 = idx % g_nwords2;
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            size_t l1 = strlen(g_words[w1]);
            size_t l2 = strlen(g_words2[w2]);
            if (l1 + l2 <= MAX_PASS_LEN) {
                memcpy(pw, g_words[w1], l1);
                memcpy(pw + l1, g_words2[w2], l2);
                pw[l1 + l2] = '\0';
            } else {
                pw[0] = '\0';
            }
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* ================================================================
 * Date-based attack: try common date password formats
 * ================================================================ */

/* Number of date formats */
#define DATE_FMT_COUNT 9
/* Additional variations: YYYY, MMYYYY, YYYYMM */
#define DATE_VAR_COUNT 3

static long dates_compute_keyspace(void)
{
    int nyears = g_date_year_end - g_date_year_start + 1;
    /* Full date formats: DATE_FMT_COUNT * 12 months * 31 days * nyears */
    long full = (long)DATE_FMT_COUNT * 12 * 31 * nyears;
    /* Variations: YYYY, MMYYYY, YYYYMM → nyears + 12*nyears + 12*nyears */
    long var = (long)nyears + 2L * 12 * nyears;
    return full + var;
}

static void dates_index_to_pass(long idx, char *out)
{
    int nyears = g_date_year_end - g_date_year_start + 1;
    long full_count = (long)DATE_FMT_COUNT * 12 * 31 * nyears;

    if (idx < full_count) {
        /* Full date format */
        int fmt = (int)(idx % DATE_FMT_COUNT);
        long rem = idx / DATE_FMT_COUNT;
        int day = (int)(rem % 31) + 1;
        rem /= 31;
        int month = (int)(rem % 12) + 1;
        rem /= 12;
        int year = (int)rem + g_date_year_start;
        int yy = year % 100;

        switch (fmt) {
            case 0: snprintf(out, MAX_PASS_LEN+1, "%02d%02d%04d", month, day, year); break;  /* MMDDYYYY */
            case 1: snprintf(out, MAX_PASS_LEN+1, "%02d%02d%04d", day, month, year); break;  /* DDMMYYYY */
            case 2: snprintf(out, MAX_PASS_LEN+1, "%04d%02d%02d", year, month, day); break;  /* YYYYMMDD */
            case 3: snprintf(out, MAX_PASS_LEN+1, "%02d/%02d/%04d", month, day, year); break; /* MM/DD/YYYY */
            case 4: snprintf(out, MAX_PASS_LEN+1, "%02d/%02d/%04d", day, month, year); break; /* DD/MM/YYYY */
            case 5: snprintf(out, MAX_PASS_LEN+1, "%04d-%02d-%02d", year, month, day); break; /* YYYY-MM-DD */
            case 6: snprintf(out, MAX_PASS_LEN+1, "%02d%02d%02d", month, day, yy); break;    /* MMDDYY */
            case 7: snprintf(out, MAX_PASS_LEN+1, "%02d%02d%02d", day, month, yy); break;    /* DDMMYY */
            case 8: snprintf(out, MAX_PASS_LEN+1, "%02d%02d%02d", yy, month, day); break;    /* YYMMDD */
        }
    } else {
        /* Variations */
        long var_idx = idx - full_count;
        if (var_idx < nyears) {
            /* Just year: YYYY */
            int year = (int)var_idx + g_date_year_start;
            snprintf(out, MAX_PASS_LEN+1, "%04d", year);
        } else {
            var_idx -= nyears;
            if (var_idx < 12L * nyears) {
                /* MMYYYY */
                int month = (int)(var_idx % 12) + 1;
                int year = (int)(var_idx / 12) + g_date_year_start;
                snprintf(out, MAX_PASS_LEN+1, "%02d%04d", month, year);
            } else {
                var_idx -= 12L * nyears;
                /* YYYYMM */
                int month = (int)(var_idx % 12) + 1;
                int year = (int)(var_idx / 12) + g_date_year_start;
                snprintf(out, MAX_PASS_LEN+1, "%04d%02d", year, month);
            }
        }
    }
}

static void *dates_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long total = atomic_load(&g_total);
    long local_count = 0;
    char pass[MAX_PASS_LEN + 1];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (start >= total) break;
        long end = start + CPU_WORK_CHUNK;
        if (end > total) end = total;

        for (long i = start; i < end && !atomic_load_explicit(&g_found, memory_order_relaxed); i++) {
            dates_index_to_pass(i, pass);

            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }

            if (test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

static void *gpu_sha256_dates_worker(void *arg)
{
    (void)arg;
    long total = atomic_load(&g_total);

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            dates_index_to_pass(start + i, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

static void *gpu_r6_dates_worker(void *arg)
{
    (void)arg;
    long total = atomic_load(&g_total);
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN + 1));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= total) break;
        long end = start + batch;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            dates_index_to_pass(start + i, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* ================================================================
 * Smart mutations attack: apply common mutations to dictionary words
 * Mutations per word: 10 + 100 + 1000 + 77 + 10 + 9 + 1 + 1 + 1 + 1 = 1210
 * ================================================================ */
#define MUTATE_NMUTATIONS 1210

static const char *mutate_suffixes[] = {
    "!", "@", "#", "$", "123", "1234", "12345", "!!", "!!!", "@#$"
};
#define MUTATE_NSUFFIXES 10

static void mutate_index_to_pass(long word_idx, int mut_idx, char *out)
{
    const char *word = g_words[word_idx];
    size_t wlen = strlen(word);

    if (mut_idx < 10) {
        /* Append single digit 0-9 */
        if (wlen + 1 <= MAX_PASS_LEN) {
            memcpy(out, word, wlen);
            out[wlen] = '0' + mut_idx;
            out[wlen + 1] = '\0';
        } else { out[0] = '\0'; }
    } else if (mut_idx < 110) {
        /* Append two digits 00-99 */
        int n = mut_idx - 10;
        if (wlen + 2 <= MAX_PASS_LEN) {
            memcpy(out, word, wlen);
            out[wlen]     = '0' + (n / 10);
            out[wlen + 1] = '0' + (n % 10);
            out[wlen + 2] = '\0';
        } else { out[0] = '\0'; }
    } else if (mut_idx < 1110) {
        /* Append three digits 000-999 */
        int n = mut_idx - 110;
        if (wlen + 3 <= MAX_PASS_LEN) {
            memcpy(out, word, wlen);
            out[wlen]     = '0' + (n / 100);
            out[wlen + 1] = '0' + ((n / 10) % 10);
            out[wlen + 2] = '0' + (n % 10);
            out[wlen + 3] = '\0';
        } else { out[0] = '\0'; }
    } else if (mut_idx < 1187) {
        /* Append years 1950-2026 (77 years) */
        int year = 1950 + (mut_idx - 1110);
        if (wlen + 4 <= MAX_PASS_LEN) {
            memcpy(out, word, wlen);
            snprintf(out + wlen, MAX_PASS_LEN + 1 - wlen, "%04d", year);
        } else { out[0] = '\0'; }
    } else if (mut_idx < 1197) {
        /* Append common suffixes */
        int si = mut_idx - 1187;
        const char *suffix = mutate_suffixes[si];
        size_t slen = strlen(suffix);
        if (wlen + slen <= MAX_PASS_LEN) {
            memcpy(out, word, wlen);
            memcpy(out + wlen, suffix, slen);
            out[wlen + slen] = '\0';
        } else { out[0] = '\0'; }
    } else if (mut_idx < 1206) {
        /* Prepend digits 1-9 */
        int d = mut_idx - 1197 + 1;
        if (wlen + 1 <= MAX_PASS_LEN) {
            out[0] = '0' + d;
            memcpy(out + 1, word, wlen);
            out[wlen + 1] = '\0';
        } else { out[0] = '\0'; }
    } else if (mut_idx == 1206) {
        /* Capitalize first letter */
        memcpy(out, word, wlen + 1);
        if (wlen > 0) out[0] = toupper((unsigned char)out[0]);
    } else if (mut_idx == 1207) {
        /* Capitalize all letters */
        for (size_t i = 0; i < wlen; i++)
            out[i] = toupper((unsigned char)word[i]);
        out[wlen] = '\0';
    } else if (mut_idx == 1208) {
        /* Reverse the word */
        for (size_t i = 0; i < wlen; i++)
            out[i] = word[wlen - 1 - i];
        out[wlen] = '\0';
    } else if (mut_idx == 1209) {
        /* Double the word */
        if (wlen * 2 <= MAX_PASS_LEN) {
            memcpy(out, word, wlen);
            memcpy(out + wlen, word, wlen);
            out[wlen * 2] = '\0';
        } else { out[0] = '\0'; }
    } else {
        out[0] = '\0';
    }
}

static void *mutate_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long total = atomic_load(&g_total);
    long local_count = 0;
    char pass[MAX_PASS_LEN * 2 + 2];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (start >= total) break;
        long end = start + CPU_WORK_CHUNK;
        if (end > total) end = total;

        for (long i = start; i < end && !atomic_load_explicit(&g_found, memory_order_relaxed); i++) {
            long word_idx = i / MUTATE_NMUTATIONS;
            int  mut_idx  = (int)(i % MUTATE_NMUTATIONS);
            mutate_index_to_pass(word_idx, mut_idx, pass);

            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }

            if (pass[0] && test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

static void *gpu_sha256_mutate_worker(void *arg)
{
    (void)arg;
    long total = atomic_load(&g_total);

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / MUTATE_NMUTATIONS;
            int  mut_idx  = (int)(idx % MUTATE_NMUTATIONS);
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            mutate_index_to_pass(word_idx, mut_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

static void *gpu_r6_mutate_worker(void *arg)
{
    (void)arg;
    long total = atomic_load(&g_total);
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= total) break;
        long end = start + batch;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long word_idx = idx / MUTATE_NMUTATIONS;
            int  mut_idx  = (int)(idx % MUTATE_NMUTATIONS);
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            mutate_index_to_pass(word_idx, mut_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* ================================================================
 * L33tspeak substitutions attack
 * Substitution map: a→@, a→4, e→3, i→1, i→!, o→0, s→$, s→5, t→7, l→1, b→8, g→9
 * ================================================================ */

typedef struct {
    char from;
    char to;
} LeetSub;

static const LeetSub g_leet_subs[] = {
    {'a', '@'}, {'a', '4'}, {'e', '3'}, {'i', '1'}, {'i', '!'},
    {'o', '0'}, {'s', '$'}, {'s', '5'}, {'t', '7'}, {'l', '1'},
    {'b', '8'}, {'g', '9'},
};
#define LEET_NSUBS 12

/* Precomputed per-word leet info */
typedef struct {
    long cumul_offset;  /* cumulative variants from prior words */
    int  nsub_pos;      /* number of substitutable positions (capped at 16) */
    int  sub_pos[16];   /* positions within the word */
    int  sub_idx[16];   /* index into g_leet_subs for each position */
    int  nsubs_at[16];  /* number of possible substitutions at each position */
    int  sub_start[16]; /* starting index in g_leet_subs for each position */
} LeetWordInfo;

static LeetWordInfo *g_leet_info = NULL;
static long g_leet_total = 0;

static void leet_precompute(void)
{
    g_leet_info = calloc((size_t)g_nwords, sizeof(LeetWordInfo));
    if (!g_leet_info) return;

    long cumul = 0;
    for (long w = 0; w < g_nwords; w++) {
        g_leet_info[w].cumul_offset = cumul;
        const char *word = g_words[w];
        size_t wlen = strlen(word);
        int npos = 0;

        for (size_t j = 0; j < wlen && j < MAX_PASS_LEN; j++) {
            char lc = tolower((unsigned char)word[j]);
            /* Count how many subs apply to this char */
            int nsubs = 0;
            int first_sub = -1;
            for (int s = 0; s < LEET_NSUBS; s++) {
                if (g_leet_subs[s].from == lc) {
                    if (first_sub < 0) first_sub = s;
                    nsubs++;
                }
            }
            if (nsubs > 0 && npos < 16) {
                g_leet_info[w].sub_pos[npos] = (int)j;
                g_leet_info[w].nsubs_at[npos] = nsubs;
                g_leet_info[w].sub_start[npos] = first_sub;
                npos++;
            }
        }
        g_leet_info[w].nsub_pos = npos;

        /* Compute variants: product of (nsubs_at[i] + 1) for each position
         * (the +1 is for keeping the original char) */
        long nvariants = 1;
        for (int p = 0; p < npos; p++) {
            nvariants *= (g_leet_info[w].nsubs_at[p] + 1);
            if (nvariants > 65536) { nvariants = 65536; break; }
        }
        cumul += nvariants;
    }
    g_leet_total = cumul;
}

/* Decode flat index into word_idx + variant */
static void leet_index_to_pass(long idx, char *out)
{
    /* Binary search for word */
    long lo = 0, hi = g_nwords - 1;
    while (lo < hi) {
        long mid = (lo + hi + 1) / 2;
        if (g_leet_info[mid].cumul_offset <= idx) lo = mid;
        else hi = mid - 1;
    }
    long word_idx = lo;
    long var_idx = idx - g_leet_info[word_idx].cumul_offset;

    const char *word = g_words[word_idx];
    size_t wlen = strlen(word);
    if (wlen > MAX_PASS_LEN) wlen = MAX_PASS_LEN;
    memcpy(out, word, wlen);
    out[wlen] = '\0';

    int npos = g_leet_info[word_idx].nsub_pos;
    /* Decompose var_idx into per-position choice using mixed-radix */
    for (int p = 0; p < npos; p++) {
        int nchoices = g_leet_info[word_idx].nsubs_at[p] + 1; /* +1 for original */
        int choice = (int)(var_idx % nchoices);
        var_idx /= nchoices;
        if (choice > 0) {
            /* choice 1..nsubs → apply substitution */
            int si = g_leet_info[word_idx].sub_start[p] + (choice - 1);
            int pos = g_leet_info[word_idx].sub_pos[p];
            out[pos] = g_leet_subs[si].to;
        }
    }
}

static void *leet_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long total = atomic_load(&g_total);
    long local_count = 0;
    char pass[MAX_PASS_LEN + 1];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (start >= total) break;
        long end = start + CPU_WORK_CHUNK;
        if (end > total) end = total;

        for (long i = start; i < end && !atomic_load_explicit(&g_found, memory_order_relaxed); i++) {
            leet_index_to_pass(i, pass);

            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }

            if (test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

static void *gpu_sha256_leet_worker(void *arg)
{
    (void)arg;
    long total = atomic_load(&g_total);

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN + 1));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            leet_index_to_pass(start + i, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

static void *gpu_r6_leet_worker(void *arg)
{
    (void)arg;
    long total = atomic_load(&g_total);
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN + 1));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }

    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= total) break;
        long end = start + batch;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN + 1);
            leet_index_to_pass(start + i, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* ================================================================
 * Mask+rules hybrid attack: apply rules to mask-generated candidates
 * ================================================================ */
static void *mask_rule_worker(void *arg)
{
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    long total = g_mask_keyspace * g_nrules;
    long local_count = 0;
    char base[MAX_PASS_LEN + 1];
    char pass[MAX_PASS_LEN * 2 + 2];

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, CPU_WORK_CHUNK);
        if (start >= total) break;
        long end = start + CPU_WORK_CHUNK;
        if (end > total) end = total;

        for (long idx = start; idx < end && !atomic_load_explicit(&g_found, memory_order_relaxed); idx++) {
            long mask_idx = idx / g_nrules;
            int  rule_idx = (int)(idx % g_nrules);
            mask_index_to_pass(mask_idx, 0, base);
            apply_rule(base, rule_idx, pass);

            if (++local_count >= TESTED_BATCH) {
                atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
                local_count = 0;
            }

            if (pass[0] && test_password_fast(pass)) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, pass, MAX_PASS_LEN);
                break;
            }
        }
    }
    atomic_fetch_add_explicit(&g_tested, local_count, memory_order_relaxed);
    free(arg);
    return NULL;
}

/* GPU mask+rules worker for R5 */
static void *gpu_sha256_mask_rule_worker(void *arg)
{
    (void)arg;
    long total = g_mask_keyspace * g_nrules;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * GPU_BATCH_SIZE);
        pw_storage[b] = malloc((size_t)GPU_BATCH_SIZE * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }
    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (start >= total) break;
        long end = start + GPU_BATCH_SIZE;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long mask_idx = idx / g_nrules;
            int  rule_idx = (int)(idx % g_nrules);
            char base[MAX_PASS_LEN + 1];
            mask_index_to_pass(mask_idx, 0, base);
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            apply_rule(base, rule_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_sha256_submit_async(g_sha256_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        sha256_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* GPU mask+rules worker for R6 */
static void *gpu_r6_mask_rule_worker(void *arg)
{
    (void)arg;
    long total = g_mask_keyspace * g_nrules;
    int batch = metal_r6_max_batch(g_r6_ctx);
    if (g_gpu_batch > 0 && g_gpu_batch < batch) batch = g_gpu_batch;

    const char **pw_ptrs[2];
    char *pw_storage[2];
    for (int b = 0; b < 2; b++) {
        pw_ptrs[b] = malloc(sizeof(char *) * batch);
        pw_storage[b] = malloc((size_t)batch * (MAX_PASS_LEN * 2 + 2));
        if (!pw_ptrs[b] || !pw_storage[b]) goto done;
    }
    int cur_buf = 0;
    void *pending_handle = NULL;
    int pending_count = 0, pending_buf = 0;

    while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
        long start = atomic_fetch_add(&g_next_idx, batch);
        if (start >= total) break;
        long end = start + batch;
        if (end > total) end = total;
        int count = (int)(end - start);

        for (int i = 0; i < count; i++) {
            long idx = start + i;
            long mask_idx = idx / g_nrules;
            int  rule_idx = (int)(idx % g_nrules);
            char base[MAX_PASS_LEN + 1];
            mask_index_to_pass(mask_idx, 0, base);
            char *pw = pw_storage[cur_buf] + i * (MAX_PASS_LEN * 2 + 2);
            apply_rule(base, rule_idx, pw);
            pw_ptrs[cur_buf][i] = pw;
        }

        if (pending_handle) {
            r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
            pending_handle = NULL;
            atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
        }
        pending_handle = metal_r6_submit_async(g_r6_ctx, pw_ptrs[cur_buf], count);
        pending_count = count;
        pending_buf = cur_buf;
        cur_buf ^= 1;
    }
    if (pending_handle) {
        r6_wait_and_check(pending_handle, pending_count, pw_ptrs[pending_buf]);
        atomic_fetch_add_explicit(&g_tested, (long)pending_count, memory_order_relaxed);
    }
done:
    for (int b = 0; b < 2; b++) { free(pw_ptrs[b]); free(pw_storage[b]); }
    free(arg);
    return NULL;
}

/* ================================================================
 * Fingerprint attack: try common patterns before brute-force
 * - Common passwords (password, 123456, etc.)
 * - Date patterns (MMDDYYYY, YYYYMMDD, DDMMYYYY)
 * - Keyboard walks (qwerty, asdfgh, etc.)
 * ================================================================ */
static const char *g_fingerprint_passwords[] = {
    /* Top 50 most common passwords */
    "password", "123456", "12345678", "1234", "qwerty",
    "12345", "dragon", "passwd", "password1", "abc123",
    "monkey", "master", "letmein", "login", "princess",
    "qwerty123", "solo", "1q2w3e", "starwars", "welcome",
    "admin", "passw0rd", "hello", "charlie", "shadow",
    "sunshine", "iloveyou", "trustno1", "batman", "access",
    "football", "jesus", "michael", "ninja", "mustang",
    "summer", "1234567", "123456789", "1234567890", "000000",
    "111111", "654321", "test", "password123", "test123",
    "root", "pass", "changeme", "secret", "P@ssw0rd",
    /* Common with numbers */
    "pass1234", "pass123", "password12", "password1234",
    "qwerty1", "qwerty12", "abc1234", "abcd1234",
    /* Keyboard patterns */
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx",
    "qazwsx", "1q2w3e4r", "1q2w3e4r5t", "zaq12wsx",
    "!@#$%^&*", "1qaz!QAZ",
    NULL
};

static int run_fingerprint_attack(int nthreads, pthread_t *threads, int *spawned_out)
{
    /* Keyspace estimate */
    int n_common = 0;
    for (int i = 0; g_fingerprint_passwords[i]; i++) n_common++;
    long date_combos = 0;
    for (int y = 1950; y <= 2026; y++) {
        for (int m = 1; m <= 12; m++) {
            int dim = 31;
            if (m == 2) dim = (y % 4 == 0) ? 29 : 28;
            else if (m == 4 || m == 6 || m == 9 || m == 11) dim = 30;
            date_combos += dim * 4; /* 3 formats + MMDD short */
        }
        date_combos++; /* year alone */
    }
    long digit_total = 0;
    for (int l = 1; l <= 6; l++) { long n = 1; for (int i = 0; i < l; i++) n *= 10; digit_total += n; }
    long keywalk_est = 50000;
    long fp_total = n_common + date_combos + keywalk_est + digit_total;
    char s_fp[16];
    fmt_num(fp_total, s_fp, sizeof(s_fp));
    fprintf(stderr, "Mode   : fingerprint (common passwords, keywalks, dates, PINs, ~%s candidates)\n", s_fp);

    /* Phase 0: try PDF metadata-derived passwords (Author, Title, etc.) */
    {
        char **meta_words = NULL;
        int meta_count = extract_metadata_seeds(g_pdf_path, &meta_words);
        if (meta_count > 0) {
            fprintf(stderr, "  Phase 0: metadata seeds (%d)...\n", meta_count);
            for (int i = 0; i < meta_count && !atomic_load(&g_found); i++) {
                if (test_password_fast(meta_words[i])) {
                    if (!atomic_exchange(&g_found, 1))
                        strncpy(g_password, meta_words[i], MAX_PASS_LEN);
                    for (int j = 0; j < meta_count; j++) free(meta_words[j]);
                    free(meta_words);
                    return 1;
                }
                atomic_fetch_add(&g_tested, 1);
            }
            for (int i = 0; i < meta_count; i++) free(meta_words[i]);
        }
        free(meta_words);
    }
    if (atomic_load(&g_found)) return 1;

    /* Phase 1: try common passwords directly (single-threaded, small list) */
    fprintf(stderr, "  Phase 1: common passwords (%d)...\n", n_common);
    for (int i = 0; g_fingerprint_passwords[i] && !atomic_load(&g_found); i++) {
        const char *pw = g_fingerprint_passwords[i];
        if (test_password_fast(pw)) {
            if (!atomic_exchange(&g_found, 1))
                strncpy(g_password, pw, MAX_PASS_LEN);
            return 1;
        }
        atomic_fetch_add(&g_tested, 1);
    }
    if (atomic_load(&g_found)) return 1;

    /* Phase 1.5: keyboard walks */
    {
        fprintf(stderr, "  Phase 1.5: keyboard walks...\n");
        typedef char KWEntry[MAX_PASS_LEN + 1];
        KWEntry *kw_walks = malloc(50000 * sizeof(KWEntry));
        if (kw_walks) {
            int nwalks = keywalk_generate(kw_walks, 50000);
            for (int i = 0; i < nwalks && !atomic_load(&g_found); i++) {
                if (test_password_fast(kw_walks[i])) {
                    if (!atomic_exchange(&g_found, 1))
                        strncpy(g_password, kw_walks[i], MAX_PASS_LEN);
                    free(kw_walks);
                    return 1;
                }
                atomic_fetch_add(&g_tested, 1);
            }
            free(kw_walks);
        }
    }
    if (atomic_load(&g_found)) return 1;

    /* Phase 2: date patterns (YYYYMMDD, MMDDYYYY, DDMMYYYY for 1950-2026) */
    fprintf(stderr, "  Phase 2: date patterns (1950-2026)...\n");
    char datepw[16];
    for (int y = 2026; y >= 1950 && !atomic_load(&g_found); y--) {
        for (int m = 1; m <= 12 && !atomic_load(&g_found); m++) {
            int days_in_month = 31;
            if (m == 2) days_in_month = (y % 4 == 0) ? 29 : 28;
            else if (m == 4 || m == 6 || m == 9 || m == 11) days_in_month = 30;
            for (int d = 1; d <= days_in_month && !atomic_load(&g_found); d++) {
                /* YYYYMMDD */
                snprintf(datepw, sizeof(datepw), "%04d%02d%02d", y, m, d);
                if (test_password_fast(datepw)) {
                    if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN);
                    return 1;
                }
                /* MMDDYYYY */
                snprintf(datepw, sizeof(datepw), "%02d%02d%04d", m, d, y);
                if (test_password_fast(datepw)) {
                    if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN);
                    return 1;
                }
                /* DDMMYYYY */
                snprintf(datepw, sizeof(datepw), "%02d%02d%04d", d, m, y);
                if (test_password_fast(datepw)) {
                    if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN);
                    return 1;
                }
                /* Short forms: MMDD, DDMM, YYYY */
                snprintf(datepw, sizeof(datepw), "%02d%02d", m, d);
                if (test_password_fast(datepw)) {
                    if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN);
                    return 1;
                }
                atomic_fetch_add(&g_tested, 4);
            }
        }
        /* Just the year */
        snprintf(datepw, sizeof(datepw), "%04d", y);
        if (test_password_fast(datepw)) {
            if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN);
            return 1;
        }
        atomic_fetch_add(&g_tested, 1);
    }

    /* Phase 3: digits brute-force 1-6 (fast, covers PINs) */
    if (!atomic_load(&g_found)) {
        fprintf(stderr, "  Phase 3: digit-only brute-force (1-6 chars)...\n");
        const char *saved_cs = g_charset;
        int saved_cs_len = g_cs_len;
        void (*saved_fn)(long, int, char *) = g_idx_to_pass;
        g_charset = "0123456789";
        g_cs_len = 10;
        g_idx_to_pass = index_to_pass;

        for (int len = 1; len <= 6 && !atomic_load(&g_found); len++) {
            long total = 1;
            for (int i = 0; i < len; i++) total *= 10;
            atomic_store(&g_tested, 0);
            atomic_store(&g_total, total);
            atomic_store(&g_next_idx, 0);
            int spawned = 0;
            void *(*worker_fn)(void *) = brute_worker;
#ifdef __ARM_NEON
            if (g_use_neon) worker_fn = brute_worker_neon;
#endif
            for (int t = 0; t < nthreads; t++) {
                BruteArg *a = malloc(sizeof(BruteArg));
                *a = (BruteArg){ .id = t, .length = len,
                                 .start = 0, .end = total, .use_shared = 1 };
                pthread_create(&threads[spawned++], NULL, worker_fn, a);
            }
            for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
        }
        g_charset = saved_cs;
        g_cs_len = saved_cs_len;
        g_idx_to_pass = saved_fn;
    }

    *spawned_out = 0;
    return atomic_load(&g_found) ? 1 : 0;
}

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
        if (g_sha256_ctx) {
            /* R5: SHA-256 is so fast the bottleneck is password generation.
             * Benchmark pure GPU throughput with pre-generated passwords. */
            int batch = GPU_BATCH_SIZE;
            const char **pw_ptrs = malloc(sizeof(char *) * (size_t)batch);
            char *pw_storage = malloc((size_t)batch * (MAX_PASS_LEN + 1));
            for (int i = 0; i < batch; i++) {
                char *pw = pw_storage + i * (MAX_PASS_LEN + 1);
                snprintf(pw, MAX_PASS_LEN + 1, "bench%07d", i);
                pw_ptrs[i] = pw;
            }
            long gpu_count = 0;
            t0 = mach_absolute_time();
            for (;;) {
                metal_sha256_verify_batch(g_sha256_ctx, pw_ptrs, batch);
                gpu_count += batch;
                t1 = mach_absolute_time();
                double elapsed = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
                if (elapsed >= BENCH_SECS) break;
            }
            double gpu_secs = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;
            double gpu_rate = gpu_secs > 0 ? (double)gpu_count / gpu_secs : 0;
            fprintf(stderr, "  GPU         : %.0f passwords/sec\n", gpu_rate);
            free(pw_ptrs);
            free(pw_storage);
        } else {
            /* R2-R4 and R6: use worker thread for end-to-end benchmark */
            atomic_store(&g_found, 0);
            atomic_store(&g_tested, 0);
            atomic_store(&g_next_idx, 0);
            spawned = 0;

            GPUBruteArg *ga = malloc(sizeof(GPUBruteArg));
            *ga = (GPUBruteArg){ .length = 7, .total = bench_total };
            void *(*gpu_worker)(void *) = gpu_brute_worker;
            if (g_r6_ctx) gpu_worker = gpu_r6_brute_worker;
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
        }

        /* ── GPU+CPU cooperative benchmark ─────────────────────── */
        if (g_sha256_ctx) {
            /* R5: GPU is so fast that CPU threads just add overhead.
             * Skip cooperative benchmark — GPU alone is optimal. */
            fprintf(stderr, "  GPU+CPU     : (GPU alone is optimal for R5)\n");
        } else {
            atomic_store(&g_found, 0);
            atomic_store(&g_tested, 0);
            atomic_store(&g_next_idx, 0);
            spawned = 0;

            GPUBruteArg *ga2 = malloc(sizeof(GPUBruteArg));
            *ga2 = (GPUBruteArg){ .length = 7, .total = bench_total };
            void *(*gpu_worker2)(void *) = gpu_brute_worker;
            if (g_r6_ctx) gpu_worker2 = gpu_r6_brute_worker;
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
        }
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
    snprintf(h.charset, sizeof(h.charset), "%s", DEFAULT_CHARSET);

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
        snprintf(h.charset, sizeof(h.charset), "%s", "0123456789");
    } else if (buf[0] == '2') {
        snprintf(h.charset, sizeof(h.charset), "%s", "abcdefghijklmnopqrstuvwxyz0123456789");
    } else if (buf[0] == '3') {
        snprintf(h.charset, sizeof(h.charset), "%s", DEFAULT_CHARSET);
    } else if (buf[0] == '4') {
        snprintf(h.charset, sizeof(h.charset), "%s", DEFAULT_CHARSET "!@#$%^&*()-_=+[]{}|;:',.<>?/`~");
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
            h.min_len = (int)strtol(buf, NULL, 10);
            h.max_len = (int)strtol(dash + 1, NULL, 10);
        } else {
            int n = (int)strtol(buf, NULL, 10);
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
 * PDF metadata extraction — extract Author/Title/Subject as seed words
 * ================================================================ */
static int extract_metadata_seeds(const char *pdf_path, char ***words_out)
{
    CFStringRef s = CFStringCreateWithCString(NULL, pdf_path, kCFStringEncodingUTF8);
    CFURLRef url  = CFURLCreateWithFileSystemPath(NULL, s, kCFURLPOSIXPathStyle, 0);
    CFRelease(s);
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(url);
    CFRelease(url);
    if (!doc) return 0;

    /* Try to unlock with empty password to access metadata */
    CGPDFDocumentUnlockWithPassword(doc, "");

    CGPDFDictionaryRef info = CGPDFDocumentGetInfo(doc);
    if (!info) { CGPDFDocumentRelease(doc); return 0; }

    const char *keys[] = { "Title", "Author", "Subject", "Keywords", "Creator" };
    char **seeds = malloc(sizeof(char *) * 256);
    int count = 0;

    for (int k = 0; k < 5 && count < 250; k++) {
        CGPDFStringRef val = NULL;
        if (!CGPDFDictionaryGetString(info, keys[k], &val) || !val) continue;

        CFStringRef cfstr = CGPDFStringCopyTextString(val);
        if (!cfstr) continue;

        char buf[256];
        if (!CFStringGetCString(cfstr, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            CFRelease(cfstr);
            continue;
        }
        CFRelease(cfstr);

        /* Add the full value */
        if (strlen(buf) > 0 && strlen(buf) <= MAX_PASS_LEN) {
            seeds[count++] = strdup(buf);
        }

        /* Split on spaces, commas, semicolons and add individual tokens */
        char tmp[256];
        strncpy(tmp, buf, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char *tok = strtok(tmp, " ,;-_.");
        while (tok && count < 250) {
            if (strlen(tok) >= 2 && strlen(tok) <= MAX_PASS_LEN)
                seeds[count++] = strdup(tok);
            tok = strtok(NULL, " ,;-_.");
        }

        /* Add lowercase variant */
        char lower[256];
        strncpy(lower, buf, sizeof(lower) - 1);
        lower[sizeof(lower) - 1] = '\0';
        for (char *c = lower; *c; c++) *c = (char)tolower((unsigned char)*c);
        if (strlen(lower) > 0 && strlen(lower) <= MAX_PASS_LEN)
            seeds[count++] = strdup(lower);

        /* Add no-spaces variant */
        char nospace[256];
        int j = 0;
        for (int i = 0; buf[i] && j < 255; i++) {
            if (buf[i] != ' ') nospace[j++] = buf[i];
        }
        nospace[j] = '\0';
        if (j > 0 && j <= MAX_PASS_LEN && strcmp(nospace, buf) != 0)
            seeds[count++] = strdup(nospace);
    }

    CGPDFDocumentRelease(doc);
    *words_out = seeds;
    return count;
}

/* ================================================================
 * Filename seed extraction — extract words from PDF filename
 * ================================================================ */
static int extract_filename_seeds(const char *pdf_path, char ***words_out)
{
    /* Get basename */
    const char *base = strrchr(pdf_path, '/');
    base = base ? base + 1 : pdf_path;

    char name[256];
    strncpy(name, base, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    /* Strip .pdf extension */
    size_t nlen = strlen(name);
    if (nlen > 4 && strcasecmp(name + nlen - 4, ".pdf") == 0)
        name[nlen - 4] = '\0';

    char **seeds = malloc(sizeof(char *) * 64);
    int count = 0;
    if (!seeds) { *words_out = NULL; return 0; }

    /* Add full filename (without extension) */
    if (strlen(name) > 0 && strlen(name) <= MAX_PASS_LEN)
        seeds[count++] = strdup(name);

    /* Split on common delimiters */
    char tmp[256];
    strncpy(tmp, name, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *tok = strtok(tmp, " _-.,()[]{}");
    while (tok && count < 56) {
        size_t tlen = strlen(tok);
        if (tlen >= 2 && tlen <= MAX_PASS_LEN) {
            seeds[count++] = strdup(tok);
            /* Lowercase variant */
            char lower[MAX_PASS_LEN + 1];
            for (size_t i = 0; i <= tlen; i++)
                lower[i] = (char)tolower((unsigned char)tok[i]);
            if (strcmp(lower, tok) != 0)
                seeds[count++] = strdup(lower);
        }
        tok = strtok(NULL, " _-.,()[]{}");
    }

    *words_out = seeds;
    return count;
}

/* ================================================================
 * Common first names for pattern attack
 * ================================================================ */
static const char *g_common_names[] = {
    "james","mary","john","patricia","robert","jennifer","michael","linda",
    "david","elizabeth","william","barbara","richard","susan","joseph","jessica",
    "thomas","sarah","christopher","karen","charles","lisa","daniel","nancy",
    "matthew","betty","anthony","margaret","mark","sandra","donald","ashley",
    "steven","kimberly","paul","emily","andrew","donna","joshua","michelle",
    "kenneth","carol","kevin","amanda","brian","dorothy","george","melissa",
    "timothy","deborah","ronald","stephanie","edward","rebecca","jason","sharon",
    "jeffrey","laura","ryan","cynthia","jacob","kathleen","gary","amy",
    "nicholas","angela","eric","shirley","jonathan","anna","stephen","brenda",
    "larry","pamela","justin","emma","scott","nicole","brandon","helen",
    "benjamin","samantha","samuel","katherine","raymond","christine","gregory","debra",
    "frank","rachel","alexander","carolyn","patrick","janet","jack","catherine",
    "dennis","maria","jerry","heather","tyler","diane","aaron","ruth",
    "jose","julie","adam","olivia","nathan","joyce","henry","virginia",
    "peter","victoria","zachary","kelly","douglas","lauren","harold","christina",
    "carl","joan","arthur","evelyn","gerald","judith","roger","megan",
    "keith","andrea","jeremy","cheryl","terry","hannah","sean","jacqueline",
    "austin","martha","albert","gloria","jesse","teresa","willie","ann",
    "christian","sara","bruce","madison","jordan","frances","ralph","kathryn",
    "roy","janice","eugene","jean","randy","abigail","philip","alice",
    "harry","judy","vincent","sophia","bobby","grace","dylan","denise",
    "billy","amber","joe","howard","carlos","marilyn","russell","beverly",
    "alan","theresa","wayne","natalie","elijah","diana",
    NULL
};

/* ================================================================
 * Smart attack: intelligent multi-phase attack
 *
 * Analyzes PDF metadata/filename, generates targeted candidates,
 * then falls through progressively broader strategies.
 * ================================================================ */
static int run_smart_attack(int nthreads, pthread_t *threads, int *spawned_out)
{
    fprintf(stderr, "Mode   : smart (intelligent multi-phase attack)\n");

    /* Collect all seed words from metadata + filename */
    char **meta_seeds = NULL, **file_seeds = NULL;
    int meta_count = extract_metadata_seeds(g_pdf_path, &meta_seeds);
    int file_count = extract_filename_seeds(g_pdf_path, &file_seeds);
    int total_seeds = meta_count + file_count;

    /* Merge seeds into one array */
    char **all_seeds = malloc(sizeof(char *) * (size_t)(total_seeds + 1));
    int seed_count = 0;
    if (all_seeds) {
        for (int i = 0; i < meta_count; i++) all_seeds[seed_count++] = meta_seeds[i];
        for (int i = 0; i < file_count; i++) all_seeds[seed_count++] = file_seeds[i];
    }
    free(meta_seeds);
    free(file_seeds);

    /* ── Phase 0: Metadata + filename seeds (direct) ────────── */
    if (seed_count > 0) {
        fprintf(stderr, "  Phase 0: metadata + filename seeds (%d candidates)...\n", seed_count);
        for (int i = 0; i < seed_count && !atomic_load(&g_found); i++) {
            if (test_password_fast(all_seeds[i])) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, all_seeds[i], MAX_PASS_LEN);
                goto smart_done;
            }
            atomic_fetch_add(&g_tested, 1);
        }
    }

    /* ── Phase 1: Common passwords ──────────────────────────── */
    if (!atomic_load(&g_found)) {
        int n_common = 0;
        for (int i = 0; g_fingerprint_passwords[i]; i++) n_common++;
        fprintf(stderr, "  Phase 1: common passwords (%d)...\n", n_common);
        for (int i = 0; g_fingerprint_passwords[i] && !atomic_load(&g_found); i++) {
            if (test_password_fast(g_fingerprint_passwords[i])) {
                if (!atomic_exchange(&g_found, 1))
                    strncpy(g_password, g_fingerprint_passwords[i], MAX_PASS_LEN);
                goto smart_done;
            }
            atomic_fetch_add(&g_tested, 1);
        }
    }

    /* ── Phase 2: Metadata/filename mutations ───────────────── */
    if (!atomic_load(&g_found) && seed_count > 0) {
        fprintf(stderr, "  Phase 2: seed mutations (%d seeds x ~100 mutations)...\n", seed_count);
        char pw[MAX_PASS_LEN + 1];
        for (int s = 0; s < seed_count && !atomic_load(&g_found); s++) {
            const char *seed = all_seeds[s];
            size_t slen = strlen(seed);
            if (slen == 0 || slen > MAX_PASS_LEN - 4) continue;

            /* Variants: original, capitalized, reversed */
            char variants[3][MAX_PASS_LEN + 1];
            int nvariants = 0;

            strncpy(variants[nvariants++], seed, MAX_PASS_LEN);

            /* Capitalized */
            strncpy(variants[nvariants], seed, MAX_PASS_LEN);
            variants[nvariants][0] = (char)toupper((unsigned char)variants[nvariants][0]);
            if (strcmp(variants[nvariants], seed) != 0) nvariants++;

            /* Reversed */
            reverse_string(seed, variants[nvariants], slen);
            if (strcmp(variants[nvariants], seed) != 0) nvariants++;

            for (int v = 0; v < nvariants && !atomic_load(&g_found); v++) {
                const char *base = variants[v];
                size_t blen = strlen(base);

                /* base + digit 0-9 */
                for (int d = 0; d <= 9 && !atomic_load(&g_found); d++) {
                    snprintf(pw, sizeof(pw), "%s%d", base, d);
                    if (test_password_fast(pw)) {
                        if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN);
                        goto smart_done;
                    }
                    atomic_fetch_add(&g_tested, 1);
                }
                /* base + year 2000-2026 */
                for (int y = 2000; y <= 2026 && !atomic_load(&g_found); y++) {
                    if (blen + 4 > MAX_PASS_LEN) break;
                    snprintf(pw, sizeof(pw), "%s%d", base, y);
                    if (test_password_fast(pw)) {
                        if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN);
                        goto smart_done;
                    }
                    atomic_fetch_add(&g_tested, 1);
                }
                /* base + common suffixes */
                static const char *suffixes[] = { "!", "@", "#", "123", "1234", "!", "1", "12", NULL };
                for (int i = 0; suffixes[i] && !atomic_load(&g_found); i++) {
                    if (blen + strlen(suffixes[i]) > MAX_PASS_LEN) continue;
                    snprintf(pw, sizeof(pw), "%s%s", base, suffixes[i]);
                    if (test_password_fast(pw)) {
                        if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN);
                        goto smart_done;
                    }
                    atomic_fetch_add(&g_tested, 1);
                }
            }
        }
    }

    /* ── Phase 3: Keyboard walks ────────────────────────────── */
    if (!atomic_load(&g_found)) {
        fprintf(stderr, "  Phase 3: keyboard walks...\n");
        typedef char KWEntry[MAX_PASS_LEN + 1];
        KWEntry *kw_walks = malloc(50000 * sizeof(KWEntry));
        if (kw_walks) {
            int nwalks = keywalk_generate(kw_walks, 50000);
            for (int i = 0; i < nwalks && !atomic_load(&g_found); i++) {
                if (test_password_fast(kw_walks[i])) {
                    if (!atomic_exchange(&g_found, 1))
                        strncpy(g_password, kw_walks[i], MAX_PASS_LEN);
                    free(kw_walks);
                    goto smart_done;
                }
                atomic_fetch_add(&g_tested, 1);
            }
            free(kw_walks);
        }
    }

    /* ── Phase 4: Date patterns ─────────────────────────────── */
    if (!atomic_load(&g_found)) {
        fprintf(stderr, "  Phase 4: date patterns (1950-2026)...\n");
        char datepw[16];
        for (int y = 2026; y >= 1950 && !atomic_load(&g_found); y--) {
            for (int m = 1; m <= 12 && !atomic_load(&g_found); m++) {
                int dim = 31;
                if (m == 2) dim = (y % 4 == 0) ? 29 : 28;
                else if (m == 4 || m == 6 || m == 9 || m == 11) dim = 30;
                for (int d = 1; d <= dim && !atomic_load(&g_found); d++) {
                    snprintf(datepw, sizeof(datepw), "%04d%02d%02d", y, m, d);
                    if (test_password_fast(datepw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN); goto smart_done; }
                    snprintf(datepw, sizeof(datepw), "%02d%02d%04d", m, d, y);
                    if (test_password_fast(datepw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN); goto smart_done; }
                    snprintf(datepw, sizeof(datepw), "%02d%02d%04d", d, m, y);
                    if (test_password_fast(datepw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN); goto smart_done; }
                    snprintf(datepw, sizeof(datepw), "%02d%02d", m, d);
                    if (test_password_fast(datepw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN); goto smart_done; }
                    atomic_fetch_add(&g_tested, 4);
                }
            }
            snprintf(datepw, sizeof(datepw), "%04d", y);
            if (test_password_fast(datepw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, datepw, MAX_PASS_LEN); goto smart_done; }
            atomic_fetch_add(&g_tested, 1);
        }
    }

    /* ── Phase 5: Reversed dictionary (if -d provided) ──────── */
    if (!atomic_load(&g_found) && g_words && g_nwords > 0) {
        fprintf(stderr, "  Phase 5: reversed dictionary words (%ld)...\n", g_nwords);
        char rev[MAX_PASS_LEN + 1];
        for (long i = 0; i < g_nwords && !atomic_load(&g_found); i++) {
            size_t wlen = strlen(g_words[i]);
            if (wlen > 0 && wlen <= MAX_PASS_LEN) {
                reverse_string(g_words[i], rev, wlen);
                if (strcmp(rev, g_words[i]) != 0 && test_password_fast(rev)) {
                    if (!atomic_exchange(&g_found, 1))
                        strncpy(g_password, rev, MAX_PASS_LEN);
                    goto smart_done;
                }
            }
            atomic_fetch_add(&g_tested, 1);
        }
    }

    /* ── Phase 6: Common name + year/digit patterns ─────────── */
    if (!atomic_load(&g_found)) {
        int n_names = 0;
        for (int i = 0; g_common_names[i]; i++) n_names++;
        long pattern_est = (long)n_names * (27 + 10 + 3) * 2;
        char num_buf[16];
        fmt_num(pattern_est, num_buf, sizeof(num_buf));
        fprintf(stderr, "  Phase 6: name patterns (%d names, ~%s candidates)...\n",
                n_names, num_buf);
        char pw[MAX_PASS_LEN + 1];
        for (int i = 0; g_common_names[i] && !atomic_load(&g_found); i++) {
            const char *name = g_common_names[i];
            size_t nlen = strlen(name);

            /* Capitalized variant */
            char cap[MAX_PASS_LEN + 1];
            strncpy(cap, name, MAX_PASS_LEN);
            cap[0] = (char)toupper((unsigned char)cap[0]);

            /* name + year, Name + year */
            for (int y = 2000; y <= 2026 && !atomic_load(&g_found); y++) {
                snprintf(pw, sizeof(pw), "%s%d", name, y);
                if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); goto smart_done; }
                snprintf(pw, sizeof(pw), "%s%d", cap, y);
                if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); goto smart_done; }
                atomic_fetch_add(&g_tested, 2);
            }
            /* name + digit, Name + digit */
            for (int d = 0; d <= 9 && !atomic_load(&g_found); d++) {
                snprintf(pw, sizeof(pw), "%s%d", name, d);
                if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); goto smart_done; }
                snprintf(pw, sizeof(pw), "%s%d", cap, d);
                if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); goto smart_done; }
                atomic_fetch_add(&g_tested, 2);
            }
            /* Name + symbol */
            if (nlen + 1 <= MAX_PASS_LEN) {
                snprintf(pw, sizeof(pw), "%s!", cap);
                if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); goto smart_done; }
                snprintf(pw, sizeof(pw), "%s@", cap);
                if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); goto smart_done; }
                snprintf(pw, sizeof(pw), "%s#", cap);
                if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); goto smart_done; }
                atomic_fetch_add(&g_tested, 3);
            }
        }
    }

    /* ── Phase 7: PIN brute-force 1-8 digits ────────────────── */
    if (!atomic_load(&g_found)) {
        fprintf(stderr, "  Phase 7: digit-only brute-force (1-8 chars)...\n");
        const char *saved_cs = g_charset;
        int saved_cs_len = g_cs_len;
        void (*saved_fn)(long, int, char *) = g_idx_to_pass;
        g_charset = "0123456789";
        g_cs_len = 10;
        g_idx_to_pass = index_to_pass;

        for (int len = 1; len <= 8 && !atomic_load(&g_found); len++) {
            long total = 1;
            for (int i = 0; i < len; i++) total *= 10;
            atomic_store(&g_tested, 0);
            atomic_store(&g_total, total);
            atomic_store(&g_next_idx, 0);
            int sp = 0;
            void *(*worker_fn)(void *) = brute_worker;
#ifdef __ARM_NEON
            if (g_use_neon) worker_fn = brute_worker_neon;
#endif
            for (int t = 0; t < nthreads; t++) {
                BruteArg *a = malloc(sizeof(BruteArg));
                *a = (BruteArg){ .id = t, .length = len,
                                 .start = 0, .end = total, .use_shared = 1 };
                pthread_create(&threads[sp++], NULL, worker_fn, a);
            }
            for (int t = 0; t < sp; t++) pthread_join(threads[t], NULL);
        }
        g_charset = saved_cs;
        g_cs_len = saved_cs_len;
        g_idx_to_pass = saved_fn;
    }

    /* ── Phase 8: Alpha-lowercase brute-force 1-6 ──────────── */
    if (!atomic_load(&g_found)) {
        fprintf(stderr, "  Phase 8: lowercase alpha brute-force (1-6 chars)...\n");
        const char *saved_cs = g_charset;
        int saved_cs_len = g_cs_len;
        void (*saved_fn)(long, int, char *) = g_idx_to_pass;
        g_charset = "abcdefghijklmnopqrstuvwxyz";
        g_cs_len = 26;
        g_idx_to_pass = index_to_pass;

        for (int len = 1; len <= 6 && !atomic_load(&g_found); len++) {
            long total = 1;
            for (int i = 0; i < len; i++) total *= 26;
            atomic_store(&g_tested, 0);
            atomic_store(&g_total, total);
            atomic_store(&g_next_idx, 0);
            int sp = 0;
            void *(*worker_fn)(void *) = brute_worker;
#ifdef __ARM_NEON
            if (g_use_neon) worker_fn = brute_worker_neon;
#endif
            for (int t = 0; t < nthreads; t++) {
                BruteArg *a = malloc(sizeof(BruteArg));
                *a = (BruteArg){ .id = t, .length = len,
                                 .start = 0, .end = total, .use_shared = 1 };
                pthread_create(&threads[sp++], NULL, worker_fn, a);
            }
            for (int t = 0; t < sp; t++) pthread_join(threads[t], NULL);
        }
        g_charset = saved_cs;
        g_cs_len = saved_cs_len;
        g_idx_to_pass = saved_fn;
    }

smart_done:
    for (int i = 0; i < seed_count; i++) free(all_seeds[i]);
    free(all_seeds);
    *spawned_out = 0;
    return atomic_load(&g_found) ? 1 : 0;
}

/* ================================================================
 * Pattern attack: structured name-based password patterns
 *
 * Generates candidates from common first names + years/digits/symbols.
 * No wordlist needed — uses built-in name database.
 * ================================================================ */
static int run_pattern_attack(int nthreads, pthread_t *threads, int *spawned_out)
{
    int n_names = 0;
    for (int i = 0; g_common_names[i]; i++) n_names++;

    /* Estimate: per name: 27 years * 2 + 10 digits * 2 + 1000 nums + 3 symbols = ~1077 */
    long pattern_total = (long)n_names * 1077 + 400; /* +400 for name+name combos */
    char nbuf[32];
    fmt_num(pattern_total, nbuf, sizeof(nbuf));
    fprintf(stderr, "Mode   : pattern (%d names, ~%s candidates)\n\n", n_names, nbuf);

    atomic_store(&g_tested, 0);
    atomic_store(&g_total, pattern_total);

    char pw[MAX_PASS_LEN + 1];

    for (int i = 0; g_common_names[i] && !atomic_load(&g_found); i++) {
        const char *name = g_common_names[i];
        size_t nlen = strlen(name);
        char cap[MAX_PASS_LEN + 1];
        strncpy(cap, name, MAX_PASS_LEN);
        cap[0] = (char)toupper((unsigned char)cap[0]);

        /* name + year, Name + year (1990-2026) */
        for (int y = 1990; y <= 2026 && !atomic_load(&g_found); y++) {
            snprintf(pw, sizeof(pw), "%s%d", name, y);
            if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); break; }
            snprintf(pw, sizeof(pw), "%s%d", cap, y);
            if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); break; }
            atomic_fetch_add(&g_tested, 2);
        }
        if (atomic_load(&g_found)) break;

        /* name + 0..999, Name + 0..999 */
        for (int d = 0; d <= 999 && !atomic_load(&g_found); d++) {
            snprintf(pw, sizeof(pw), "%s%d", name, d);
            if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); break; }
            atomic_fetch_add(&g_tested, 1);
        }
        if (atomic_load(&g_found)) break;

        /* Name + symbol */
        if (nlen + 1 <= MAX_PASS_LEN) {
            static const char *syms[] = { "!", "@", "#", "$", "123", "1234", NULL };
            for (int s = 0; syms[s] && !atomic_load(&g_found); s++) {
                if (nlen + strlen(syms[s]) <= MAX_PASS_LEN) {
                    snprintf(pw, sizeof(pw), "%s%s", cap, syms[s]);
                    if (test_password_fast(pw)) { if (!atomic_exchange(&g_found, 1)) strncpy(g_password, pw, MAX_PASS_LEN); break; }
                    atomic_fetch_add(&g_tested, 1);
                }
            }
        }
    }

    /* Top 20 name+name combos */
    if (!atomic_load(&g_found)) {
        int combo_limit = n_names < 20 ? n_names : 20;
        for (int i = 0; i < combo_limit && !atomic_load(&g_found); i++) {
            for (int j = 0; j < combo_limit && !atomic_load(&g_found); j++) {
                if (i == j) continue;
                size_t l1 = strlen(g_common_names[i]);
                size_t l2 = strlen(g_common_names[j]);
                if (l1 + l2 <= MAX_PASS_LEN) {
                    snprintf(pw, sizeof(pw), "%s%s", g_common_names[i], g_common_names[j]);
                    if (test_password_fast(pw)) {
                        if (!atomic_exchange(&g_found, 1))
                            strncpy(g_password, pw, MAX_PASS_LEN);
                        break;
                    }
                    atomic_fetch_add(&g_tested, 1);
                }
            }
        }
    }

    *spawned_out = 0;
    return atomic_load(&g_found) ? 1 : 0;
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
        "  %s -f <pdf> --smart [-d <wordlist>]      intelligent multi-phase attack\n"
        "  %s -f <pdf> --pattern                    name-based pattern attack\n"
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
        "  --combine                   merge and dedup wordlists from remaining args\n"
        "  --prince                    PRINCE attack: combine 2-3 dictionary words (use with -d)\n"
        "  --fingerprint               smart attack: common passwords, dates, PINs first\n"
        "  --max-rounds <N>            R6 GPU max KDF rounds (default 200, min 64)\n"
        "  --dedup                     skip duplicate candidates in rule-based attacks\n"
        "  --show-pot                  display all cracked passwords from pot file and exit\n"
        "  --no-pot                    skip pot file lookup and don't save results\n"
        "  --json                      output results as JSON to stdout\n"
        "  --session <name>            named session for checkpoint management\n"
        "  --session-list              list all saved sessions and exit\n"
        "  --keywalk                   fingerprint attack with keyboard walks\n"
        "  --prince-words              use PRINCE 2-word combos for ?w in masks (use with -d)\n"
        "  --incremental / -I          incremental probability mode (requires -M <model>)\n"
        "  --gpu-batch <N>             override GPU batch size\n"
        "  --pot-file <path>           use custom pot file path\n"
        "  --progress-file <path>      write JSON progress to file (atomic updates)\n"
        "  --combinator <wordlist2>    combinator attack: dict1 x dict2 (use with -d)\n"
        "  --toggle                    toggle-case walk: all case variations of dict words\n"
        "  --dates                     date-based password attack (MMDDYYYY, YYYYMMDD, etc.)\n"
        "  --date-range YYYY-YYYY      year range for --dates (default: 1940-2026)\n"
        "  --mutate                    smart mutations of dict words (use with -d)\n"
        "  --leet                      l33tspeak substitutions of dict words (use with -d)\n"
        "  --metadata-seeds            extract PDF Author/Title/Subject as seed passwords\n"
        "  --smart                     intelligent multi-phase attack (metadata, patterns, PINs, brute)\n"
        "  --reverse                   also try reversed words in dictionary mode (use with -d)\n"
        "  --pattern                   pattern attack using common names + years/digits/symbols\n",
        p, p, p, p, p, p, p, p, p);
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
    int         charset_explicit = 0;
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
        {"max-rounds",       required_argument, NULL, 0x106},
        {"prince",           no_argument,       NULL, 0x107},
        {"fingerprint",      no_argument,       NULL, 0x108},
        {"dedup",            no_argument,       NULL, 0x109},
        {"show-pot",         no_argument,       NULL, 0x10A},
        {"no-pot",           no_argument,       NULL, 0x10B},
        {"json",             no_argument,       NULL, 0x10C},
        {"session",          required_argument, NULL, 0x10D},
        {"session-list",     no_argument,       NULL, 0x10E},
        {"keywalk",          no_argument,       NULL, 0x10F},
        {"prince-words",     no_argument,       NULL, 0x110},
        {"incremental",      no_argument,       NULL, 0x111},
        {"gpu-batch",        required_argument, NULL, 0x112},
        {"pot-file",         required_argument, NULL, 0x113},
        {"progress-file",    required_argument, NULL, 0x114},
        {"combinator",       required_argument, NULL, 0x115},
        {"toggle",           no_argument,       NULL, 0x116},
        {"dates",            no_argument,       NULL, 0x117},
        {"date-range",       required_argument, NULL, 0x118},
        {"mutate",           no_argument,       NULL, 0x119},
        {"leet",             no_argument,       NULL, 0x11A},
        {"metadata-seeds",   no_argument,       NULL, 0x11B},
        {"smart",            no_argument,       NULL, 0x11C},
        {"reverse",          no_argument,       NULL, 0x11D},
        {"pattern",          no_argument,       NULL, 0x11E},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "f:d:bl:c:t:Grim:R::H:BFAOU1:2:3:4:M:I",
                              long_opts, NULL)) != -1) {
        switch (opt) {
            case 'f': pdf_path    = optarg;       break;
            case 'd': dict_path   = optarg;       break;
            case 'b': brute       = 1;            break;
            case 'l': max_len     = safe_atoi(optarg, 1, 127, "-l"); break;
            case 'c': charset     = optarg; charset_explicit = 1; break;
            case 't': nthreads    = safe_atoi(optarg, 1, 256, "-t"); break;
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
                          g_hybrid_suffix_len = safe_atoi(optarg, 1, 32, "-H");
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
            case 0x102: markov_threshold      = safe_atoi(optarg, 1, 256, "--markov-threshold"); break;
            case 0x103: generate_pattern      = optarg; break;
            case 0x104: combine_mode          = 1; break;
            case 0x105: markov_generate_n     = safe_atoi(optarg, 1, 100000000, "--markov-generate"); break;
            case 0x106: g_max_rounds         = safe_atoi(optarg, 1, 100000, "--max-rounds"); break;
            case 0x107: g_prince_mode        = 1;            break;
            case 0x108: g_fingerprint_mode   = 1;            break;
            case 0x109: g_rule_dedup         = 1;            break;
            case 0x10A: g_show_pot          = 1;            break;
            case 0x10B: g_no_pot            = 1;            break;
            case 0x10C: g_json_mode         = 1;            break;
            case 0x10D: strncpy(g_session_name, optarg, sizeof(g_session_name) - 1); g_session_name[sizeof(g_session_name)-1] = 0; break;
            case 0x10E: g_session_list      = 1;            break;
            case 0x10F: g_fingerprint_mode  = 1;            break; /* keywalk → fingerprint mode */
            case 0x110: g_prince_words      = 1;            break;
            case 0x111: g_incremental_mode  = 1;            break;
            case 'I':   g_incremental_mode  = 1;            break;
            case 0x112: g_gpu_batch         = safe_atoi(optarg, 1, 1048576, "--gpu-batch"); break;
            case 0x113: g_custom_pot_path   = optarg;       break;
            case 0x114: g_progress_file     = optarg;       break;
            case 0x115: g_dict2_path        = optarg;       break;
            case 0x116: g_toggle_mode       = 1;            break;
            case 0x117: g_dates_mode       = 1;            break;
            case 0x118: {
                /* Parse YYYY-YYYY range */
                char *dash = strchr(optarg, '-');
                if (!dash) { fprintf(stderr, "--date-range requires YYYY-YYYY format\n"); exit(1); }
                *dash = '\0';
                g_date_year_start = safe_atoi(optarg, 1900, 2100, "--date-range start");
                g_date_year_end   = safe_atoi(dash + 1, 1900, 2100, "--date-range end");
                if (g_date_year_start > g_date_year_end) {
                    fprintf(stderr, "--date-range: start year must be <= end year\n"); exit(1);
                }
                break;
            }
            case 0x119: g_mutate_mode      = 1;            break;
            case 0x11A: g_leet_mode        = 1;            break;
            case 0x11B: g_metadata_seeds   = 1;            break;
            case 0x11C: g_smart_mode      = 1;            break;
            case 0x11D: g_reverse_mode    = 1;            break;
            case 0x11E: g_pattern_mode    = 1;            break;
            default:  usage(argv[0]);
        }
    }

    /* ── Handle standalone utility modes (no PDF needed) ─────── */

    /* Initialize pot file path */
    pot_init();

    /* --show-pot: print pot file and exit */
    if (g_show_pot) {
        pot_show();
        return 0;
    }

    /* --session-list: list sessions and exit */
    if (g_session_list) {
        session_list();
        return 0;
    }

    /* Record start time for JSON output */
    g_start_time = time(NULL);

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
    if (g_rule_mode && !dict_path && !g_mask_mode) {
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

    /* When resuming, peek at checkpoint to determine mode and restore state */
    if (resume) {
        ckpt_make_path(pdf_path);
        Checkpoint peek = ckpt_load();
        if (peek.valid) {
            /* Restore charset from checkpoint if not specified on command line */
            if (peek.charset[0] && !charset_explicit) {
                static char restored_charset[256];
                strncpy(restored_charset, peek.charset, sizeof(restored_charset) - 1);
                charset = restored_charset;
            }
            /* Auto-detect mode if not specified on command line */
            if (!brute && !dict_path && !g_mask_mode && !g_auto_mode) {
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
    }

    /* --prince requires a wordlist */
    if (g_prince_mode && !dict_path) {
        fprintf(stderr, "--prince requires -d <wordlist>\n");
        usage(argv[0]);
    }

    /* --incremental requires a Markov model */
    if (g_incremental_mode && !markov_model_path) {
        fprintf(stderr, "--incremental requires -M <model>\n");
        usage(argv[0]);
    }

    if (!brute && !dict_path && !g_mask_mode && !g_benchmark_mode &&
        !g_auto_mode && !g_prince_mode && !g_fingerprint_mode &&
        !g_incremental_mode && !g_dates_mode && !g_mutate_mode &&
        !g_leet_mode && !g_smart_mode && !g_pattern_mode && !resume) {
        fprintf(stderr, "-d, -b, -m, -A, -B, --prince, --fingerprint, --incremental, --dates, --mutate, --leet, --smart, or --pattern required\n");
        usage(argv[0]);
    }
    if ((g_mutate_mode || g_leet_mode) && !dict_path) {
        fprintf(stderr, "--mutate and --leet require -d <wordlist>\n");
        usage(argv[0]);
    }
    if (g_reverse_mode && !dict_path) {
        fprintf(stderr, "--reverse requires -d <wordlist>\n");
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
    if (brute && g_cs_len == 0) {
        fprintf(stderr, "Error: charset is empty\n");
        return 1;
    }
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

    /* ── Pot file lookup (after parsing encrypt params) ──────── */
    if (g_enc_params.valid && !g_no_pot) {
        char pot_hash[65];
        pot_compute_hash(&g_enc_params, pot_hash);
        char cached_pw[MAX_PASS_LEN + 1];
        if (pot_lookup(pot_hash, cached_pw, sizeof(cached_pw))) {
            if (g_json_mode) {
                char esc_pw[256], esc_path[2048];
                json_escape(cached_pw, esc_pw, sizeof(esc_pw));
                json_escape(pdf_path, esc_path, sizeof(esc_path));
                printf("{\"status\":\"found\",\"password\":\"%s\",\"source\":\"pot\",\"pdf\":\"%s\"}\n",
                       esc_pw, esc_path);
            } else {
                printf("Found in pot file: %s\n", cached_pw);
            }
            return 0;
        }
    }

    /* ── Session checkpoint path override ─────────────────────── */
    if (g_session_name[0])
        session_set_ckpt_path(g_session_name);

    /* ── Select best acceleration engine ─────────────────────── */
    if (g_fast_crypto && !no_gpu && g_enc_params.revision <= 4) {
        /* R2-R4: benchmark GPU, NEON, and scalar to pick the best */
        g_gpu_ctx = metal_keygen_init(&g_enc_params, NULL);
        select_best_engine(nthreads);
    } else if (g_fast_crypto && !no_gpu && g_enc_params.revision == 5) {
        /* R5: full SHA-256 verification on GPU */
        /* check_owner: 0=user, 1=owner, 2=both */
        int check_owner = (g_password_mode == PW_MODE_OWNER) ? 1 :
                           (g_password_mode == PW_MODE_BOTH) ? 2 : 0;
        g_sha256_ctx = metal_sha256_init(&g_enc_params, check_owner, NULL);
        if (g_sha256_ctx)
            g_use_gpu = 1;
    } else if (g_fast_crypto && !no_gpu && g_enc_params.revision == 6) {
        /* R6: full Algorithm 2.B verification on GPU */
        int check_owner = (g_password_mode == PW_MODE_OWNER) ? 1 :
                           (g_password_mode == PW_MODE_BOTH) ? 2 : 0;
        g_r6_ctx = metal_r6_init(&g_enc_params, check_owner, NULL);
        if (g_r6_ctx) {
            g_use_gpu = 1;
            if (g_max_rounds != 200)
                metal_r6_set_max_rounds(g_r6_ctx, g_max_rounds);
        }
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
                "brute-force", "dictionary", "mask", "rule", "hybrid", "auto",
                "prince", "fingerprint"
            };
            const char *label = (ck.attack_mode >= 0 && ck.attack_mode <= 7)
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
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

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
                void *(*dict_fn)(void *) = dict_worker;
#ifdef __ARM_NEON
                if (g_use_neon && g_fast_crypto) dict_fn = dict_worker_neon;
#endif
                for (int t = 0; t < limit; t++) {
                    DictArg *a = malloc(sizeof(DictArg));
                    a->id = t;
                    a->use_shared = g_use_gpu;
                    pthread_create(&threads[spawned++], NULL, dict_fn, a);
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
    if (g_mask_mode && !g_rule_mode) {
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

    /* ── PRINCE + rules hybrid attack ─────────────────────────── */
    else if (g_prince_mode && g_rule_mode && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_PRINCE;
        if (!g_words && !load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }
        if (g_rules_file) load_rules_file(g_rules_file);
        else init_rules();

        /* Compute PRINCE keyspace */
        g_prince_2word_total = g_nwords * g_nwords;
        long prince_3word = g_nwords * g_nwords * g_nwords;
        if (g_nwords > 10000) {
            g_prince_max_words = 2;
            prince_3word = 0;
        }
        g_prince_total = g_prince_2word_total + prince_3word;
        long pr_total = g_prince_total * g_nrules;

        fprintf(stderr, "Mode   : PRINCE + rules (%ld words, %d rules, keyspace %ld)\n\n",
                g_nwords, g_nrules, pr_total);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, pr_total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, prince_rule_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
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

    /* ── Toggle-case walk ────────────────────────────────────────── */
    else if (g_toggle_mode && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_DICT;
        if (!g_words && !load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }

        /* Compute total variants */
        long toggle_total = 0;
        for (long w = 0; w < g_nwords; w++) {
            size_t wlen = strlen(g_words[w]);
            int na = 0;
            for (size_t j = 0; j < wlen && j < MAX_PASS_LEN; j++)
                if (isalpha((unsigned char)g_words[w][j])) na++;
            if (na > 16) na = 16;
            toggle_total += (1L << na);
        }

        fprintf(stderr, "Mode   : toggle-case (%ld words, %ld variants)\n\n",
                g_nwords, toggle_total);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, toggle_total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        if (g_use_gpu && g_sha256_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_sha256_toggle_worker, malloc(1));
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, toggle_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
    }

    /* ── Combinator attack (dict1 x dict2) ────────────────────── */
    else if (g_dict2_path && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_COMBINATOR;
        if (!g_words && !load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }

        /* Load second wordlist */
        FILE *f2 = fopen(g_dict2_path, "r");
        if (!f2) {
            fprintf(stderr, "Cannot open second wordlist: %s\n", g_dict2_path);
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }
        long cap2 = 10000;
        g_words2 = malloc(sizeof(char *) * cap2);
        g_nwords2 = 0;
        char ln2[MAX_PASS_LEN + 4];
        while (fgets(ln2, sizeof(ln2), f2)) {
            size_t len2 = strlen(ln2);
            while (len2 && (ln2[len2-1] == '\n' || ln2[len2-1] == '\r')) ln2[--len2] = '\0';
            if (!len2) continue;
            if (g_nwords2 >= cap2) {
                cap2 *= 2;
                g_words2 = realloc(g_words2, sizeof(char *) * cap2);
            }
            g_words2[g_nwords2++] = strdup(ln2);
        }
        fclose(f2);

        long combo_total = g_nwords * g_nwords2;
        fprintf(stderr, "Mode   : combinator (%ld x %ld = %ld combos)\n\n",
                g_nwords, g_nwords2, combo_total);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, combo_total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        if (g_use_gpu && g_sha256_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_sha256_combinator_worker, malloc(1));
        } else if (g_use_gpu && g_r6_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_r6_combinator_worker, malloc(1));
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, combinator_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
        for (long i = 0; i < g_nwords2; i++) free(g_words2[i]);
        free(g_words2);
    }

    /* ── Mask+rules hybrid attack ─────────────────────────────── */
    else if (g_mask_mode && g_rule_mode) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_MASK_RULE;

        if (!g_rules_file)
            init_rules();
        else
            load_rules_file(g_rules_file);

        long total = g_mask_keyspace * g_nrules;
        fprintf(stderr, "Mode   : mask+rules (\"%s\" x %d rules, keyspace %ld)\n\n",
                g_mask_str, g_nrules, total);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        if (g_use_gpu && g_sha256_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_sha256_mask_rule_worker, malloc(1));
        } else if (g_use_gpu && g_r6_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_r6_mask_rule_worker, malloc(1));
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, mask_rule_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
    }

    /* ── PRINCE attack (word combinations) ──────────────────────── */
    else if (g_prince_mode && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_PRINCE;
        if (!g_words && !load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }

        /* Compute keyspace: nwords^2 + nwords^3 */
        g_prince_2word_total = g_nwords * g_nwords;
        long prince_3word = g_nwords * g_nwords * g_nwords;
        /* Overflow check */
        if (g_nwords > 10000) {
            g_prince_max_words = 2;
            prince_3word = 0;
            fprintf(stderr, "Note: wordlist >10K words, limiting to 2-word combinations\n");
        }
        g_prince_total = g_prince_2word_total + prince_3word;

        fprintf(stderr, "Mode   : PRINCE (%ld words, %s combos, keyspace %ld)\n\n",
                g_nwords,
                g_prince_max_words >= 3 ? "2+3 word" : "2 word",
                g_prince_total);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, g_prince_total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, prince_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
    }

    /* ── Fingerprint attack (smart patterns) ─────────────────── */
    else if (g_fingerprint_mode) {
        g_is_brute = 1;
        g_attack_mode = ATTACK_FINGERPRINT;

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, 0); /* unknown total */

        run_fingerprint_attack(nthreads, threads, &spawned);
    }

    /* ── Smart attack (intelligent multi-phase) ──────────────── */
    else if (g_smart_mode) {
        g_is_brute = 1;
        g_attack_mode = ATTACK_SMART;

        /* Load wordlist if provided (used in Phase 5: reversed dict) */
        if (dict_path && !g_words) {
            load_wordlist(dict_path);
        }

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, 0); /* unknown total — multi-phase */

        run_smart_attack(nthreads, threads, &spawned);

        if (g_words) {
            for (long i = 0; i < g_nwords; i++) free(g_words[i]);
            free(g_words);
            g_words = NULL;
            g_nwords = 0;
        }
    }

    /* ── Pattern attack (common name patterns) ───────────────── */
    else if (g_pattern_mode) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_PATTERN;

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, 0);

        run_pattern_attack(nthreads, threads, &spawned);
    }

    /* ── Incremental (Markov probability order) attack ─────────── */
    else if (g_incremental_mode && g_markov) {
        g_is_brute = 1;
        g_attack_mode = ATTACK_INCREMENTAL;

        int effective_cs = g_markov->threshold < g_markov->charset_size
                         ? g_markov->threshold : g_markov->charset_size;

        /* Try to resume from incremental checkpoint */
        char incr_path[1040];
        snprintf(incr_path, sizeof(incr_path), "%s.incr", g_ckpt_path);
        int resumed = 0;
        if (resume && g_ckpt_path[0]) {
            resumed = incr_heap_load(incr_path);
            if (resumed)
                fprintf(stderr, "Mode   : incremental (Markov, len 1-%d, %d chars/pos) [resuming, %ld tested]\n\n",
                        MAX_PASS_LEN, effective_cs, atomic_load(&g_tested));
        }
        if (!resumed) {
            atomic_store(&g_tested, 0);
            fprintf(stderr, "Mode   : incremental (Markov, len 1-%d, %d chars/pos)\n\n",
                    MAX_PASS_LEN, effective_cs);
        }
        atomic_store(&g_total, 0); /* unknown total — incremental */

        /* Reset ring buffer state */
        g_incr_head = 0;
        g_incr_tail = 0;
        g_incr_done = 0;

        /* Spawn producer */
        pthread_t producer;
        pthread_create(&producer, NULL, incr_producer_thread, NULL);

        /* Spawn consumer workers */
        spawned = 0;
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, incr_consumer_worker, a);
        }

        /* Wait for consumers */
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        /* Signal producer to stop if still running */
        atomic_store(&g_found, 1);
        pthread_mutex_lock(&g_incr_mutex);
        pthread_cond_signal(&g_incr_not_full);
        pthread_mutex_unlock(&g_incr_mutex);
        pthread_join(producer, NULL);

        /* Save incremental state for resume (if not found) */
        if (!g_password[0] && g_ckpt_path[0])
            incr_heap_save(incr_path);

        /* Free global heap */
        if (g_incr_heap) {
            heap_free(g_incr_heap);
            free(g_incr_heap);
            g_incr_heap = NULL;
        }
    }

    /* ── Date-based attack ────────────────────────────────────── */
    else if (g_dates_mode) {
        g_is_brute = 1;
        g_attack_mode = ATTACK_DATES;

        long dates_total = dates_compute_keyspace();
        char nbuf[32];
        fmt_num(dates_total, nbuf, sizeof(nbuf));
        fprintf(stderr, "Mode   : dates (%d-%d, %s candidates)\n\n",
                g_date_year_start, g_date_year_end, nbuf);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, dates_total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        if (g_use_gpu && g_sha256_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_sha256_dates_worker, malloc(1));
        } else if (g_use_gpu && g_r6_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_r6_dates_worker, malloc(1));
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, dates_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);
    }

    /* ── Smart mutations attack ───────────────────────────────── */
    else if (g_mutate_mode && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_MUTATE;
        if (!g_words && !load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }

        long mutate_total = g_nwords * MUTATE_NMUTATIONS;
        char nbuf[32];
        fmt_num(mutate_total, nbuf, sizeof(nbuf));
        fprintf(stderr, "Mode   : mutate (%ld words x %d mutations = %s candidates)\n\n",
                g_nwords, MUTATE_NMUTATIONS, nbuf);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, mutate_total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        if (g_use_gpu && g_sha256_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_sha256_mutate_worker, malloc(1));
        } else if (g_use_gpu && g_r6_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_r6_mutate_worker, malloc(1));
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, mutate_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        for (long i = 0; i < g_nwords; i++) free(g_words[i]);
        free(g_words);
    }

    /* ── L33tspeak substitutions attack ───────────────────────── */
    else if (g_leet_mode && dict_path) {
        g_is_brute = 0;
        g_attack_mode = ATTACK_LEET;
        if (!g_words && !load_wordlist(dict_path)) {
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }

        /* Precompute leet substitution info per word */
        leet_precompute();
        if (!g_leet_info) {
            fprintf(stderr, "Failed to allocate leet info\n");
            atomic_store(&g_found, 1);
            pthread_join(prog, NULL);
            return 1;
        }

        char nbuf[32];
        fmt_num(g_leet_total, nbuf, sizeof(nbuf));
        fprintf(stderr, "Mode   : leet (%ld words, %s variants)\n\n",
                g_nwords, nbuf);

        atomic_store(&g_tested, 0);
        atomic_store(&g_total, g_leet_total);
        atomic_store(&g_next_idx, 0);
        spawned = 0;

        if (g_use_gpu && g_sha256_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_sha256_leet_worker, malloc(1));
        } else if (g_use_gpu && g_r6_ctx) {
            pthread_create(&threads[spawned++], NULL, gpu_r6_leet_worker, malloc(1));
        }
        for (int t = 0; t < nthreads; t++) {
            void *a = malloc(1);
            pthread_create(&threads[spawned++], NULL, leet_worker, a);
        }
        for (int t = 0; t < spawned; t++) pthread_join(threads[t], NULL);

        free(g_leet_info);
        g_leet_info = NULL;
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

        /* Inject PDF metadata as seed words if requested */
        if (g_metadata_seeds) {
            char **meta_words = NULL;
            int meta_count = extract_metadata_seeds(pdf_path, &meta_words);
            if (meta_count > 0) {
                /* Prepend metadata seeds to wordlist (checked first) */
                long new_total = g_nwords + meta_count;
                char **merged = malloc(sizeof(char *) * (size_t)new_total);
                if (merged) {
                    for (int i = 0; i < meta_count; i++)
                        merged[i] = meta_words[i];
                    for (long i = 0; i < g_nwords; i++)
                        merged[meta_count + i] = g_words[i];
                    free(g_words);
                    g_words = merged;
                    g_nwords = new_total;
                    fprintf(stderr, "Metadata: added %d seed words from PDF metadata\n",
                            meta_count);
                }
            }
            free(meta_words);
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
        void *(*dict_fn)(void *) = dict_worker;
#ifdef __ARM_NEON
        if (g_use_neon && g_fast_crypto) dict_fn = dict_worker_neon;
#endif
        for (int t = 0; t < limit; t++) {
            DictArg *a = malloc(sizeof(DictArg));
            a->id = t;
            a->use_shared = g_use_gpu;
            pthread_create(&threads[spawned++], NULL, dict_fn, a);
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
    if (!g_json_mode) fputs("\n\n", stderr);

    if (g_gpu_ctx) metal_keygen_free(g_gpu_ctx);
    if (g_sha256_ctx) metal_sha256_free(g_sha256_ctx);

    /* Mode name for JSON output */
    static const char *mode_names[] = {
        "brute", "dict", "mask", "rule", "hybrid", "auto", "prince", "fingerprint",
        "combinator", "mask_rule", "incremental", "dates", "mutate", "leet",
        "smart", "pattern"
    };
    const char *cur_mode_name = (g_attack_mode >= 0 && g_attack_mode <= 13)
                                ? mode_names[g_attack_mode] : "unknown";
    long final_tested = atomic_load(&g_tested);
    long final_elapsed = (long)(time(NULL) - g_start_time);
    if (final_elapsed < 1) final_elapsed = 1;
    long final_rate = final_tested / final_elapsed;

    /* If interrupted during work, save checkpoint and exit */
    if (g_interrupted) {
        ckpt_save();
        if (g_json_mode) {
            char esc_ckpt[2048];
            json_escape(g_ckpt_path, esc_ckpt, sizeof(esc_ckpt));
            printf("{\"status\":\"interrupted\",\"tested\":%ld,\"checkpoint\":\"%s\"}\n",
                   final_tested, esc_ckpt);
        } else {
            fprintf(stderr, "Checkpoint saved to %s (use -r to resume)\n", g_ckpt_path);
        }
        return 1;
    }

    if (g_password[0]) {
        /* ── Write to pot file ──────────────────────────────────── */
        if (g_enc_params.valid && !g_no_pot) {
            char pot_hash[65];
            pot_compute_hash(&g_enc_params, pot_hash);
            pot_append(pot_hash, g_password);
        }

        if (g_json_mode) {
            char esc_pw[256], esc_path[2048];
            json_escape(g_password, esc_pw, sizeof(esc_pw));
            json_escape(pdf_path, esc_path, sizeof(esc_path));
            printf("{\"status\":\"found\",\"password\":\"%s\",\"type\":\"%s\","
                   "\"tested\":%ld,\"elapsed\":%ld,\"rate\":%ld,"
                   "\"mode\":\"%s\",\"pdf\":\"%s\",\"revision\":%d}\n",
                   esc_pw, g_found_type ? g_found_type : "Unknown",
                   final_tested, final_elapsed, final_rate,
                   cur_mode_name, esc_path, g_enc_params.revision);
        } else {
            if (g_found_type)
                printf("%s password found: %s\n", g_found_type, g_password);
            else
                printf("Password found: %s\n", g_password);
        }
        ckpt_delete();  /* success — remove checkpoint */
        return 0;
    }

    /* Save final checkpoint before exiting (exhausted or interrupted) */
    ckpt_save();

    if (g_json_mode) {
        char esc_path[2048];
        json_escape(pdf_path, esc_path, sizeof(esc_path));
        printf("{\"status\":\"exhausted\",\"tested\":%ld,\"elapsed\":%ld,"
               "\"rate\":%ld,\"mode\":\"%s\",\"pdf\":\"%s\"}\n",
               final_tested, final_elapsed, final_rate,
               cur_mode_name, esc_path);
    } else {
        fprintf(stderr, "Checkpoint saved to %s (use -r to resume)\n", g_ckpt_path);
        printf("Password not found.\n");
    }
    return 1;
}
