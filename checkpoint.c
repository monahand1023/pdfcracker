/*
 * checkpoint.c — Checkpoint save/load/delete (extracted from pdfcrack.c)
 *
 * All state is kept in global variables defined in pdfcrack.c.  The
 * globals required here are declared extern so this translation unit
 * can link against them without duplicating their definitions.
 */

#include "checkpoint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <limits.h>
#include "pdf_encrypt.h"

/* ── Types that checkpoint.c needs from pdfcrack.c ──────────────
 * IncrHeap / IncrEntry are defined in pdfcrack.c.  We only need the
 * pointer — forward-declare the struct so we can take its address.
 * The full definition is not required here.
 * ─────────────────────────────────────────────────────────────── */
typedef struct IncrEntry IncrEntry;
typedef struct {
    IncrEntry *entries;
    int size;
    int capacity;
} IncrHeap;

/* ── Globals defined in pdfcrack.c ─────────────────────────────── */
extern char          g_ckpt_path[1024];
extern int           g_is_brute;
extern int           g_attack_mode;
extern int           g_auto_phase;
extern atomic_long   g_next_idx;
extern atomic_int    g_current_len;
extern const char   *g_charset;
extern long          g_completed_prior;
extern char          g_mask_str[256];
extern int           g_hybrid_suffix_len;
extern int           g_hybrid_mask_mode;
extern char          g_hybrid_mask_str[256];
extern int           g_freq_mode;
extern int           g_password_mode;
extern char          g_custom_charset_str[4][256];
extern char          g_prefix[MAX_PASS_LEN + 1];
extern char          g_suffix[MAX_PASS_LEN + 1];
extern int           g_prefix_len;
extern int           g_suffix_len;
extern char          g_session_name[256];
extern const char   *g_pdf_path;
extern IncrHeap     *g_incr_heap;
extern PDFEncryptParams g_enc_params;

/* ── Functions defined in pdfcrack.c ────────────────────────────── */
extern int  safe_atoi(const char *s, int min_val, int max_val,
                      const char *name);
extern void incr_heap_save(const char *path);

/* ── Single source of truth for attack-mode names + is_brute flag ──
 * Index equals the ATTACK_* id. Drives BOTH save and load so they
 * can never drift apart.
 * ─────────────────────────────────────────────────────────────── */
static const struct { const char *name; int is_brute; } CKPT_MODES[] = {
    [ATTACK_BRUTE]={"brute",1},       [ATTACK_DICT]={"dict",0},
    [ATTACK_MASK]={"mask",1},         [ATTACK_RULE]={"rule",0},
    [ATTACK_HYBRID]={"hybrid",0},     [ATTACK_AUTO]={"auto",0},
    [ATTACK_PRINCE]={"prince",0},     [ATTACK_FINGERPRINT]={"fingerprint",1},
    [ATTACK_COMBINATOR]={"combinator",0}, [ATTACK_MASK_RULE]={"mask_rule",1},
    [ATTACK_INCREMENTAL]={"incremental",1}, [ATTACK_DATES]={"dates",1},
    [ATTACK_MUTATE]={"mutate",0},     [ATTACK_LEET]={"leet",0},
    [ATTACK_SMART]={"smart",1},       [ATTACK_PATTERN]={"pattern",0},
};
#define CKPT_NMODES ((int)(sizeof(CKPT_MODES)/sizeof(CKPT_MODES[0])))

/* Non-exiting integer parse for checkpoint fields.
 * Sets *ok=0 on bad/out-of-range input; returns lo in that case. */
static long ck_atol(const char *s, long lo, long hi, int *ok) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (end == s || errno != 0 || v < lo || v > hi) { *ok = 0; return lo; }
    return v;
}

/* Cheap document identity: FNV-1a 64 over O, U, permissions, file_id.
 * Writes a 16-hex-char string to out.
 * Returns "" (out[0]='\0') if g_enc_params is not valid. */
static void ckpt_fingerprint(char *out, size_t outsz) {
    out[0] = '\0';
    if (!g_enc_params.valid) return;
    unsigned long long h = 1469598103934665603ULL;
    #define FNV_MIX(p, n) do { const unsigned char *_b=(const unsigned char*)(p); \
        for (int _i=0; _i<(int)(n); _i++) { h ^= _b[_i]; h *= 1099511628211ULL; } } while (0)
    FNV_MIX(g_enc_params.o_value, g_enc_params.o_value_len);
    FNV_MIX(g_enc_params.u_value, g_enc_params.u_value_len);
    FNV_MIX(&g_enc_params.permissions, sizeof(g_enc_params.permissions));
    FNV_MIX(g_enc_params.file_id, g_enc_params.file_id_len);
    #undef FNV_MIX
    snprintf(out, outsz, "%016llx", h);
}

/* ================================================================
 * ckpt_make_path
 * ================================================================ */
void ckpt_make_path(const char *pdf_path)
{
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

/* ================================================================
 * ckpt_save
 * ================================================================ */
void ckpt_save(void)
{
    if (!g_ckpt_path[0]) return;
    if (g_attack_mode < 0 || g_attack_mode >= CKPT_NMODES) return;

    /* Save incremental heap FIRST so .ckpt never references a not-yet-durable .incr. */
    if (g_attack_mode == ATTACK_INCREMENTAL && g_incr_heap) {
        char incr_path[1040];
        snprintf(incr_path, sizeof(incr_path), "%s.incr", g_ckpt_path);
        incr_heap_save(incr_path);
    }

    char tmp[1040];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_ckpt_path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;

    fprintf(f, "version=%d\n", CKPT_VERSION);
    { char fp[32]; ckpt_fingerprint(fp, sizeof(fp));
      if (fp[0]) fprintf(f, "pdf_fingerprint=%s\n", fp); }
    fprintf(f, "attack_mode=%s\n", CKPT_MODES[g_attack_mode].name);

    long cur_idx = atomic_load(&g_next_idx);
    fprintf(f, "current_idx=%ld\n", cur_idx);

    if (g_is_brute || g_attack_mode == ATTACK_BRUTE ||
        g_attack_mode == ATTACK_MASK || g_attack_mode == ATTACK_AUTO) {
        int cur_len = atomic_load(&g_current_len);
        fprintf(f, "charset=%s\n", g_charset);
        fprintf(f, "current_len=%d\n", cur_len);
        fprintf(f, "completed_prior=%ld\n", g_completed_prior);
    }
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
    for (int ci = 0; ci < 4; ci++)
        if (g_custom_charset_str[ci][0])
            fprintf(f, "custom_charset_%d=%s\n", ci + 1, g_custom_charset_str[ci]);
    if (g_prefix_len) fprintf(f, "prefix=%s\n", g_prefix);
    if (g_suffix_len) fprintf(f, "suffix=%s\n", g_suffix);
    if (g_session_name[0]) fprintf(f, "session_name=%s\n", g_session_name);
    if (g_pdf_path) fprintf(f, "pdf_path=%s\n", g_pdf_path);

    fflush(f);
    fsync(fileno(f));
    fclose(f);
    if (rename(tmp, g_ckpt_path) != 0) { perror("checkpoint rename"); return; }

    /* fsync the directory so the rename itself is durable across a crash. */
    char dpath[1040];
    snprintf(dpath, sizeof(dpath), "%s", g_ckpt_path);
    char *slash = strrchr(dpath, '/');
    const char *dir;
    if (!slash) dir = ".";
    else if (slash == dpath) dir = "/";
    else { *slash = '\0'; dir = dpath; }
    int dfd = open(dir, O_RDONLY);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
}

/* ================================================================
 * ckpt_load
 * ================================================================ */
Checkpoint ckpt_load(void)
{
    Checkpoint ck = {0};
    ck.attack_mode = -1;
    if (!g_ckpt_path[0]) return ck;

    FILE *f = fopen(g_ckpt_path, "r");
    if (!f) return ck;

    int saw_version = 0, saw_mode = 0, parse_ok = 1;
    char stored_fp[32] = {0};

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strncmp(line, "version=", 8) == 0) {
            int ok = 1;
            long v = ck_atol(line + 8, 0, 1000000, &ok);
            saw_version = (ok && v == CKPT_VERSION);
        } else if (strncmp(line, "attack_mode=", 12) == 0) {
            const char *name = line + 12;
            for (int m = 0; m < CKPT_NMODES; m++) {
                if (CKPT_MODES[m].name && strcmp(name, CKPT_MODES[m].name) == 0) {
                    ck.attack_mode = m;
                    ck.is_brute = CKPT_MODES[m].is_brute;
                    saw_mode = 1;
                    break;
                }
            }
        } else if (strncmp(line, "pdf_fingerprint=", 16) == 0) {
            strncpy(stored_fp, line + 16, sizeof(stored_fp) - 1);
        } else if (strncmp(line, "charset=", 8) == 0) {
            strncpy(ck.charset, line + 8, sizeof(ck.charset) - 1);
        } else if (strncmp(line, "current_len=", 12) == 0) {
            ck.resume_len = (int)ck_atol(line + 12, 0, 127, &parse_ok);
        } else if (strncmp(line, "current_idx=", 12) == 0) {
            ck.resume_idx = ck_atol(line + 12, 0, LONG_MAX, &parse_ok);
            ck.dict_idx = ck.resume_idx;
        } else if (strncmp(line, "completed_prior=", 16) == 0) {
            ck.completed_prior = ck_atol(line + 16, 0, LONG_MAX, &parse_ok);
        } else if (strncmp(line, "prefix=", 7) == 0) {
            strncpy(ck.prefix, line + 7, MAX_PASS_LEN);
            ck.prefix[MAX_PASS_LEN] = '\0';
        } else if (strncmp(line, "suffix=", 7) == 0) {
            strncpy(ck.suffix, line + 7, MAX_PASS_LEN);
            ck.suffix[MAX_PASS_LEN] = '\0';
        } else if (strncmp(line, "mask_pattern=", 13) == 0) {
            strncpy(ck.mask_pattern, line + 13, sizeof(ck.mask_pattern) - 1);
        } else if (strncmp(line, "hybrid_suffix_len=", 18) == 0) {
            ck.hybrid_suffix_len = (int)ck_atol(line + 18, 0, 32, &parse_ok);
        } else if (strncmp(line, "hybrid_mask=", 12) == 0) {
            strncpy(ck.hybrid_mask, line + 12, sizeof(ck.hybrid_mask) - 1);
        } else if (strncmp(line, "auto_phase=", 11) == 0) {
            ck.auto_phase = (int)ck_atol(line + 11, 0, 20, &parse_ok);
        } else if (strncmp(line, "freq_mode=", 10) == 0) {
            ck.freq_mode = (int)ck_atol(line + 10, 0, 1, &parse_ok);
        } else if (strncmp(line, "password_mode=", 14) == 0) {
            ck.password_mode = (int)ck_atol(line + 14, 0, 2, &parse_ok);
        } else if (strncmp(line, "custom_charset_", 15) == 0 &&
                   line[15] >= '1' && line[15] <= '4' && line[16] == '=') {
            int ci = line[15] - '1';
            strncpy(ck.custom_charsets[ci], line + 17,
                    sizeof(ck.custom_charsets[ci]) - 1);
        }
    }
    fclose(f);

    if (!saw_version || !saw_mode || !parse_ok) {
        fprintf(stderr, "Checkpoint invalid (corrupt or wrong version); starting fresh.\n");
        return ck;   /* ck.valid stays 0 → start fresh */
    }

    /* If the checkpoint records a document fingerprint and we know the
     * current document, refuse to resume against a different PDF. */
    if (stored_fp[0] && g_enc_params.valid) {
        char cur_fp[32];
        ckpt_fingerprint(cur_fp, sizeof(cur_fp));
        if (cur_fp[0] && strcmp(cur_fp, stored_fp) != 0) {
            fprintf(stderr, "Checkpoint is for a different document; starting fresh.\n");
            return ck;
        }
    }

    ck.valid = 1;
    return ck;
}

/* ================================================================
 * ckpt_delete
 * ================================================================ */
void ckpt_delete(void)
{
    if (g_ckpt_path[0])
        unlink(g_ckpt_path);
}
