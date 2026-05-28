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

/* ── Functions defined in pdfcrack.c ────────────────────────────── */
extern int  safe_atoi(const char *s, int min_val, int max_val,
                      const char *name);
extern void incr_heap_save(const char *path);

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

/* ================================================================
 * ckpt_load
 * ================================================================ */
Checkpoint ckpt_load(void)
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
            strncpy(ck.custom_charsets[ci], line + 17,
                    sizeof(ck.custom_charsets[ci]) - 1);
        }
    }
    fclose(f);
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
