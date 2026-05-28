/*
 * checkpoint.h — Checkpoint save/load/delete for pdfcrack
 *
 * Declares the Checkpoint struct, all attack-mode constants, and the
 * four checkpoint functions extracted from pdfcrack.c.  Include this
 * header in any translation unit that calls ckpt_make_path / ckpt_save /
 * ckpt_load / ckpt_delete.
 */

#ifndef CHECKPOINT_H
#define CHECKPOINT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>

/* Maximum password length — must match pdfcrack.c */
#ifndef MAX_PASS_LEN
#define MAX_PASS_LEN 32
#endif

/* ── Attack mode identifiers ─────────────────────────────────── */
#define ATTACK_BRUTE        0
#define ATTACK_DICT         1
#define ATTACK_MASK         2
#define ATTACK_RULE         3
#define ATTACK_HYBRID       4
#define ATTACK_AUTO         5
#define ATTACK_PRINCE       6
#define ATTACK_FINGERPRINT  7
#define ATTACK_COMBINATOR   8
#define ATTACK_MASK_RULE    9
#define ATTACK_INCREMENTAL  10
#define ATTACK_DATES        11
#define ATTACK_MUTATE       12
#define ATTACK_LEET         13
#define ATTACK_SMART        14
#define ATTACK_PATTERN      15

/* ── Password mode ────────────────────────────────────────────── */
#ifndef PW_MODE_BOTH
#define PW_MODE_BOTH  0
#define PW_MODE_USER  1
#define PW_MODE_OWNER 2
#endif

/* ── Checkpoint struct ────────────────────────────────────────── */
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

/* ── Public API ───────────────────────────────────────────────── */

/*
 * ckpt_make_path — derive the checkpoint file path from the PDF path
 * and store it in g_ckpt_path.  Must be called before ckpt_save /
 * ckpt_load / ckpt_delete.
 */
void ckpt_make_path(const char *pdf_path);

/*
 * ckpt_save — atomically write the current crack state to g_ckpt_path.
 * No-op if g_ckpt_path is empty.
 */
void ckpt_save(void);

/*
 * ckpt_load — read state from g_ckpt_path and return a populated
 * Checkpoint struct.  Returns {.valid=0} on error or missing file.
 */
Checkpoint ckpt_load(void);

/*
 * ckpt_delete — remove the checkpoint file.
 */
void ckpt_delete(void);

#endif /* CHECKPOINT_H */
