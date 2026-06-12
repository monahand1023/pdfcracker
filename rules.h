/*
 * rules.h — Rule engine for pdfcracker (hashcat-compatible mangling rules)
 *
 * Shared between pdfcrack.c and fuzz_rules.c so the fuzzer exercises the
 * real production code path rather than a hand-copied duplicate.
 */
#ifndef RULES_H
#define RULES_H

#include <stddef.h>   /* size_t  */
#include <stdint.h>   /* uint64_t */

/* ── Core password-length constant (used by rule engine and core) ── */
#define MAX_PASS_LEN     32

/* ── Rule storage limits ────────────────────────────────────────── */
#define MAX_RULES        4096
#define MAX_OPS_PER_RULE 8

/* ── Rule operation type ─────────────────────────────────────────── */
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

/* ── Single rule operation ───────────────────────────────────────── */
typedef struct {
    RuleType type;
    char     ch;
    char     ch2;
    int      pos;
} RuleOp;

/* ── Rule = ordered sequence of operations ───────────────────────── */
typedef struct {
    int    nops;
    RuleOp ops[MAX_OPS_PER_RULE];
} Rule;

/* ── Global rule state (defined in rules.c) ─────────────────────── */
extern Rule g_rules[MAX_RULES];
extern int  g_nrules;
extern int  g_rule_dedup;   /* 1 = enable bloom-filter dedup */

/* ── Public API ──────────────────────────────────────────────────── */

/* Add single-op or two-op rule to g_rules[] */
void add_rule_1(RuleType type, char ch, char ch2, int pos);
void add_rule_2(RuleType t1, char c1, char c1b, int p1,
                RuleType t2, char c2, char c2b, int p2);

/* Parse one hashcat-style rule character from *p into rule->ops[rule->nops].
 * Returns number of chars consumed, or 0 on error/unknown opcode. */
int parse_rule_op(const char *p, Rule *rule);

/* Apply a single rule op in-place on buf[0..len-1]. Returns new length. */
size_t apply_one_op(char *buf, size_t len, const RuleOp *op);

/* Apply rule[rule_idx] from g_rules[] to word; result written to out (NUL-terminated). */
void apply_rule(const char *word, int rule_idx, char *out);

/* Load hashcat-style rules file (one rule per line).
 * Populates g_rules[] / g_nrules. Returns 1 on success, 0 on failure. */
int load_rules_file(const char *path);

/* Populate g_rules[] / g_nrules with the built-in default rule set. */
void init_rules(void);

/* Bloom-filter dedup check.
 * Returns 1 if pw was already seen (caller should skip), 0 if new.
 * Always returns 0 when g_rule_dedup == 0. */
int rule_dedup_check(const char *pw);

#endif /* RULES_H */
