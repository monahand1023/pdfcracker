/*
 * rules.c — Rule engine for pdfcracker (hashcat-compatible mangling rules)
 *
 * Implements parse_rule_op, apply_one_op, apply_rule, load_rules_file,
 * init_rules, add_rule_1, add_rule_2, rule_dedup_check.
 *
 * Linked into pdfcrack, and also directly into the fuzz_rules fuzzer so that
 * fuzzing exercises the real production path.
 */
#include "rules.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* ── Global rule state ───────────────────────────────────────────── */
Rule    g_rules[MAX_RULES];
int     g_nrules  = 0;
int     g_rule_dedup = 0;

static uint64_t g_rule_bloom[65536]; /* 512 KB bloom filter */

/* ── add_rule_1 ──────────────────────────────────────────────────── */
void add_rule_1(RuleType type, char ch, char ch2, int pos)
{
    if (g_nrules >= MAX_RULES) return;
    Rule *r = &g_rules[g_nrules++];
    r->nops = 1;
    r->ops[0] = (RuleOp){ .type = type, .ch = ch, .ch2 = ch2, .pos = pos };
}

/* ── add_rule_2 ──────────────────────────────────────────────────── */
void add_rule_2(RuleType t1, char c1, char c1b, int p1,
                RuleType t2, char c2, char c2b, int p2)
{
    if (g_nrules >= MAX_RULES) return;
    Rule *r = &g_rules[g_nrules++];
    r->nops = 2;
    r->ops[0] = (RuleOp){ .type = t1, .ch = c1, .ch2 = c1b, .pos = p1 };
    r->ops[1] = (RuleOp){ .type = t2, .ch = c2, .ch2 = c2b, .pos = p2 };
}

/* ── parse_rule_op ───────────────────────────────────────────────── */
/* Parse one hashcat-style rule character from *p into rule->ops[rule->nops].
 * Returns number of chars consumed, or 0 on error. */
int parse_rule_op(const char *p, Rule *rule)
{
    if (rule->nops >= MAX_OPS_PER_RULE) return 0;
    RuleOp *op = &rule->ops[rule->nops];
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

/* ── apply_one_op ────────────────────────────────────────────────── */
/* Apply a single rule op in-place on buf[0..len-1]. Returns new length. */
size_t apply_one_op(char *buf, size_t len, const RuleOp *op)
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

/* ── apply_rule ──────────────────────────────────────────────────── */
void apply_rule(const char *word, int rule_idx, char *out)
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

/* ── load_rules_file ─────────────────────────────────────────────── */
/* Load rules from a file (one rule per line, hashcat-compatible) */
int load_rules_file(const char *path)
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

/* ── init_rules ──────────────────────────────────────────────────── */
void init_rules(void)
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

/* ── rule_dedup_check ────────────────────────────────────────────── */
/* Deduplicate rule-generated candidates using a bloom filter.
 * Returns 1 if the password was already seen (skip), 0 if new. */
int rule_dedup_check(const char *pw)
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
