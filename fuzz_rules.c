/*
 * fuzz_rules.c — Fuzzer for pdfcracker rule parser
 * Build: clang -fsanitize=fuzzer,address,undefined -o fuzz_rules fuzz_rules.c
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_PASS_LEN 32
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

/* Exact copy of parse_rule_op() from pdfcrack.c */
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

/* Exact copy of apply_one_op() from pdfcrack.c */
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char line[256];
    if (size > 255) size = 255;
    memcpy(line, data, size);
    line[size] = '\0';

    Rule r;
    memset(&r, 0, sizeof(r));
    const char *p = line;
    while (*p && r.nops < MAX_OPS_PER_RULE) {
        int consumed = parse_rule_op(p, &r);
        if (consumed <= 0) break;
        p += consumed;
    }

    if (r.nops > 0) {
        char out[MAX_PASS_LEN * 2 + 2];
        const char *test_words[] = {"password", "a", "abcdefghijklmnopqrstuvwxyz012345", "", NULL};
        for (int i = 0; test_words[i]; i++) {
            size_t len = strlen(test_words[i]);
            if (len > MAX_PASS_LEN) len = MAX_PASS_LEN;
            memcpy(out, test_words[i], len);
            out[len] = '\0';
            for (int j = 0; j < r.nops; j++) {
                len = apply_one_op(out, len, &r.ops[j]);
            }
            out[len] = '\0';
        }
    }
    return 0;
}
