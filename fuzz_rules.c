/*
 * fuzz_rules.c — Fuzzer for pdfcracker rule parser
 *
 * Links against the REAL rule engine (rules.c / rules.h) so any parser
 * bug found here is a bug in production, not in a hand-copied duplicate.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -o fuzz_rules fuzz_rules.c rules.c
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "rules.h"

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
