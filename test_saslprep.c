/*
 * test_saslprep.c — Unit tests for saslprep() (RFC 4013)
 *
 * Build (via Makefile):
 *   make test_saslprep
 *   ./test_saslprep
 */

#include "saslprep.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* ================================================================
 * Helper: call saslprep and assert success + exact output
 * ================================================================ */
static void check_pass(const char *label,
                       const char *input, size_t input_len,
                       const char *expected, size_t expected_len)
{
    uint8_t out[128];
    size_t  out_len = 0;
    int rc = saslprep(input, input_len, out, &out_len);
    if (rc != 0) {
        fprintf(stderr, "  FAIL [%s]: expected success, got rc=%d\n", label, rc);
        assert(0);
    }
    if (out_len != expected_len || memcmp(out, expected, out_len) != 0) {
        fprintf(stderr, "  FAIL [%s]: output mismatch (len %zu vs %zu)\n",
                label, out_len, expected_len);
        assert(0);
    }
    printf("  PASS [%s]\n", label);
}

/* ================================================================
 * Helper: call saslprep and assert failure
 * ================================================================ */
static void check_fail(const char *label, const char *input, size_t input_len)
{
    uint8_t out[128];
    size_t  out_len = 0;
    int rc = saslprep(input, input_len, out, &out_len);
    if (rc == 0) {
        fprintf(stderr, "  FAIL [%s]: expected error, got rc=0\n", label);
        assert(0);
    }
    printf("  PASS [%s] (correctly rejected)\n", label);
}

/* ================================================================
 * Test 1: Pure ASCII passthrough
 * ASCII printable input must come out unchanged.
 * ================================================================ */
static void test_ascii_passthrough(void)
{
    printf("test_ascii_passthrough:\n");

    /* Typical alphanumeric password */
    check_pass("hello", "hello", 5, "hello", 5);

    /* Password with symbols */
    check_pass("P@ssw0rd!", "P@ssw0rd!", 9, "P@ssw0rd!", 9);

    /* Single character */
    check_pass("a", "a", 1, "a", 1);

    /* Maximum typical length */
    const char *long_pw = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    size_t      long_len = strlen(long_pw);
    check_pass("long_ascii", long_pw, long_len, long_pw, long_len);
}

/* ================================================================
 * Test 2: Empty string input
 * saslprep() with input_len=0 must succeed and return out_len=0.
 * ================================================================ */
static void test_empty_string(void)
{
    printf("test_empty_string:\n");

    uint8_t out[128];
    size_t  out_len = 99; /* sentinel */
    int rc = saslprep("", 0, out, &out_len);
    if (rc != 0) {
        fprintf(stderr, "  FAIL [empty]: rc=%d\n", rc);
        assert(0);
    }
    if (out_len != 0) {
        fprintf(stderr, "  FAIL [empty]: out_len=%zu, expected 0\n", out_len);
        assert(0);
    }
    printf("  PASS [empty string]\n");
}

/* ================================================================
 * Test 3: Prohibited characters are rejected
 * ASCII control characters (C.2.1: <= 0x001F, 0x007F) are prohibited.
 * ================================================================ */
static void test_prohibited_chars(void)
{
    printf("test_prohibited_chars:\n");

    /* ASCII NUL (0x00) — prohibited C.2.1 */
    check_fail("NUL byte", "\x00", 1);

    /* ASCII DEL (0x7F) — prohibited C.2.1 */
    check_fail("DEL (0x7F)", "\x7F", 1);

    /* ASCII control: BEL (0x07) */
    check_fail("BEL (0x07)", "\x07", 1);

    /* ASCII control: ESC (0x1B) */
    check_fail("ESC (0x1B)", "\x1B", 1);

    /* String with embedded control character */
    check_fail("embedded NUL in string", "pass\x00word", 10);
}

/* ================================================================
 * Test 4: Non-ASCII space characters are mapped to U+0020
 * NO-BREAK SPACE (U+00A0, UTF-8: \xC2\xA0) → ASCII space (0x20)
 * ================================================================ */
static void test_space_mapping(void)
{
    printf("test_space_mapping:\n");

    /* U+00A0 NO-BREAK SPACE → 0x20 */
    /* UTF-8 encoding of U+00A0 is \xC2\xA0 */
    const char nbsp[] = "\xC2\xA0";
    uint8_t out[128];
    size_t  out_len = 0;
    int rc = saslprep(nbsp, 2, out, &out_len);
    if (rc != 0) {
        fprintf(stderr, "  FAIL [nbsp_maps_to_space]: rc=%d\n", rc);
        assert(0);
    }
    if (out_len != 1 || out[0] != 0x20) {
        fprintf(stderr, "  FAIL [nbsp_maps_to_space]: out_len=%zu out[0]=0x%02x\n",
                out_len, out_len > 0 ? out[0] : 0);
        assert(0);
    }
    printf("  PASS [no-break space maps to ASCII space]\n");
}

/* ================================================================
 * Test 5: NULL input pointer
 * saslprep(NULL, ...) must either return 0 with out_len=0 or -1.
 * ================================================================ */
static void test_null_input(void)
{
    printf("test_null_input:\n");

    uint8_t out[128];
    size_t  out_len = 99;
    int rc = saslprep(NULL, 0, out, &out_len);
    /* Either succeeds with empty output, or returns error */
    if (rc == 0) {
        if (out_len != 0) {
            fprintf(stderr, "  FAIL [null_input]: rc=0 but out_len=%zu\n", out_len);
            assert(0);
        }
        printf("  PASS [null input -> empty output]\n");
    } else {
        printf("  PASS [null input -> error]\n");
    }
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    printf("saslprep unit tests\n");
    printf("===================\n");

    test_ascii_passthrough();
    test_empty_string();
    test_prohibited_chars();
    test_space_mapping();
    test_null_input();

    printf("\nAll saslprep tests passed.\n");
    return 0;
}
