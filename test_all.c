/*
 * test_all.c — Comprehensive test of pdf_encrypt parser + crypto
 *
 * Build:
 *   clang -O3 -framework CoreGraphics -framework Foundation -framework Security \
 *         -o test_all test_all.c pdf_encrypt.c
 */

#include "pdf_encrypt.h"
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static int cg_test(const char *path, const char *pass)
{
    CFStringRef s = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    CFURLRef url  = CFURLCreateWithFileSystemPath(NULL, s, kCFURLPOSIXPathStyle, 0);
    CFRelease(s);
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(url);
    CFRelease(url);
    if (!doc) return -1;
    int r = CGPDFDocumentUnlockWithPassword(doc, pass);
    CGPDFDocumentRelease(doc);
    return r;
}

typedef struct {
    const char *file;
    const char *user_pass;
    const char *owner_pass;
    const char *description;
    int         expect_unsupported; /* 1 = parser should fail (R5/R6) */
} TestCase;

int main(void)
{
    TestCase cases[] = {
        /* pypdf outputs */
        {"test_r2_40bit.pdf",    "pass40",     "owner40",    "pypdf R2 40-bit",    0},
        {"test_encrypted.pdf",   "test123",    "owner456",   "pypdf R3 128-bit",   0},
        {"test_r4_aes128.pdf",   "passaes",    "owneraes",   "pypdf R4 AES-128",   0},
        {"test_multipage.pdf",   "multipage",  "owner_mp",   "pypdf R3 multipage", 0},
        {"test_r5_aes256.pdf",   "pass256",    "owner256",   "pypdf R5 AES-256",   0},
        /* pikepdf outputs (nested /CF dicts) */
        {"test_xrefstream.pdf",  "user_xref",  "owner_xref", "pikepdf R4 AES",     0},
        {"test_pikepdf_trad.pdf","user_trad",  "owner_trad", "pikepdf R4 trad",    0},
        {"test_pikepdf_r6.pdf",  "user_r6",    "owner_r6",   "pikepdf R6 AES-256", 0},
        {NULL, NULL, NULL, NULL, 0}
    };

    int total_pass = 0, total_fail = 0;

    for (int c = 0; cases[c].file; c++) {
        TestCase *tc = &cases[c];
        printf("━━━ %s (%s) ━━━\n", tc->file, tc->description);

        PDFEncryptParams params = pdf_parse_encrypt_file(tc->file);
        if (!params.valid) {
            if (tc->expect_unsupported) {
                printf("  Parser: unsupported (expected) — OK\n\n");
                total_pass++;
            } else {
                printf("  Parser: FAILED to parse — FAIL\n\n");
                total_fail++;
            }
            continue;
        }

        printf("  V=%d R=%d KeyLen=%d FileID=%d bytes\n",
               params.version, params.revision, params.key_length,
               params.file_id_len);

        /* Test: user password */
        struct { const char *label; const char *pw; } tests[] = {
            {"user",  tc->user_pass},
            {"owner", tc->owner_pass},
            {"wrong", "WRONGPASSWORD"},
            {"empty", ""},
            {NULL, NULL}
        };

        for (int i = 0; tests[i].label; i++) {
            int cg  = cg_test(tc->file, tests[i].pw);
            int our = pdf_verify_password(&params, tests[i].pw);
            int ok  = (cg == our);
            if (ok) total_pass++; else total_fail++;
            printf("  [%s] %-6s \"%s\" → CG=%d ours=%d\n",
                   ok ? "PASS" : "FAIL", tests[i].label, tests[i].pw, cg, our);
        }

        /* Benchmark */
        const int N = 5000;
        clock_t t0 = clock();
        for (int i = 0; i < N; i++)
            pdf_verify_user_password(&params, "wrong");
        double our_s = (double)(clock() - t0) / CLOCKS_PER_SEC;
        t0 = clock();
        for (int i = 0; i < N; i++)
            cg_test(tc->file, "wrong");
        double cg_s = (double)(clock() - t0) / CLOCKS_PER_SEC;
        printf("  Speed: %d/s vs CG %d/s  (%.1fx)\n\n",
               (int)(N/our_s), (int)(N/cg_s), cg_s/our_s);
    }

    /* ── Batch4 cross-validation: NEON SIMD must match scalar ──── */
    printf("━━━ Batch4 NEON vs Scalar cross-validation ━━━\n");
    for (int c = 0; cases[c].file; c++) {
        TestCase *tc = &cases[c];
        PDFEncryptParams params = pdf_parse_encrypt_file(tc->file);
        if (!params.valid || params.revision >= 5) continue;

        const char *pw_user[4]  = { tc->user_pass,  "WRONG1", "WRONG2", "WRONG3" };
        const char *pw_owner[4] = { tc->owner_pass, "WRONG1", "WRONG2", "WRONG3" };
        int ul[4] = { (int)strlen(pw_user[0]),  6, 6, 6 };
        int ol[4] = { (int)strlen(pw_owner[0]), 6, 6, 6 };

        int u_hits = pdf_verify_user_batch4(&params, pw_user, ul);
        int o_hits = pdf_verify_owner_batch4(&params, pw_owner, ol);

        int u_ok = (u_hits & 1) == 1 && (u_hits & 0xE) == 0;
        int o_ok = (o_hits & 1) == 1 && (o_hits & 0xE) == 0;

        if (u_ok) total_pass++; else total_fail++;
        printf("  [%s] %s batch4 user  \"%s\"\n",
               u_ok ? "PASS" : "FAIL", tc->file, tc->user_pass);
        if (o_ok) total_pass++; else total_fail++;
        printf("  [%s] %s batch4 owner \"%s\"\n",
               o_ok ? "PASS" : "FAIL", tc->file, tc->owner_pass);
    }
    printf("\n");

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Total: %d passed, %d failed\n", total_pass, total_fail);
    return total_fail > 0 ? 1 : 0;
}
