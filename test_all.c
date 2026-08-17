/*
 * test_all.c — Comprehensive test of pdf_encrypt parser + crypto
 *
 * Build:
 *   clang -O3 -framework CoreGraphics -framework Foundation -framework Security \
 *         -o test_all test_all.c pdf_encrypt.c
 */

#include "pdf_encrypt.h"
#include "saslprep.h"
#include <CoreGraphics/CoreGraphics.h>
#include <CommonCrypto/CommonDigest.h>
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

    /* ── Batch4 NEON vs Scalar cross-validation (R2–R4 only) ────
     * R5/R6 have no batch4 path; they are validated against
     * CoreGraphics in the main loop above. */
    printf("━━━ Batch4 NEON vs Scalar cross-validation (R2–R4) ━━━\n");
    for (int c = 0; cases[c].file; c++) {
        TestCase *tc = &cases[c];
        PDFEncryptParams params = pdf_parse_encrypt_file(tc->file);
        if (!params.valid || params.revision < 2 || params.revision > 4) continue;

        const char *pw_user[4]  = { tc->user_pass,  "WRONG1", tc->owner_pass, "" };
        const char *pw_owner[4] = { tc->owner_pass, "WRONG1", tc->user_pass,  "" };
        int ul[4], ol[4];
        for (int i = 0; i < 4; i++) { ul[i] = (int)strlen(pw_user[i]); ol[i] = (int)strlen(pw_owner[i]); }

        int u_hits = pdf_verify_user_batch4(&params, pw_user, ul);
        int o_hits = pdf_verify_owner_batch4(&params, pw_owner, ol);

        for (int i = 0; i < 4; i++) {
            int scal_u  = pdf_verify_user_password(&params, pw_user[i]);
            int batch_u = (u_hits >> i) & 1;
            int ok = (scal_u == batch_u);
            if (ok) total_pass++; else total_fail++;
            printf("  [%s] %s user lane %d \"%s\" scalar=%d batch4=%d\n",
                   ok ? "PASS" : "FAIL", tc->file, i, pw_user[i], scal_u, batch_u);

            int scal_o  = pdf_verify_owner_password(&params, pw_owner[i]);
            int batch_o = (o_hits >> i) & 1;
            ok = (scal_o == batch_o);
            if (ok) total_pass++; else total_fail++;
            printf("  [%s] %s owner lane %d \"%s\" scalar=%d batch4=%d\n",
                   ok ? "PASS" : "FAIL", tc->file, i, pw_owner[i], scal_o, batch_o);
        }
    }
    printf("\n");

    /* ── Regression tests for the review-hardening fixes ────────────
     * These exercise behavior CoreGraphics cannot be an oracle for, and
     * that the file+CG cross-check above therefore cannot catch:
     *   #1 nonconforming /Perms must NOT reject a confirmed R5/R6 password
     *   #4 R5 applies SASLprep to the password
     *   #3 R2 key length is pinned to 40-bit regardless of /Length
     * Each asserts the *fixed* behavior, so a future regression fails here. */
    printf("━━━ Regression: review-hardening fixes ━━━\n");

    /* #1 — corrupt /Perms on a real R5/R6 fixture; the correct password must
     * still verify (the primary hash is authoritative, /Perms is advisory). */
    {
        struct { const char *file; const char *pw; } pc[] = {
            {"test_r5_aes256.pdf",  "pass256"},
            {"test_pikepdf_r6.pdf", "user_r6"},
            {NULL, NULL}
        };
        for (int i = 0; pc[i].file; i++) {
            PDFEncryptParams p = pdf_parse_encrypt_file(pc[i].file);
            if (!p.valid) { printf("  [SKIP] %s did not parse\n", pc[i].file); continue; }

            int before = pdf_verify_user_password(&p, pc[i].pw);
            /* Force a /Perms block that the removed hard-gate would reject. */
            p.has_perms = 1; p.has_ue = 1;
            memset(p.perms_value, 0xEE, sizeof(p.perms_value));
            int after = pdf_verify_user_password(&p, pc[i].pw);
            int wrong = pdf_verify_user_password(&p, "definitely_wrong_pw");

            int ok = (before == 1 && after == 1);
            if (ok) total_pass++; else total_fail++;
            printf("  [%s] %-22s correct pw verifies with corrupt /Perms (before=%d after=%d)\n",
                   ok ? "PASS" : "FAIL", pc[i].file, before, after);

            ok = (wrong == 0);
            if (ok) total_pass++; else total_fail++;
            printf("  [%s] %-22s wrong pw still rejected (=%d)\n",
                   ok ? "PASS" : "FAIL", pc[i].file, wrong);
        }
    }

    /* #4 — R5 must SASLprep the password. Build a synthetic R5 /U from the
     * NORMALIZED password, then assert the raw (non-normalized) form verifies. */
    {
        /* Split literal so the \xAD escape can't absorb following hex chars.
         * U+00AD SOFT HYPHEN is deleted by SASLprep → normalizes to "pass256". */
        const char *raw = "pa\xC2\xAD" "ss256";
        uint8_t norm[128]; size_t norm_len = 0;
        if (saslprep(raw, strlen(raw), norm, &norm_len) != 0 || norm_len == 0) {
            printf("  [FAIL] R5 SASLprep: saslprep() failed on test input\n");
            total_fail++;
        } else {
            PDFEncryptParams p; memset(&p, 0, sizeof(p));
            p.valid = 1; p.version = 5; p.revision = 5; p.key_length = 256;
            uint8_t vsalt[8] = {1,2,3,4,5,6,7,8};
            uint8_t ksalt[8] = {9,10,11,12,13,14,15,16};
            CC_SHA256_CTX c; CC_SHA256_Init(&c);
            CC_SHA256_Update(&c, norm, (CC_LONG)norm_len);
            CC_SHA256_Update(&c, vsalt, 8);
            CC_SHA256_Final(p.u_value, &c);
            memcpy(p.u_value + 32, vsalt, 8);
            memcpy(p.u_value + 40, ksalt, 8);
            p.u_value_len = 48;

            int raw_ok  = pdf_verify_user_password(&p, raw);        /* needs SASLprep */
            int norm_ok = pdf_verify_user_password(&p, "pass256");  /* already normal */
            int wrong   = pdf_verify_user_password(&p, "pass255");
            int ok = (raw_ok == 1 && norm_ok == 1 && wrong == 0);
            if (ok) total_pass++; else total_fail++;
            printf("  [%s] R5 SASLprep: raw-form=%d normalized-form=%d wrong=%d\n",
                   ok ? "PASS" : "FAIL", raw_ok, norm_ok, wrong);
        }
    }

    /* #3 — R2 key length is always 40-bit (5 bytes), even if /Length says 128. */
    {
        PDFEncryptParams p; memset(&p, 0, sizeof(p));
        p.valid = 1; p.version = 2; p.revision = 2; p.key_length = 128;
        p.file_id_len = 16;   /* zero-filled ID is fine; only the length matters */
        uint8_t key[16];
        int kb = pdf_compute_encryption_key(&p, "whatever", key);
        int ok = (kb == 5);
        if (ok) total_pass++; else total_fail++;
        printf("  [%s] R2 with /Length 128 → 5-byte key (got %d)\n",
               ok ? "PASS" : "FAIL", kb);
    }
    printf("\n");

    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("Total: %d passed, %d failed\n", total_pass, total_fail);
    return total_fail > 0 ? 1 : 0;
}
