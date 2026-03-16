/*
 * test_crypto.c — Validate pdf_encrypt parser + crypto against CGPDFDocument
 *
 * Build:
 *   clang -O3 -framework CoreGraphics -framework Foundation -framework Security \
 *         -o test_crypto test_crypto.c pdf_encrypt.c
 */

#include "pdf_encrypt.h"
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/* Test CGPDFDocument path */
static int cg_test_password(const char *path, const char *pass)
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

int main(int argc, char *argv[])
{
    const char *pdf_path = "test_encrypted.pdf";
    if (argc > 1) pdf_path = argv[1];

    printf("=== PDF Encrypt Parser + Crypto Test ===\n\n");

    /* Parse encryption parameters */
    printf("Parsing: %s\n", pdf_path);
    PDFEncryptParams params = pdf_parse_encrypt_file(pdf_path);

    if (!params.valid) {
        printf("FAIL: parser returned valid=0\n");
        return 1;
    }

    printf("  V=%d  R=%d  KeyLen=%d bits\n", params.version, params.revision,
           params.key_length);
    printf("  P=%d  EncryptMetadata=%d\n", params.permissions,
           params.encrypt_metadata);
    printf("  FileID len=%d\n", params.file_id_len);

    printf("  O=");
    for (int i = 0; i < 16; i++) printf("%02x", params.o_value[i]);
    printf("...\n");

    printf("  U=");
    for (int i = 0; i < 16; i++) printf("%02x", params.u_value[i]);
    printf("...\n\n");

    /* Test passwords: compare our crypto against CGPDFDocument */
    const char *tests[] = {
        "test123",    /* correct user password */
        "owner456",   /* correct owner password */
        "wrong",      /* wrong password */
        "",           /* empty password */
        "abc",        /* wrong */
        "test1234",   /* wrong */
        NULL
    };

    int pass = 0, fail = 0;
    for (int i = 0; tests[i]; i++) {
        int cg_result  = cg_test_password(pdf_path, tests[i]);
        int our_result = pdf_verify_password(&params, tests[i]);

        const char *status;
        if (cg_result == our_result) {
            status = "PASS";
            pass++;
        } else {
            status = "FAIL";
            fail++;
        }
        printf("  %-10s \"%s\" → CG=%d  ours=%d  [%s]\n",
               status, tests[i], cg_result, our_result, status);
    }

    printf("\n%d passed, %d failed\n\n", pass, fail);

    /* Benchmark: our crypto vs CGPDFDocument */
    if (params.valid) {
        const int N = 10000;
        printf("Benchmarking %d password attempts...\n", N);

        /* Our path */
        clock_t t0 = clock();
        for (int i = 0; i < N; i++)
            pdf_verify_user_password(&params, "wrongpassword");
        clock_t t1 = clock();
        double our_time = (double)(t1 - t0) / CLOCKS_PER_SEC;
        printf("  Direct crypto:  %.3f sec  (%d/s)\n",
               our_time, (int)(N / our_time));

        /* CG path */
        t0 = clock();
        for (int i = 0; i < N; i++)
            cg_test_password(pdf_path, "wrongpassword");
        t1 = clock();
        double cg_time = (double)(t1 - t0) / CLOCKS_PER_SEC;
        printf("  CGPDFDocument:  %.3f sec  (%d/s)\n",
               cg_time, (int)(N / cg_time));

        printf("  Speedup: %.1fx\n", cg_time / our_time);
    }

    return fail > 0 ? 1 : 0;
}
