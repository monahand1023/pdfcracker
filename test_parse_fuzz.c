/* libFuzzer harness for the PDF encrypt parser. ASan/UBSan catch over-reads. */
#include "pdf_encrypt.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *buf = (uint8_t *)malloc(size ? size : 1);
    if (!buf) return 0;
    if (size) memcpy(buf, data, size);
    PDFEncryptParams p = pdf_parse_encrypt(buf, size);
    (void)p;
    free(buf);
    return 0;
}
