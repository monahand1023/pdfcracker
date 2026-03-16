/*
 * pdf_encrypt.h — PDF encryption parameter extraction and password verification
 *
 * Provides:
 *   1. PDFEncryptParams struct with all values needed for password verification
 *   2. Parser to extract these from raw PDF bytes
 *   3. CPU-side password verification (MD5+RC4 via CommonCrypto)
 *
 * Supports encryption revisions R2, R3, R4 (user password verification).
 * Owner password verification is also supported.
 */

#ifndef PDF_ENCRYPT_H
#define PDF_ENCRYPT_H

#include <stdint.h>
#include <stddef.h>

/* Standard 32-byte PDF password padding (ISO 32000-1, Table 3.18) */
static const uint8_t PDF_PASSWORD_PADDING[32] = {
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
};

typedef struct {
    int      version;           /* /V value (1, 2, 3, 4)              */
    int      revision;          /* /R value (2, 3, 4)                 */
    int      key_length;        /* in bits (40, 56, 64, 80, 96, 128) */
    int32_t  permissions;       /* /P value (signed 32-bit)           */
    uint8_t  o_value[32];       /* /O value (owner password hash)     */
    uint8_t  u_value[32];       /* /U value (user password hash)      */
    uint8_t  file_id[48];       /* first element of /ID array         */
    int      file_id_len;       /* actual length (usually 16 or 32+) */
    int      encrypt_metadata;  /* 1 = encrypt metadata (default), 0 = don't */
    int      valid;             /* 1 if parsing succeeded             */
} PDFEncryptParams;

/*
 * Parse encryption parameters from raw PDF bytes.
 * Returns params with valid=1 on success, valid=0 on failure.
 */
PDFEncryptParams pdf_parse_encrypt(const uint8_t *data, size_t len);

/*
 * Parse encryption parameters from a PDF file on disk.
 */
PDFEncryptParams pdf_parse_encrypt_file(const char *path);

/*
 * Verify a user password against the encryption parameters.
 * Returns 1 if the password is correct, 0 otherwise.
 * Supports R2, R3, R4.
 */
int pdf_verify_user_password(const PDFEncryptParams *params, const char *password);

/*
 * Verify an owner password against the encryption parameters.
 * Returns 1 if the password is correct, 0 otherwise.
 * Supports R2, R3, R4.
 */
int pdf_verify_owner_password(const PDFEncryptParams *params, const char *password);

/*
 * Verify a password as either user or owner.
 * Returns 1 if it matches either, 0 otherwise.
 */
int pdf_verify_password(const PDFEncryptParams *params, const char *password);

/*
 * Compute the encryption key from a user password (Algorithm 2).
 * key_out must be at least params->key_length/8 bytes.
 * Returns key length in bytes.
 */
int pdf_compute_encryption_key(const PDFEncryptParams *params,
                               const char *password,
                               uint8_t *key_out);

#endif /* PDF_ENCRYPT_H */
