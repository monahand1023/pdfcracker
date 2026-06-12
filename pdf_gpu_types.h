/*
 * pdf_gpu_types.h — GPU parameter structs shared by the host (metal_keygen.m)
 * and the Metal shader (pdf_md5.metal).
 *
 * These structs are written by the CPU and read by the GPU, so their memory
 * layout MUST be identical on both sides. Keeping a single definition here
 * removes the previous hand-duplicated copies (which carried "must match"
 * comments and could silently drift).
 *
 * Fixed-width stdint types are used because Metal (via <metal_stdlib>) and
 * clang both provide them. All fields are naturally aligned, so no packing
 * attribute is needed — packed and unpacked layouts are identical here.
 */

#ifndef PDF_GPU_TYPES_H
#define PDF_GPU_TYPES_H

#ifndef __METAL_VERSION__
#include <stdint.h>
#endif

/* R2–R4: MD5 key-derivation parameters (Algorithm 2). */
typedef struct {
    uint32_t revision;          /* 2, 3, or 4 */
    uint32_t key_bytes;         /* key_length / 8 (5 or 16) */
    int32_t  permissions;       /* /P value (signed) */
    uint32_t encrypt_metadata;  /* 1 or 0 */
    uint32_t file_id_len;
    uint8_t  o_value[32];       /* /O */
    uint8_t  file_id[48];       /* first /ID element */
    uint8_t  padding[32];       /* PDF_PASSWORD_PADDING */
} PDFEncryptGPU;

/* R5: SHA-256 verification parameters (Algorithm 3.2). */
typedef struct {
    uint8_t  u_hash[32];        /* first 32 bytes of U (the target hash) */
    uint8_t  u_salt[8];         /* U[32:40] validation salt */
    uint8_t  o_hash[32];        /* first 32 bytes of O */
    uint8_t  o_salt[8];         /* O[32:40] validation salt */
    uint8_t  u_full[48];        /* full U value (for owner password check) */
    uint32_t check_owner;       /* 1 = verify owner password, 0 = verify user */
} PDFR5GPU;

/* R6: Algorithm 2.B KDF parameters. */
typedef struct {
    uint8_t  target_hash[32];   /* U[0:32] or O[0:32] — comparison target */
    uint8_t  salt[8];           /* validation salt (U[32:40] or O[32:40]) */
    uint8_t  extra[48];         /* extra data: empty for user, U[0:48] for owner */
    uint32_t extra_len;         /* 0 for user, 48 for owner */
    uint32_t max_rounds;        /* safety limit (default 200) */
    uint32_t check_both;        /* 1 = dual mode: try primary, then secondary */
    uint8_t  target_hash2[32];  /* secondary target hash */
    uint8_t  salt2[8];          /* secondary validation salt */
    uint8_t  extra2[48];        /* secondary extra data */
    uint32_t extra_len2;        /* secondary extra length */
    uint32_t _pad;              /* padding for alignment */
} PDFR6GPU;

/* Per-thread R6 scratch size (K1 ~15KB + AES output). Used host- and GPU-side. */
#define R6_SCRATCH_SIZE 16384

#endif /* PDF_GPU_TYPES_H */
