/*
 * metal_keygen.h — GPU-accelerated PDF key derivation via Metal
 *
 * Batches candidate passwords through a Metal compute shader that runs
 * MD5 key derivation (Algorithm 2). The caller then does RC4 verification
 * on the CPU (RC4's S-box is hostile to GPU SIMD).
 */

#ifndef METAL_KEYGEN_H
#define METAL_KEYGEN_H

#include "pdf_encrypt.h"
#include <stdint.h>

/* Opaque handle to Metal pipeline state */
typedef struct MetalKeygenContext MetalKeygenContext;

/*
 * Initialize Metal pipeline for PDF key derivation.
 * Returns NULL if Metal is unavailable or setup fails.
 * The metallib_path should point to the compiled .metallib file,
 * or NULL to search in the same directory as the executable.
 */
MetalKeygenContext *metal_keygen_init(const PDFEncryptParams *params,
                                      const char *metallib_path);

/*
 * Derive encryption keys for a batch of passwords.
 *
 * passwords:    array of null-terminated C strings
 * count:        number of passwords in the batch
 * keys_out:     output buffer, must be at least count * key_bytes bytes
 *               where key_bytes = params->key_length / 8
 *
 * Returns the number of keys generated (== count on success, 0 on error).
 */
int metal_keygen_batch(MetalKeygenContext *ctx,
                       const char **passwords,
                       int count,
                       uint8_t *keys_out);

/*
 * Get the key size in bytes for this context.
 */
int metal_keygen_key_bytes(MetalKeygenContext *ctx);

/*
 * Run a quick benchmark: returns passwords/second throughput for the
 * GPU pipeline (including RC4 verification on CPU).
 * Tests with `bench_count` dummy passwords.
 */
double metal_keygen_benchmark(MetalKeygenContext *ctx, int bench_count);

/*
 * Free all Metal resources.
 */
void metal_keygen_free(MetalKeygenContext *ctx);

/* ── R5 SHA-256 GPU verification ─────────────────────────────── */

/* Opaque handle to R5 SHA-256 Metal pipeline */
typedef struct MetalSHA256Context MetalSHA256Context;

/*
 * Initialize Metal pipeline for R5 SHA-256 password verification.
 * check_owner: 0 = verify user password, 1 = verify owner password.
 * Returns NULL if Metal is unavailable or setup fails.
 */
MetalSHA256Context *metal_sha256_init(const PDFEncryptParams *params,
                                       int check_owner,
                                       const char *metallib_path);

/*
 * Verify a batch of passwords on the GPU using SHA-256 (R5).
 *
 * passwords:    array of null-terminated C strings
 * count:        number of passwords in the batch
 *
 * Returns the index (0-based) of the first matching password,
 * or -1 if no match was found in this batch.
 */
int metal_sha256_verify_batch(MetalSHA256Context *ctx,
                               const char **passwords,
                               int count);

/*
 * Free all Metal resources for the SHA-256 pipeline.
 */
void metal_sha256_free(MetalSHA256Context *ctx);

/* ── R6 GPU verification ────────────────────────────────────── */

/* Opaque handle to R6 Metal pipeline */
typedef struct MetalR6Context MetalR6Context;

/*
 * Initialize Metal pipeline for R6 password verification (Algorithm 2.B).
 * check_owner: 0 = verify user password, 1 = verify owner password.
 * Returns NULL if Metal is unavailable or setup fails.
 */
MetalR6Context *metal_r6_init(const PDFEncryptParams *params,
                               int check_owner,
                               const char *metallib_path);

/*
 * Verify a batch of passwords on the GPU using R6 Algorithm 2.B.
 * Returns the index (0-based) of the first matching password,
 * or -1 if no match was found in this batch.
 */
int metal_r6_verify_batch(MetalR6Context *ctx,
                           const char **passwords,
                           int count);

/*
 * Get max batch size for R6 context.
 */
int metal_r6_max_batch(MetalR6Context *ctx);

/*
 * Free all Metal resources for the R6 pipeline.
 */
void metal_r6_free(MetalR6Context *ctx);

#endif /* METAL_KEYGEN_H */
