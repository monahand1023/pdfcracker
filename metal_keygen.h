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

#endif /* METAL_KEYGEN_H */
