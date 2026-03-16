/*
 * saslprep.h — SASLprep (RFC 4013) for PDF 2.0 R6 password normalization
 *
 * Uses macOS CoreFoundation for NFKC normalization.
 */

#ifndef SASLPREP_H
#define SASLPREP_H

#include <stdint.h>
#include <stddef.h>

/*
 * Apply SASLprep normalization to a UTF-8 password.
 * Returns 0 on success, -1 on prohibited/invalid input.
 * out must be at least 128 bytes. out_len receives the byte length.
 * Pure ASCII input passes through unchanged (fast path).
 */
int saslprep(const char *input, size_t input_len, uint8_t *out, size_t *out_len);

#endif /* SASLPREP_H */
