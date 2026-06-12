/*
 * pdf_encrypt.c — PDF encryption parameter parser + password verification
 *
 * Parser: Extracts /Encrypt dictionary and /ID from raw PDF bytes.
 *         Handles traditional xref tables and basic xref streams.
 *
 * Crypto: Implements ISO 32000-1 Algorithms 2, 4, 5, 6, 7 using
 *         CommonCrypto (MD5, RC4) — no external dependencies.
 */

/* MD5 is deprecated by Apple for security contexts, but the PDF spec
 * mandates it for R2-R4 password verification. Suppress the warnings. */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#include "pdf_encrypt.h"
#include "saslprep.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
/* MD5 is deprecated by Apple for security contexts, but the PDF spec
 * mandates it for R2-R4 password verification. Suppress the warnings. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#pragma clang diagnostic pop

/* Inline RC4 — replaces CCCrypt for small inputs (16/32 bytes) */
#include "rc4_inline.h"

/* ── PDF crypto constants ────────────────────────────────────── */
#define R3_KEY_ITERATIONS    50  /* MD5 iterations in R3+ key derivation (Alg 2) */
#define R34_RC4_EXTRA_PASSES 19  /* extra RC4 passes in Alg 5 U-check and owner decrypt */

/* NEON SIMD acceleration for SHA-256/384/512 and AES-128-CBC (R6 path) */
#if defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)
#include "sha256_simd.h"
#include "sha512_simd.h"
#endif
#if defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)
#include "aes_simd.h"
#endif

/* ================================================================
 * Helper: scan for a string in PDF data (backward or forward)
 * ================================================================ */
static const uint8_t *find_backward(const uint8_t *data, size_t len,
                                     const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen > len) return NULL;
    for (size_t i = len - nlen; ; i--) {
        if (memcmp(data + i, needle, nlen) == 0)
            return data + i;
        if (i == 0) break;
    }
    return NULL;
}

static const uint8_t *find_forward(const uint8_t *data, size_t len,
                                    const char *needle, size_t start)
{
    size_t nlen = strlen(needle);
    if (start + nlen > len) return NULL;
    for (size_t i = start; i <= len - nlen; i++) {
        if (memcmp(data + i, needle, nlen) == 0)
            return data + i;
    }
    return NULL;
}

/* ================================================================
 * Helper: skip whitespace in PDF data
 * ================================================================ */
static const uint8_t *skip_ws(const uint8_t *p, const uint8_t *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' ||
                       *p == '\n' || *p == '\0'))
        p++;
    return p;
}

/* ================================================================
 * Helper: parse an integer from PDF data
 * ================================================================ */
static long parse_int(const uint8_t *p, const uint8_t *end, const uint8_t **next)
{
    p = skip_ws(p, end);
    int neg = 0;
    if (p < end && *p == '-') { neg = 1; p++; }
    else if (p < end && *p == '+') { p++; }
    long val = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        val = val * 10 + (*p - '0');
        p++;
    }
    if (next) *next = p;
    return neg ? -val : val;
}

/* ================================================================
 * Helper: parse a hex string <...> into bytes
 * ================================================================ */
static int parse_hex_string(const uint8_t *p, const uint8_t *end,
                            uint8_t *out, int max_len, const uint8_t **next)
{
    if (p >= end || *p != '<') return 0;
    p++; /* skip < */

    int n = 0;
    int nibble = -1;
    while (p < end && *p != '>') {
        int c = *p++;
        int v;
        if (c >= '0' && c <= '9')      v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue; /* skip whitespace within hex string */

        if (nibble < 0) {
            nibble = v;
        } else {
            if (n < max_len)
                out[n++] = (uint8_t)((nibble << 4) | v);
            nibble = -1;
        }
    }
    /* Trailing odd nibble: pad with 0 */
    if (nibble >= 0 && n < max_len)
        out[n++] = (uint8_t)(nibble << 4);

    if (p < end && *p == '>') p++;
    if (next) *next = p;
    return n;
}

/* ================================================================
 * Helper: parse a literal string (...) into bytes
 * ================================================================ */
static int parse_literal_string(const uint8_t *p, const uint8_t *end,
                                uint8_t *out, int max_len,
                                const uint8_t **next)
{
    if (p >= end || *p != '(') return 0;
    p++; /* skip ( */

    int n = 0;
    int depth = 1;
    while (p < end && depth > 0) {
        uint8_t c = *p++;
        if (c == '(') {
            depth++;
            if (n < max_len) out[n++] = c;
        } else if (c == ')') {
            depth--;
            if (depth > 0 && n < max_len) out[n++] = c;
        } else if (c == '\\' && p < end) {
            c = *p++;
            switch (c) {
                case 'n':  if (n < max_len) out[n++] = '\n'; break;
                case 'r':  if (n < max_len) out[n++] = '\r'; break;
                case 't':  if (n < max_len) out[n++] = '\t'; break;
                case 'b':  if (n < max_len) out[n++] = '\b'; break;
                case 'f':  if (n < max_len) out[n++] = '\f'; break;
                case '(':  if (n < max_len) out[n++] = '(';  break;
                case ')':  if (n < max_len) out[n++] = ')';  break;
                case '\\': if (n < max_len) out[n++] = '\\'; break;
                default:
                    /* Octal escape */
                    if (c >= '0' && c <= '7') {
                        int oct = c - '0';
                        if (p < end && *p >= '0' && *p <= '7')
                            oct = oct * 8 + (*p++ - '0');
                        if (p < end && *p >= '0' && *p <= '7')
                            oct = oct * 8 + (*p++ - '0');
                        if (n < max_len) out[n++] = (uint8_t)oct;
                    } else {
                        if (n < max_len) out[n++] = c;
                    }
                    break;
            }
        } else {
            if (n < max_len) out[n++] = c;
        }
    }
    if (next) *next = p;
    return n;
}

/* ================================================================
 * Helper: parse a PDF string (hex or literal)
 * ================================================================ */
static int parse_pdf_string(const uint8_t *p, const uint8_t *end,
                            uint8_t *out, int max_len, const uint8_t **next)
{
    p = skip_ws(p, end);
    if (p >= end) return 0;
    if (*p == '<')
        return parse_hex_string(p, end, out, max_len, next);
    if (*p == '(')
        return parse_literal_string(p, end, out, max_len, next);
    return 0;
}

/* ================================================================
 * Helper: find a dictionary key's value within a << ... >> block
 * Returns pointer to the value after the key, or NULL.
 * ================================================================ */
static const uint8_t *find_dict_value(const uint8_t *dict_start,
                                       const uint8_t *end,
                                       const char *key)
{
    size_t klen = strlen(key);
    const uint8_t *p = dict_start;
    int depth = 0; /* track nested << >> */

    while (p < end - klen) {
        /* Track nested dictionaries */
        if (*p == '<' && p + 1 < end && *(p + 1) == '<') {
            depth++;
            p += 2;
            continue;
        }
        if (*p == '>' && p + 1 < end && *(p + 1) == '>') {
            if (depth > 0) {
                depth--;
                p += 2;
                continue;
            }
            break; /* end of our dict */
        }

        /* Only match keys at depth 0 (our dict level) */
        if (depth == 0 && *p == '/') {
            if (memcmp(p + 1, key, klen) == 0) {
                const uint8_t *after = p + 1 + klen;
                if (after < end && (*after == ' ' || *after == '/' ||
                    *after == '<' || *after == '(' || *after == '[' ||
                    *after == '\r' || *after == '\n' || *after == '\t' ||
                    (*after >= '0' && *after <= '9') || *after == '-' ||
                    *after == '+')) {
                    return skip_ws(after, end);
                }
            }
        }
        p++;
    }
    return NULL;
}

/* ================================================================
 * Parse encryption parameters from raw PDF bytes
 * ================================================================ */
PDFEncryptParams pdf_parse_encrypt(const uint8_t *data, size_t len)
{
    PDFEncryptParams params;
    memset(&params, 0, sizeof(params));
    params.encrypt_metadata = 1; /* default */

    /* Minimum viable encrypted PDF is at least ~200 bytes */
    if (!data || len < 64) return params;

    const uint8_t *end = data + len;

    /* ── Find startxref ────────────────────────────────────────── */
    const uint8_t *sxref = find_backward(data, len, "startxref");
    if (!sxref) return params;

    const uint8_t *p = sxref + 9; /* skip "startxref" */
    long xref_offset = parse_int(p, end, &p);
    if (xref_offset < 0 || xref_offset >= (long)len) return params;

    /* ── Find the trailer dictionary ───────────────────────────── */
    /* Try traditional: look for "trailer" after the xref table */
    const uint8_t *trailer = NULL;
    const uint8_t *xref_pos = data + xref_offset;

    if (xref_pos + 4 < end && memcmp(xref_pos, "xref", 4) == 0) {
        /* Traditional xref table — find trailer after it */
        trailer = find_forward(data, len, "trailer", (size_t)(xref_pos - data));
        if (!trailer) return params;
        trailer += 7; /* skip "trailer" */
        trailer = skip_ws(trailer, end);
    } else {
        /* Possibly xref stream (PDF 1.5+).
         * The xref_offset points to an object "N 0 obj << ... >>"
         * The stream dictionary IS the trailer. */
        trailer = find_forward(data, len, "<<", (size_t)(xref_pos - data));
        if (!trailer) return params;
    }

    /* ── Find << that starts the trailer dict ──────────────────── */
    const uint8_t *dict_start = trailer;
    if (dict_start + 1 >= end || *dict_start != '<' || *(dict_start + 1) != '<') {
        dict_start = find_forward(data, len, "<<", (size_t)(trailer - data));
        if (!dict_start) return params;
    }
    dict_start += 2; /* skip << */

    /* Handle /Prev (incremental updates): if this trailer doesn't have
     * /Encrypt, follow /Prev to earlier trailers */
    const uint8_t *encrypt_val = find_dict_value(dict_start, end, "Encrypt");
    const uint8_t *trailer_dict = dict_start; /* the one with /Encrypt */

    if (!encrypt_val) {
        /* Try following /Prev chain (up to 10 hops).
         * /Prev can point to either a traditional xref (with "trailer")
         * or an xref stream object (with dict embedded in the object). */
        const uint8_t *cur_dict = dict_start;
        for (int hop = 0; hop < 10 && !encrypt_val; hop++) {
            const uint8_t *prev_val = find_dict_value(cur_dict, end, "Prev");
            if (!prev_val) break;
            long prev_offset = parse_int(prev_val, end, NULL);
            if (prev_offset <= 0 || prev_offset >= (long)len) break;

            const uint8_t *prev_pos = data + prev_offset;

            /* Try traditional xref first */
            const uint8_t *prev_dict_start = NULL;
            if (prev_pos + 4 < end && memcmp(prev_pos, "xref", 4) == 0) {
                const uint8_t *prev_trailer = find_forward(data, len, "trailer",
                                                           (size_t)(prev_pos - data));
                if (prev_trailer) {
                    prev_trailer += 7;
                    prev_trailer = skip_ws(prev_trailer, end);
                    if (prev_trailer + 2 < end && *prev_trailer == '<' &&
                        *(prev_trailer + 1) == '<')
                        prev_dict_start = prev_trailer + 2;
                }
            } else {
                /* Xref stream — find << after the object header */
                const uint8_t *dd = find_forward(data, len, "<<",
                                                 (size_t)(prev_pos - data));
                if (dd && dd + 2 < end)
                    prev_dict_start = dd + 2;
            }

            if (!prev_dict_start) break;
            cur_dict = prev_dict_start;
            encrypt_val = find_dict_value(cur_dict, end, "Encrypt");
            if (encrypt_val) trailer_dict = cur_dict;
        }
    }

    if (!encrypt_val) return params;

    /* ── Parse /Encrypt — indirect ref (N G R) or inline dict ──── */
    const uint8_t *enc_dict = NULL;

    if (encrypt_val < end && *encrypt_val == '<' &&
        encrypt_val + 1 < end && *(encrypt_val + 1) == '<') {
        /* Inline encrypt dictionary (rare but valid) */
        enc_dict = encrypt_val + 2;
    } else {
        /* Indirect reference: N G R */
        long encrypt_obj_num = parse_int(encrypt_val, end, &p);
        p = skip_ws(p, end);
        long encrypt_gen_num = parse_int(p, end, &p);
        p = skip_ws(p, end);

        /* Try "N G obj" with actual generation number first */
        char obj_header[32];
        snprintf(obj_header, sizeof(obj_header), "%ld %ld obj",
                 encrypt_obj_num, encrypt_gen_num);
        const uint8_t *obj_pos = find_forward(data, len, obj_header, 0);

        /* Fall back to "N 0 obj" if gen was non-zero and not found */
        if (!obj_pos && encrypt_gen_num != 0) {
            snprintf(obj_header, sizeof(obj_header), "%ld 0 obj",
                     encrypt_obj_num);
            obj_pos = find_forward(data, len, obj_header, 0);
        }
        if (!obj_pos) return params;

        /* Find << of the encrypt dictionary */
        const uint8_t *dict_pos = find_forward(data, len, "<<",
                                               (size_t)(obj_pos - data));
        if (!dict_pos) return params;
        enc_dict = dict_pos + 2;
    }

    /* ── Extract encryption values ─────────────────────────────── */
    const uint8_t *val;

    /* /V */
    val = find_dict_value(enc_dict, end, "V");
    if (val) params.version = (int)parse_int(val, end, NULL);

    /* /R */
    val = find_dict_value(enc_dict, end, "R");
    if (val) params.revision = (int)parse_int(val, end, NULL);

    /* /Length (in bits) */
    val = find_dict_value(enc_dict, end, "Length");
    if (val) {
        params.key_length = (int)parse_int(val, end, NULL);
    } else {
        /* Default: 40 bits for V=1, 128 bits for V>=2 */
        params.key_length = (params.version >= 2) ? 128 : 40;
    }

    /* /P (permissions, signed 32-bit) */
    val = find_dict_value(enc_dict, end, "P");
    if (val) params.permissions = (int32_t)parse_int(val, end, NULL);

    /* /O (owner password hash — 32 bytes for R2-4, 48 for R5-6) */
    val = find_dict_value(enc_dict, end, "O");
    if (val) {
        int max_o = (params.revision >= 5) ? 48 : 32;
        params.o_value_len = parse_pdf_string(val, end, params.o_value, max_o, NULL);
    }

    /* /U (user password hash — 32 bytes for R2-4, 48 for R5-6) */
    val = find_dict_value(enc_dict, end, "U");
    if (val) {
        int max_u = (params.revision >= 5) ? 48 : 32;
        params.u_value_len = parse_pdf_string(val, end, params.u_value, max_u, NULL);
    }

    /* R5/R6 additional values */
    if (params.revision >= 5) {
        val = find_dict_value(enc_dict, end, "OE");
        if (val) {
            int n = parse_pdf_string(val, end, params.oe_value, 32, NULL);
            params.has_oe = (n == 32);
        }
        val = find_dict_value(enc_dict, end, "UE");
        if (val) {
            int n = parse_pdf_string(val, end, params.ue_value, 32, NULL);
            params.has_ue = (n == 32);
        }
        val = find_dict_value(enc_dict, end, "Perms");
        if (val) {
            int n = parse_pdf_string(val, end, params.perms_value, 16, NULL);
            params.has_perms = (n == 16);
        }
    }

    /* /EncryptMetadata */
    val = find_dict_value(enc_dict, end, "EncryptMetadata");
    if (val) {
        if (end - val >= 5 && memcmp(val, "false", 5) == 0)
            params.encrypt_metadata = 0;
    }

    /* ── Extract /ID from trailer ──────────────────────────────── */
    /* Try the trailer that has /Encrypt first, then fall back to
     * the main trailer */
    const uint8_t *id_val = find_dict_value(trailer_dict, end, "ID");
    if (!id_val) id_val = find_dict_value(dict_start, end, "ID");
    if (id_val) {
        /* /ID is an array [ <hex1> <hex2> ] — we want the first element */
        id_val = skip_ws(id_val, end);
        if (id_val < end && *id_val == '[') {
            id_val++;
            id_val = skip_ws(id_val, end);
            params.file_id_len = parse_pdf_string(id_val, end, params.file_id,
                                                   48, NULL);
            if (params.file_id_len > 48) params.file_id_len = 48;
        }
    }

    /* ── Validate ──────────────────────────────────────────────── */
    /* Check that O and U were actually parsed (not all zeros) */
    int o_ok = 0, u_ok = 0;
    int check_len = (params.revision >= 5) ? 48 : 32;
    for (int i = 0; i < check_len; i++) {
        if (params.o_value[i]) o_ok = 1;
        if (params.u_value[i]) u_ok = 1;
    }

    if (params.revision >= 5 && params.revision <= 6 && o_ok && u_ok) {
        /* R5/R6 don't need file_id for password verification */
        params.valid = 1;
    } else if (params.revision >= 2 && params.revision <= 4 &&
               params.file_id_len > 0 && o_ok && u_ok) {
        params.valid = 1;
    }

    return params;
}

/* ================================================================
 * Parse from file
 * ================================================================ */
PDFEncryptParams pdf_parse_encrypt_file(const char *path)
{
    PDFEncryptParams params;
    memset(&params, 0, sizeof(params));

    struct stat st;
    if (stat(path, &st) != 0) return params;

    FILE *f = fopen(path, "rb");
    if (!f) return params;

    uint8_t *data = malloc((size_t)st.st_size);
    if (!data) { fclose(f); return params; }

    size_t n = fread(data, 1, (size_t)st.st_size, f);
    fclose(f);

    params = pdf_parse_encrypt(data, n);
    free(data);
    return params;
}

/* ── Helper: 19 additional RC4 passes with XOR-modified keys (16 bytes) ── */
static inline void rc4_multi_pass_16(const uint8_t *key, int key_len,
                                      uint8_t data[16], int start, int end, int step)
{
    for (int r = start; r != end + step; r += step) {
        uint8_t mod_key[16];
        for (int j = 0; j < key_len; j++)
            mod_key[j] = key[j] ^ (uint8_t)r;
        uint8_t temp[16];
        rc4_encrypt_16(mod_key, key_len, data, temp);
        memcpy(data, temp, 16);
    }
}

/* ── Helper: pad or truncate password to 32 bytes per PDF spec ── */
static inline void pad_password(const char *password, uint8_t padded[32])
{
    size_t plen = password ? strlen(password) : 0;
    if (plen > 32) plen = 32;
    if (plen > 0) memcpy(padded, password, plen);
    if (plen < PDF_PASSWORD_PADDING_LEN)
        memcpy(padded + plen, PDF_PASSWORD_PADDING, PDF_PASSWORD_PADDING_LEN - plen);
}

/* ── Helper: compute key-length in bytes, clamped to [5, 16] ──── */
static inline int key_bytes_for(const PDFEncryptParams *p)
{
    int kb = p->key_length / 8;
    if (kb < 5)  kb = 5;
    if (kb > 16) kb = 16;
    return kb;
}

/* ── Helper: serialize permissions as 4 bytes little-endian ───── */
static inline void p_to_le32(int32_t perm, uint8_t out[4])
{
    out[0] = (uint8_t)(perm & 0xFF);
    out[1] = (uint8_t)((perm >> 8) & 0xFF);
    out[2] = (uint8_t)((perm >> 16) & 0xFF);
    out[3] = (uint8_t)((perm >> 24) & 0xFF);
}

/* ── Helper: Algorithm 2 key derivation from a pre-padded 32-byte password ──
 * Shared by pdf_compute_encryption_key and verify_user_with_padded.       */
static int compute_key_from_padded(const PDFEncryptParams *p,
                                    const uint8_t padded[32],
                                    uint8_t key_out[16])
{
    int key_bytes = key_bytes_for(p);

    /* Steps b-f: MD5(padded + O + P(LE) + fileID [+ 0xFFFFFFFF if R>=4 && !meta]) */
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);
    CC_MD5_Update(&md5, padded, 32);
    CC_MD5_Update(&md5, p->o_value, 32);
    uint8_t pb[4];
    p_to_le32(p->permissions, pb);
    CC_MD5_Update(&md5, pb, 4);
    CC_MD5_Update(&md5, p->file_id, (CC_LONG)p->file_id_len);
    if (p->revision >= 4 && !p->encrypt_metadata) {
        uint8_t ff[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        CC_MD5_Update(&md5, ff, 4);
    }
    uint8_t hash[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(hash, &md5);

    /* Step g: For R >= 3, iterate MD5 R3_KEY_ITERATIONS times on first key_bytes */
    if (p->revision >= 3) {
        for (int i = 0; i < R3_KEY_ITERATIONS; i++)
            CC_MD5(hash, (CC_LONG)key_bytes, hash);
    }

    memcpy(key_out, hash, (size_t)key_bytes);
    return key_bytes;
}

/* ================================================================
 * Algorithm 2: Compute encryption key from user password
 * (ISO 32000-1 section 7.6.3.3)
 * ================================================================ */
int pdf_compute_encryption_key(const PDFEncryptParams *params,
                               const char *password,
                               uint8_t *key_out)
{
    uint8_t padded[32];
    pad_password(password, padded);
    return compute_key_from_padded(params, padded, key_out);
}

/* ================================================================
 * Algorithm 4: Compute U value for R=2 (user password check)
 * ================================================================ */
static void compute_u_r2(const uint8_t *key, int key_len,
                         uint8_t *u_out)
{
    /* RC4-encrypt the 32-byte padding string with the key */
    rc4_encrypt(key, key_len, PDF_PASSWORD_PADDING, u_out, PDF_PASSWORD_PADDING_LEN);
}

/* ================================================================
 * Algorithm 5: Compute U value for R=3/R4 (user password check)
 * ================================================================ */
static void compute_u_r3(const PDFEncryptParams *params,
                         const uint8_t *key, int key_len,
                         uint8_t *u_out)
{
    /* (a) MD5 hash of padding + file ID */
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);
    CC_MD5_Update(&md5, PDF_PASSWORD_PADDING, PDF_PASSWORD_PADDING_LEN);
    CC_MD5_Update(&md5, params->file_id, (CC_LONG)params->file_id_len);

    uint8_t hash[16];
    CC_MD5_Final(hash, &md5);

    /* (b) RC4-encrypt the 16-byte hash with the key */
    uint8_t encrypted[16];
    rc4_encrypt_16(key, key_len, hash, encrypted);

    /* (c) R34_RC4_EXTRA_PASSES additional RC4 passes with XOR-modified keys */
    rc4_multi_pass_16(key, key_len, encrypted, 1, R34_RC4_EXTRA_PASSES, 1);

    /* First 16 bytes are the check value, rest is arbitrary */
    memcpy(u_out, encrypted, 16);
}

/* ================================================================
 * Algorithm 2.B: R6 iterative hash (ISO 32000-2 section 7.6.4.3.4)
 *
 * This is the deliberately slow KDF used by R6.
 * Input: password, salt (8 bytes), extra data (0 or 48 bytes for U)
 * Output: 32-byte hash
 * ================================================================ */
static void algorithm_2b(const uint8_t *password, size_t pw_len,
                          const uint8_t *salt, const uint8_t *extra,
                          int extra_len, uint8_t *out)
{
    if (pw_len > 127) return; /* normalize_password_r6 caps at 127; defend the buffers */
    /* Step a: SHA-256(password + salt + extra) */
    uint8_t hash[64]; /* large enough for SHA-512 */

    /* Build initial input for SHA-256 */
    uint8_t init_buf[127 + 8 + 48]; /* max: 127 pw + 8 salt + 48 extra */
    size_t init_len = 0;
    memcpy(init_buf, password, pw_len);
    init_len += pw_len;
    memcpy(init_buf + init_len, salt, 8);
    init_len += 8;
    if (extra_len > 0) {
        memcpy(init_buf + init_len, extra, (size_t)extra_len);
        init_len += (size_t)extra_len;
    }

#if defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)
    sha256_hash_neon(init_buf, init_len, hash);
#else
    CC_SHA256(init_buf, (CC_LONG)init_len, hash);
#endif

    int hash_len = 32; /* starts as SHA-256 */

    /* Step b-e: iterate until round >= 64 and last byte condition met */
    unsigned round = 0;

    /* Pre-allocate scratch buffer on stack to avoid malloc/free per round.
     * Max K1 size = (127 + 64 + 48) * 64 = 15,296 bytes.
     * AES-CBC encrypt is done in-place on K1. */
    uint8_t K1[64 * (127 + 64 + 48)];

    for (;;) {
        /* Step b: Build K1 = (password + hash + extra) repeated 64 times */
        size_t seq_len = pw_len + (size_t)hash_len + (size_t)extra_len;
        uint8_t seq[127 + 64 + 48]; /* max: 127 pw + 64 hash + 48 extra */
        memcpy(seq, password, pw_len);
        memcpy(seq + pw_len, hash, (size_t)hash_len);
        if (extra_len > 0)
            memcpy(seq + pw_len + hash_len, extra, (size_t)extra_len);

        if (seq_len > sizeof(K1) / 64) return;
        size_t K1_len = seq_len * 64;

        /* Doubling memcpy: copy seq once, then double the filled region
         * each iteration (1→2→4→8→16→32→64) instead of 64 individual copies. */
        memcpy(K1, seq, seq_len);
        size_t filled = seq_len;
        while (filled < K1_len) {
            size_t chunk = filled;
            if (chunk > K1_len - filled)
                chunk = K1_len - filled;
            memcpy(K1 + filled, K1, chunk);
            filled += chunk;
        }

        /* Step c: AES-CBC encrypt K1 in-place with key=hash[0:16], iv=hash[16:32] */
        /* K1_len is always a multiple of 16 because seq_len * 64 and the
         * minimum seq_len (pw=0 + hash=32 + extra=0 = 32) is already 16-aligned. */
        size_t aes_len = K1_len;

#if defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)
        {
            uint8x16_t rk[11];
            aes128_expand_key_neon(hash, rk);
            aes128_cbc_encrypt_inplace_rk(rk, hash + 16, K1, K1_len);
        }
#else
        {
            size_t cc_out_len = 0;
            /* CCCrypt supports in-place encryption (src==dst) on macOS */
            CCCrypt(kCCEncrypt, kCCAlgorithmAES, 0,
                    hash, 16, hash + 16,
                    K1, K1_len,
                    K1, K1_len, &cc_out_len);
            aes_len = cc_out_len;
        }
#endif

        /* Step d: Choose hash based on sum of first 16 bytes mod 3 */
        unsigned sum = 0;
        for (int i = 0; i < 16; i++) sum += K1[i];

        switch (sum % 3) {
            case 0:
#if defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)
                sha256_hash_neon(K1, aes_len, hash);
#else
                CC_SHA256(K1, (CC_LONG)aes_len, hash);
#endif
                hash_len = 32;
                break;
            case 1:
#if defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA512)
                sha384_hash_neon(K1, aes_len, hash);
#else
                CC_SHA384(K1, (CC_LONG)aes_len, hash);
#endif
                hash_len = 48;
                break;
            case 2:
#if defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA512)
                sha512_hash_neon(K1, aes_len, hash);
#else
                CC_SHA512(K1, (CC_LONG)aes_len, hash);
#endif
                hash_len = 64;
                break;
        }

        /* Step e: Check termination */
        uint8_t last_byte = K1[aes_len - 1];
        round++;

        if (round >= 64 && last_byte <= (round - 32))
            break;
    }

    memcpy(out, hash, 32);
}

/* ================================================================
 * R5 user password verification (Algorithm 2.A simplified)
 * SHA-256(password + validation_salt) == U[0:32]
 * validation_salt = U[32:40]
 * ================================================================ */
static int verify_user_r5(const PDFEncryptParams *params, const char *password)
{
    if (params->u_value_len < 40) return 0;

    size_t pw_len = password ? strlen(password) : 0;
    if (pw_len > 127) pw_len = 127;

    uint8_t hash[32];
    CC_SHA256_CTX sha256;
    CC_SHA256_Init(&sha256);
    if (pw_len > 0) CC_SHA256_Update(&sha256, (const uint8_t *)password, (CC_LONG)pw_len);
    CC_SHA256_Update(&sha256, params->u_value + 32, 8); /* validation salt */
    CC_SHA256_Final(hash, &sha256);

    return memcmp(hash, params->u_value, 32) == 0;
}

/* ================================================================
 * R5 owner password verification
 * SHA-256(password + validation_salt + U[0:48]) == O[0:32]
 * validation_salt = O[32:40]
 * ================================================================ */
static int verify_owner_r5(const PDFEncryptParams *params, const char *password)
{
    if (params->o_value_len < 40 || params->u_value_len < 48) return 0;

    size_t pw_len = password ? strlen(password) : 0;
    if (pw_len > 127) pw_len = 127;

    uint8_t hash[32];
    CC_SHA256_CTX sha256;
    CC_SHA256_Init(&sha256);
    if (pw_len > 0) CC_SHA256_Update(&sha256, (const uint8_t *)password, (CC_LONG)pw_len);
    CC_SHA256_Update(&sha256, params->o_value + 32, 8); /* validation salt */
    CC_SHA256_Update(&sha256, params->u_value, 48);       /* full U value */
    CC_SHA256_Final(hash, &sha256);

    return memcmp(hash, params->o_value, 32) == 0;
}

/* ── Helper: SASLprep normalization for R6 passwords ─────────── */
static inline void normalize_password_r6(const char *password,
                                          const uint8_t **out_data,
                                          size_t *out_len)
{
    size_t pw_len = password ? strlen(password) : 0;
    if (pw_len > 127) pw_len = 127;
    *out_len = pw_len;
    /* Try SASLprep normalization; fall back to raw password */
    static _Thread_local uint8_t norm_buf[128];
    size_t norm_len = 0;
    if (pw_len > 0 && saslprep(password, pw_len, norm_buf, &norm_len) == 0 && norm_len > 0) {
        *out_data = norm_buf;
        *out_len = norm_len;
    } else {
        *out_data = (const uint8_t *)password;
    }
}

/* ================================================================
 * R6 user password verification (Algorithm 2.A with 2.B hash)
 * Algorithm2B(password, U_validation_salt, "") == U[0:32]
 * ================================================================ */
static int verify_user_r6(const PDFEncryptParams *params, const char *password)
{
    if (params->u_value_len < 40) return 0;

    const uint8_t *pw_data;
    size_t pw_len;
    normalize_password_r6(password, &pw_data, &pw_len);

    uint8_t hash[32];
    algorithm_2b(pw_data, pw_len,
                 params->u_value + 32, /* validation salt */
                 NULL, 0,              /* no extra data for user */
                 hash);

    return memcmp(hash, params->u_value, 32) == 0;
}

/* ================================================================
 * R6 owner password verification
 * Algorithm2B(password, O_validation_salt, U[0:48]) == O[0:32]
 * ================================================================ */
static int verify_owner_r6(const PDFEncryptParams *params, const char *password)
{
    if (params->o_value_len < 40 || params->u_value_len < 48) return 0;

    const uint8_t *pw_data;
    size_t pw_len;
    normalize_password_r6(password, &pw_data, &pw_len);

    uint8_t hash[32];
    algorithm_2b(pw_data, pw_len,
                 params->o_value + 32, /* validation salt */
                 params->u_value, 48,  /* full U as extra data */
                 hash);

    return memcmp(hash, params->o_value, 32) == 0;
}

/* ── Length-safe user verification from an already-padded 32-byte password ──
 * Used by both pdf_verify_user_password (which pads then calls this) and the
 * owner-recovery path (which feeds the raw 32-byte /O decryption result).
 * Eliminates the C-string round-trip that would truncate at embedded NULs. */
static int verify_user_with_padded(const PDFEncryptParams *p, const uint8_t padded[32])
{
    uint8_t key[16];
    int key_bytes = compute_key_from_padded(p, padded, key);

    if (p->revision == 2) {
        uint8_t computed_u[32];
        compute_u_r2(key, key_bytes, computed_u);
        return memcmp(computed_u, p->u_value, 32) == 0;
    }
    /* R3/R4 */
    uint8_t computed_u[16];
    compute_u_r3(p, key, key_bytes, computed_u);
    return memcmp(computed_u, p->u_value, 16) == 0;
}

/* ================================================================
 * Algorithm 6: Verify user password
 * ================================================================ */
int pdf_verify_user_password(const PDFEncryptParams *params, const char *password)
{
    if (!params->valid) return 0;

    if (params->revision == 5) return verify_user_r5(params, password);
    if (params->revision == 6) return verify_user_r6(params, password);

    uint8_t padded[32];
    pad_password(password, padded);
    return verify_user_with_padded(params, padded);
}

/* ================================================================
 * Algorithm 7: Verify owner password
 *
 * Recover the user password from the O value using the owner password,
 * then verify it as a user password.
 * ================================================================ */
static inline void rc4_owner_decrypt(const uint8_t *key, int key_len, uint8_t data[32])
{
    for (int r = R34_RC4_EXTRA_PASSES; r >= 0; r--) {
        uint8_t mod_key[16];
        for (int j = 0; j < key_len; j++)
            mod_key[j] = key[j] ^ (uint8_t)r;
        uint8_t temp[32];
        rc4_encrypt(mod_key, key_len, data, temp, 32);
        memcpy(data, temp, 32);
    }
}

/* ── Helper: recover padded user password from /O using the owner key ────
 * Returns the raw 32-byte padded user password without any C-string
 * conversion, so embedded NUL bytes are preserved (NUL-safe).          */
static void recover_user_password(const uint8_t *o_value, const uint8_t *key,
                                   int key_len, int revision,
                                   uint8_t out_padded[32])
{
    if (revision == 2) {
        /* Single RC4 pass (RC4 is symmetric: encrypt == decrypt) */
        rc4_encrypt(key, key_len, o_value, out_padded, 32);
    } else {
        /* R3/R4: (R34_RC4_EXTRA_PASSES+1) RC4 passes in reverse (19 down to 0) */
        memcpy(out_padded, o_value, 32);
        rc4_owner_decrypt(key, key_len, out_padded);
    }
}

int pdf_verify_owner_password(const PDFEncryptParams *params, const char *password)
{
    if (!params->valid) return 0;

    if (params->revision == 5) return verify_owner_r5(params, password);
    if (params->revision == 6) return verify_owner_r6(params, password);

    int key_bytes = key_bytes_for(params);

    /* Step a: Pad the owner password and derive the owner key */
    uint8_t padded[32];
    pad_password(password, padded);

    uint8_t hash[16];
    CC_MD5(padded, 32, hash);

    /* Step c: For R >= 3, iterate MD5 R3_KEY_ITERATIONS times on first key_bytes */
    if (params->revision >= 3) {
        for (int i = 0; i < R3_KEY_ITERATIONS; i++)
            CC_MD5(hash, (CC_LONG)key_bytes, hash);
    }

    uint8_t key[16];
    memcpy(key, hash, (size_t)key_bytes);

    /* Step d/e: Recover the 32-byte padded user password from /O (NUL-safe),
     * then verify it directly without a C-string round-trip. */
    uint8_t user_padded[32];
    recover_user_password(params->o_value, key, key_bytes, params->revision, user_padded);

    return verify_user_with_padded(params, user_padded);
}

/* ================================================================
 * Verify as either user or owner password
 * ================================================================ */
int pdf_verify_password(const PDFEncryptParams *params, const char *password)
{
    return pdf_verify_user_password(params, password) ||
           pdf_verify_owner_password(params, password);
}

/* ================================================================
 * ARM NEON SIMD batch verification: 4 user passwords in parallel
 * ================================================================ */
#ifdef __ARM_NEON
#include "md5_simd.h"

int pdf_verify_user_batch4(const PDFEncryptParams *params,
                           const char *pw[4], int pwlen[4])
{
    if (!params->valid) return 0;
    if (params->revision < 2 || params->revision > 4) return 0;

    int key_bytes = key_bytes_for(params);

    /* ── Algorithm 2 (key derivation) for all 4 passwords ──────── */

    /* Step a: Pad each password to 32 bytes */
    uint8_t padded[4][32];
    for (int i = 0; i < 4; i++)
        pad_password(pw[i], padded[i]);

    /* Steps b-f: Build the MD5 input for each password.
     * Input = padded(32) + O(32) + P(4) + fileID(N) [+ 0xFFFFFFFF if R>=4 && !encryptMeta]
     * All 4 share the same O, P, fileID, so they differ only in the first 32 bytes. */
    uint8_t p_bytes[4];
    p_to_le32(params->permissions, p_bytes);

    int extra = (params->revision >= 4 && !params->encrypt_metadata) ? 4 : 0;
    size_t msg_len = 32 + 32 + 4 + (size_t)params->file_id_len + (size_t)extra;

    /* Build message buffers (max ~116 bytes each, well within md5_x4 limits) */
    uint8_t msg[4][256];
    for (int i = 0; i < 4; i++) {
        size_t off = 0;
        memcpy(msg[i] + off, padded[i], 32); off += 32;
        memcpy(msg[i] + off, params->o_value, 32); off += 32;
        memcpy(msg[i] + off, p_bytes, 4); off += 4;
        memcpy(msg[i] + off, params->file_id, (size_t)params->file_id_len);
        off += (size_t)params->file_id_len;
        if (extra) {
            uint8_t ff[4] = {0xFF, 0xFF, 0xFF, 0xFF};
            memcpy(msg[i] + off, ff, 4);
        }
    }

    /* Initial MD5 hash (4-way SIMD) */
    const uint8_t *ptrs[4] = { msg[0], msg[1], msg[2], msg[3] };
    size_t lens[4] = { msg_len, msg_len, msg_len, msg_len };
    uint8_t hash[4][16];
    md5_x4(ptrs, lens, hash);

    /* Step g: For R >= 3, iterate MD5 R3_KEY_ITERATIONS times on first key_bytes */
    if (params->revision >= 3) {
        uint8_t buf[4][64]; /* key_bytes <= 16, fits in single block */
        for (int iter = 0; iter < R3_KEY_ITERATIONS; iter++) {
            for (int i = 0; i < 4; i++)
                memcpy(buf[i], hash[i], (size_t)key_bytes);
            md5_x4_short(buf, (size_t)key_bytes, hash);
        }
    }

    /* Now hash[i] contains the encryption key for password i */
    uint8_t keys[4][16];
    for (int i = 0; i < 4; i++)
        memcpy(keys[i], hash[i], (size_t)key_bytes);

    /* ── RC4 verification (per-password, cannot be vectorized) ─── */
    int result = 0;

    if (params->revision == 2) {
        /* Algorithm 4: RC4-encrypt padding, compare 32 bytes */
        for (int i = 0; i < 4; i++) {
            /* Early first-byte exit: reject 255/256 candidates instantly */
            if (rc4_first_byte(keys[i], key_bytes, PDF_PASSWORD_PADDING[0])
                != params->u_value[0])
                continue;
            uint8_t computed_u[32];
            rc4_encrypt(keys[i], key_bytes, PDF_PASSWORD_PADDING, computed_u, PDF_PASSWORD_PADDING_LEN);
            if (memcmp(computed_u, params->u_value, PDF_PASSWORD_PADDING_LEN) == 0)
                result |= (1 << i);
        }
    } else {
        /* Algorithm 5 (R3/R4): MD5(padding+fileID), 20 RC4 passes, compare 16 bytes.
         * The initial MD5(padding+fileID) is the same for all 4, compute once. */
        CC_MD5_CTX md5ctx;
        CC_MD5_Init(&md5ctx);
        CC_MD5_Update(&md5ctx, PDF_PASSWORD_PADDING, PDF_PASSWORD_PADDING_LEN);
        CC_MD5_Update(&md5ctx, params->file_id, (CC_LONG)params->file_id_len);
        uint8_t base_hash[16];
        CC_MD5_Final(base_hash, &md5ctx);

        for (int i = 0; i < 4; i++) {
            uint8_t encrypted[16];
            rc4_encrypt_16(keys[i], key_bytes, base_hash, encrypted);
            rc4_multi_pass_16(keys[i], key_bytes, encrypted, 1, R34_RC4_EXTRA_PASSES, 1);

            if (memcmp(encrypted, params->u_value, 16) == 0)
                result |= (1 << i);
        }
    }

    return result;
}

int pdf_verify_owner_batch4(const PDFEncryptParams *params,
                            const char *pw[4], int pwlen[4])
{
    if (!params->valid) return 0;

    /* R5/R6: use scalar path (SHA-256 based, no NEON MD5 benefit) */
    if (params->revision >= 5) {
        int result = 0;
        for (int i = 0; i < 4; i++) {
            if (pdf_verify_owner_password(params, pw[i]))
                result |= (1 << i);
        }
        return result;
    }

    if (params->revision < 2 || params->revision > 4) return 0;

    int key_bytes = key_bytes_for(params);

    /* ── Owner key derivation for all 4 passwords (SIMD MD5) ── */

    /* Step a: Pad each owner password to 32 bytes */
    uint8_t padded[4][32];
    for (int i = 0; i < 4; i++)
        pad_password(pw[i], padded[i]);

    /* Step b: MD5 hash of padded password (4-way SIMD) */
    const uint8_t *ptrs[4] = { padded[0], padded[1], padded[2], padded[3] };
    size_t lens[4] = { 32, 32, 32, 32 };
    uint8_t hash[4][16];
    md5_x4(ptrs, lens, hash);

    /* Step c: For R >= 3, iterate MD5 R3_KEY_ITERATIONS times on first key_bytes */
    if (params->revision >= 3) {
        uint8_t buf[4][64];
        for (int iter = 0; iter < R3_KEY_ITERATIONS; iter++) {
            for (int i = 0; i < 4; i++)
                memcpy(buf[i], hash[i], (size_t)key_bytes);
            md5_x4_short(buf, (size_t)key_bytes, hash);
        }
    }

    /* Now hash[i] contains the owner key for password i */
    uint8_t keys[4][16];
    for (int i = 0; i < 4; i++)
        memcpy(keys[i], hash[i], (size_t)key_bytes);

    /* ── Per-password: recover padded user password (NUL-safe), verify directly ── */
    int result = 0;

    for (int i = 0; i < 4; i++) {
        uint8_t user_padded[32];
        recover_user_password(params->o_value, keys[i], key_bytes,
                              params->revision, user_padded);
        if (verify_user_with_padded(params, user_padded))
            result |= (1 << i);
    }

    return result;
}

#endif /* __ARM_NEON */
