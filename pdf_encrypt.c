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
    if (*dict_start != '<' || *(dict_start + 1) != '<') {
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

    if (*encrypt_val == '<' && encrypt_val + 1 < end && *(encrypt_val + 1) == '<') {
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
        if (memcmp(val, "false", 5) == 0)
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

/* ================================================================
 * Algorithm 2: Compute encryption key from user password
 * (ISO 32000-1 section 7.6.3.3)
 * ================================================================ */
int pdf_compute_encryption_key(const PDFEncryptParams *params,
                               const char *password,
                               uint8_t *key_out)
{
    int key_bytes = params->key_length / 8;
    if (key_bytes < 5)  key_bytes = 5;
    if (key_bytes > 16) key_bytes = 16;

    /* Step a: Pad or truncate password to 32 bytes */
    uint8_t padded[32];
    size_t plen = password ? strlen(password) : 0;
    if (plen > 32) plen = 32;
    if (plen > 0) memcpy(padded, password, plen);
    if (plen < 32) memcpy(padded + plen, PDF_PASSWORD_PADDING, 32 - plen);

    /* Step b-f: MD5 hash of padded + O + P(LE) + fileID [+ 0xFFFFFFFF if !encryptMetadata] */
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);

    /* (b) password */
    CC_MD5_Update(&md5, padded, 32);

    /* (c) O value */
    CC_MD5_Update(&md5, params->o_value, 32);

    /* (d) P value as 4 bytes little-endian */
    uint8_t p_bytes[4];
    int32_t perm = params->permissions;
    p_bytes[0] = (uint8_t)(perm & 0xFF);
    p_bytes[1] = (uint8_t)((perm >> 8) & 0xFF);
    p_bytes[2] = (uint8_t)((perm >> 16) & 0xFF);
    p_bytes[3] = (uint8_t)((perm >> 24) & 0xFF);
    CC_MD5_Update(&md5, p_bytes, 4);

    /* (e) File ID (first element) */
    CC_MD5_Update(&md5, params->file_id, (CC_LONG)params->file_id_len);

    /* (f) If R >= 4 and metadata is not encrypted, hash 0xFFFFFFFF */
    if (params->revision >= 4 && !params->encrypt_metadata) {
        uint8_t ff[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        CC_MD5_Update(&md5, ff, 4);
    }

    uint8_t hash[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(hash, &md5);

    /* (g) For R >= 3: iterate MD5 50 times on the first key_bytes bytes */
    if (params->revision >= 3) {
        for (int i = 0; i < 50; i++) {
            CC_MD5(hash, (CC_LONG)key_bytes, hash);
        }
    }

    memcpy(key_out, hash, (size_t)key_bytes);
    return key_bytes;
}

/* ================================================================
 * Algorithm 4: Compute U value for R=2 (user password check)
 * ================================================================ */
static void compute_u_r2(const uint8_t *key, int key_len,
                         uint8_t *u_out)
{
    /* RC4-encrypt the 32-byte padding string with the key */
    size_t out_len = 32;
    CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
            key, (size_t)key_len,
            NULL, /* no IV for RC4 */
            PDF_PASSWORD_PADDING, 32,
            u_out, 32, &out_len);
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
    CC_MD5_Update(&md5, PDF_PASSWORD_PADDING, 32);
    CC_MD5_Update(&md5, params->file_id, (CC_LONG)params->file_id_len);

    uint8_t hash[16];
    CC_MD5_Final(hash, &md5);

    /* (b) RC4-encrypt the 16-byte hash with the key */
    size_t out_len = 16;
    uint8_t encrypted[16];
    CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
            key, (size_t)key_len,
            NULL, hash, 16,
            encrypted, 16, &out_len);

    /* (c) 19 additional RC4 passes with XOR-modified keys */
    for (int i = 1; i <= 19; i++) {
        uint8_t mod_key[16];
        for (int j = 0; j < key_len; j++)
            mod_key[j] = key[j] ^ (uint8_t)i;

        uint8_t temp[16];
        out_len = 16;
        CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                mod_key, (size_t)key_len,
                NULL, encrypted, 16,
                temp, 16, &out_len);
        memcpy(encrypted, temp, 16);
    }

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
    /* Step a: SHA-256(password + salt + extra) */
    uint8_t hash[64]; /* large enough for SHA-512 */
    CC_SHA256_CTX sha256;
    CC_SHA256_Init(&sha256);
    CC_SHA256_Update(&sha256, password, (CC_LONG)pw_len);
    CC_SHA256_Update(&sha256, salt, 8);
    if (extra_len > 0)
        CC_SHA256_Update(&sha256, extra, (CC_LONG)extra_len);
    CC_SHA256_Final(hash, &sha256);

    int hash_len = 32; /* starts as SHA-256 */

    /* Step b-e: iterate until round >= 64 and last byte condition met */
    unsigned round = 0;
    uint8_t K1[64 * (127 + 64 + 48)]; /* max iteration block */

    for (;;) {
        /* Step b: Build K1 = password + hash + extra, repeated 64 times */
        size_t seq_len = pw_len + (size_t)hash_len + (size_t)extra_len;
        uint8_t seq[127 + 64 + 48]; /* max: 127 pw + 64 hash + 48 extra */
        memcpy(seq, password, pw_len);
        memcpy(seq + pw_len, hash, (size_t)hash_len);
        if (extra_len > 0)
            memcpy(seq + pw_len + hash_len, extra, (size_t)extra_len);

        size_t K1_len = seq_len * 64;
        for (int i = 0; i < 64; i++)
            memcpy(K1 + i * seq_len, seq, seq_len);

        /* Step c: AES-CBC encrypt K1 with key=hash[0:16], iv=hash[16:32] */
        uint8_t *aes_out = malloc(K1_len + 16); /* CBC may need padding room */
        if (!aes_out) { memcpy(out, hash, 32); return; }
        size_t aes_len = 0;
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, 0, /* no padding */
                hash, 16, hash + 16,
                K1, K1_len,
                aes_out, K1_len + 16, &aes_len);

        /* Step d: Choose hash based on first byte of encrypted result */
        /* Sum of first 16 bytes mod 3 determines hash algorithm */
        unsigned sum = 0;
        for (int i = 0; i < 16; i++) sum += aes_out[i];

        switch (sum % 3) {
            case 0:
                CC_SHA256(aes_out, (CC_LONG)aes_len, hash);
                hash_len = 32;
                break;
            case 1:
                CC_SHA384(aes_out, (CC_LONG)aes_len, hash);
                hash_len = 48;
                break;
            case 2:
                CC_SHA512(aes_out, (CC_LONG)aes_len, hash);
                hash_len = 64;
                break;
        }

        /* Step e: Check termination */
        uint8_t last_byte = aes_out[aes_len - 1];
        free(aes_out);
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

/* ================================================================
 * R6 user password verification (Algorithm 2.A with 2.B hash)
 * Algorithm2B(password, U_validation_salt, "") == U[0:32]
 * ================================================================ */
static int verify_user_r6(const PDFEncryptParams *params, const char *password)
{
    if (params->u_value_len < 40) return 0;

    size_t pw_len = password ? strlen(password) : 0;
    if (pw_len > 127) pw_len = 127;

    uint8_t hash[32];
    algorithm_2b((const uint8_t *)password, pw_len,
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

    size_t pw_len = password ? strlen(password) : 0;
    if (pw_len > 127) pw_len = 127;

    uint8_t hash[32];
    algorithm_2b((const uint8_t *)password, pw_len,
                 params->o_value + 32, /* validation salt */
                 params->u_value, 48,  /* full U as extra data */
                 hash);

    return memcmp(hash, params->o_value, 32) == 0;
}

/* ================================================================
 * Algorithm 6: Verify user password
 * ================================================================ */
int pdf_verify_user_password(const PDFEncryptParams *params, const char *password)
{
    if (!params->valid) return 0;

    if (params->revision == 5) return verify_user_r5(params, password);
    if (params->revision == 6) return verify_user_r6(params, password);

    uint8_t key[16];
    int key_len = pdf_compute_encryption_key(params, password, key);

    if (params->revision == 2) {
        uint8_t computed_u[32];
        compute_u_r2(key, key_len, computed_u);
        return memcmp(computed_u, params->u_value, 32) == 0;
    }

    if (params->revision == 3 || params->revision == 4) {
        uint8_t computed_u[16];
        compute_u_r3(params, key, key_len, computed_u);
        /* Compare first 16 bytes only */
        return memcmp(computed_u, params->u_value, 16) == 0;
    }

    return 0;
}

/* ================================================================
 * Algorithm 7: Verify owner password
 *
 * Recover the user password from the O value using the owner password,
 * then verify it as a user password.
 * ================================================================ */
int pdf_verify_owner_password(const PDFEncryptParams *params, const char *password)
{
    if (!params->valid) return 0;

    if (params->revision == 5) return verify_owner_r5(params, password);
    if (params->revision == 6) return verify_owner_r6(params, password);

    int key_bytes = params->key_length / 8;
    if (key_bytes < 5)  key_bytes = 5;
    if (key_bytes > 16) key_bytes = 16;

    /* Step a: Pad the owner password */
    uint8_t padded[32];
    size_t plen = password ? strlen(password) : 0;
    if (plen > 32) plen = 32;
    if (plen > 0) memcpy(padded, password, plen);
    if (plen < 32) memcpy(padded + plen, PDF_PASSWORD_PADDING, 32 - plen);

    /* Step b: MD5 hash */
    uint8_t hash[16];
    CC_MD5(padded, 32, hash);

    /* Step c: For R >= 3, iterate MD5 50 times on first key_bytes */
    if (params->revision >= 3) {
        for (int i = 0; i < 50; i++)
            CC_MD5(hash, (CC_LONG)key_bytes, hash);
    }

    uint8_t key[16];
    memcpy(key, hash, (size_t)key_bytes);

    /* Step d: RC4-decrypt the O value to recover the user password */
    uint8_t user_pass[32];

    if (params->revision == 2) {
        /* Single RC4 decryption */
        size_t out_len = 32;
        CCCrypt(kCCDecrypt, kCCAlgorithmRC4, 0,
                key, (size_t)key_bytes,
                NULL, params->o_value, 32,
                user_pass, 32, &out_len);
    } else {
        /* R3/R4: 20 RC4 passes in reverse (19 down to 0) */
        memcpy(user_pass, params->o_value, 32);
        for (int i = 19; i >= 0; i--) {
            uint8_t mod_key[16];
            for (int j = 0; j < key_bytes; j++)
                mod_key[j] = key[j] ^ (uint8_t)i;

            uint8_t temp[32];
            size_t out_len = 32;
            CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
                    mod_key, (size_t)key_bytes,
                    NULL, user_pass, 32,
                    temp, 32, &out_len);
            memcpy(user_pass, temp, 32);
        }
    }

    /* Step e: The recovered value is the padded user password.
     * Use it to verify as a user password. */
    /* Convert padded user password back to a string (trim padding) */
    char user_str[33];
    int ulen = 32;
    /* Find where padding starts */
    for (int i = 0; i < 32; i++) {
        if (user_pass[i] == PDF_PASSWORD_PADDING[0]) {
            /* Check if the rest matches padding */
            int is_pad = 1;
            for (int j = 0; j + i < 32 && j < 32; j++) {
                if (user_pass[i + j] != PDF_PASSWORD_PADDING[j]) {
                    is_pad = 0;
                    break;
                }
            }
            if (is_pad) { ulen = i; break; }
        }
    }
    memcpy(user_str, user_pass, (size_t)ulen);
    user_str[ulen] = '\0';

    return pdf_verify_user_password(params, user_str);
}

/* ================================================================
 * Verify as either user or owner password
 * ================================================================ */
int pdf_verify_password(const PDFEncryptParams *params, const char *password)
{
    return pdf_verify_user_password(params, password) ||
           pdf_verify_owner_password(params, password);
}
