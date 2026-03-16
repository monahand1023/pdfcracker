/*
 * pdf_md5.metal — GPU MD5 key derivation for PDF password cracking
 *
 * Implements ISO 32000-1 Algorithm 2 (encryption key computation) entirely
 * on the GPU. Each thread processes one candidate password and outputs the
 * derived encryption key. The CPU then does RC4 verification.
 *
 * MD5 is pure arithmetic — ideal for GPU SIMD.
 */

#include <metal_stdlib>
using namespace metal;

/* ── MD5 constants ──────────────────────────────────────────────── */

constant uint K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

constant uint S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

/* ── MD5 block transform ─────────────────────────────────────── */

static void md5_transform(thread uint4 &state, thread const uint *M)
{
    uint a = state.x, b = state.y, c = state.z, d = state.w;

    for (uint i = 0; i < 64; i++) {
        uint f, g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        uint temp = d;
        d = c;
        c = b;
        uint x = a + f + K[i] + M[g];
        b = b + ((x << S[i]) | (x >> (32 - S[i])));
        a = temp;
    }

    state += uint4(a, b, c, d);
}

/* ── MD5 hash of arbitrary data (up to 120 bytes for our use case) ── */

/* We need to hash up to: 32 (padded pw) + 32 (O) + 4 (P) + 48 (fileID) + 4 (ff) = 120 bytes
 * That's at most 2 MD5 blocks (128 bytes with padding). */
static void md5_hash(thread const uchar *data, uint len, thread uchar *out)
{
    uint4 state = uint4(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);

    /* Process complete 64-byte blocks */
    uint offset = 0;
    while (offset + 64 <= len) {
        uint M[16];
        for (uint i = 0; i < 16; i++) {
            uint idx = offset + i * 4;
            M[i] = uint(data[idx]) | (uint(data[idx+1]) << 8) |
                   (uint(data[idx+2]) << 16) | (uint(data[idx+3]) << 24);
        }
        md5_transform(state, M);
        offset += 64;
    }

    /* Final block(s) with padding */
    uchar block[128]; /* max 2 blocks */
    uint remaining = len - offset;
    for (uint i = 0; i < remaining; i++)
        block[i] = data[offset + i];
    block[remaining] = 0x80;

    uint block_len;
    if (remaining < 56) {
        block_len = 64;
        for (uint i = remaining + 1; i < 56; i++) block[i] = 0;
    } else {
        block_len = 128;
        for (uint i = remaining + 1; i < 120; i++) block[i] = 0;
    }

    /* Length in bits as 64-bit LE at end */
    uint bit_len = len * 8;
    block[block_len - 8] = uchar(bit_len);
    block[block_len - 7] = uchar(bit_len >> 8);
    block[block_len - 6] = uchar(bit_len >> 16);
    block[block_len - 5] = uchar(bit_len >> 24);
    block[block_len - 4] = 0;
    block[block_len - 3] = 0;
    block[block_len - 2] = 0;
    block[block_len - 1] = 0;

    /* Process final block(s) */
    uint M[16];
    for (uint i = 0; i < 16; i++) {
        uint idx = i * 4;
        M[i] = uint(block[idx]) | (uint(block[idx+1]) << 8) |
               (uint(block[idx+2]) << 16) | (uint(block[idx+3]) << 24);
    }
    md5_transform(state, M);

    if (block_len == 128) {
        for (uint i = 0; i < 16; i++) {
            uint idx = 64 + i * 4;
            M[i] = uint(block[idx]) | (uint(block[idx+1]) << 8) |
                   (uint(block[idx+2]) << 16) | (uint(block[idx+3]) << 24);
        }
        md5_transform(state, M);
    }

    /* Output as bytes (LE) */
    for (uint i = 0; i < 4; i++) {
        out[i*4+0] = uchar(state[i]);
        out[i*4+1] = uchar(state[i] >> 8);
        out[i*4+2] = uchar(state[i] >> 16);
        out[i*4+3] = uchar(state[i] >> 24);
    }
}

/* Short MD5: hash exactly 'len' bytes from 'data' (len <= 16, single block) */
static void md5_short(thread const uchar *data, uint len, thread uchar *out)
{
    uint4 state = uint4(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);

    uchar block[64];
    for (uint i = 0; i < len; i++) block[i] = data[i];
    block[len] = 0x80;
    for (uint i = len + 1; i < 56; i++) block[i] = 0;
    uint bit_len = len * 8;
    block[56] = uchar(bit_len);
    block[57] = uchar(bit_len >> 8);
    block[58] = uchar(bit_len >> 16);
    block[59] = uchar(bit_len >> 24);
    block[60] = 0; block[61] = 0; block[62] = 0; block[63] = 0;

    uint M[16];
    for (uint i = 0; i < 16; i++) {
        uint idx = i * 4;
        M[i] = uint(block[idx]) | (uint(block[idx+1]) << 8) |
               (uint(block[idx+2]) << 16) | (uint(block[idx+3]) << 24);
    }
    md5_transform(state, M);

    for (uint i = 0; i < 4; i++) {
        out[i*4+0] = uchar(state[i]);
        out[i*4+1] = uchar(state[i] >> 8);
        out[i*4+2] = uchar(state[i] >> 16);
        out[i*4+3] = uchar(state[i] >> 24);
    }
}

/* ── GPU parameters (set once per PDF) ───────────────────────── */

struct PDFEncryptGPU {
    uint   revision;          /* 2, 3, or 4 */
    uint   key_bytes;         /* key_length / 8 (5 or 16) */
    int    permissions;       /* /P value (signed) */
    uint   encrypt_metadata;  /* 1 or 0 */
    uint   file_id_len;
    uchar  o_value[32];       /* /O */
    uchar  file_id[48];       /* first /ID element */
    uchar  padding[32];       /* PDF_PASSWORD_PADDING */
};

/* ── Kernel: PDF MD5 key derivation (Algorithm 2) ────────────── */

kernel void pdf_keygen(
    device const uchar   *passwords    [[buffer(0)]],  /* packed, 32 bytes each */
    device const uchar   *pass_lengths [[buffer(1)]],  /* 1 byte per password */
    constant PDFEncryptGPU &params     [[buffer(2)]],
    device uchar          *keys_out    [[buffer(3)]],  /* key_bytes per entry */
    uint tid [[thread_position_in_grid]])
{
    /* Read password for this thread */
    uint pw_offset = tid * 32;
    uchar pw_len = pass_lengths[tid];

    /* Step a: Pad password to 32 bytes */
    uchar padded[32];
    for (uint i = 0; i < 32; i++) {
        if (i < uint(pw_len))
            padded[i] = passwords[pw_offset + i];
        else
            padded[i] = params.padding[i - uint(pw_len)];
    }

    /* Steps b-f: Build input buffer for MD5
     * = padded(32) + O(32) + P(4) + fileID(len) [+ 0xFFFFFFFF] */
    uchar input[120];
    uint input_len = 0;

    /* (b) padded password */
    for (uint i = 0; i < 32; i++) input[input_len++] = padded[i];

    /* (c) O value */
    for (uint i = 0; i < 32; i++) input[input_len++] = params.o_value[i];

    /* (d) P as 4 bytes LE */
    int perm = params.permissions;
    input[input_len++] = uchar(perm & 0xFF);
    input[input_len++] = uchar((perm >> 8) & 0xFF);
    input[input_len++] = uchar((perm >> 16) & 0xFF);
    input[input_len++] = uchar((perm >> 24) & 0xFF);

    /* (e) File ID */
    for (uint i = 0; i < params.file_id_len; i++)
        input[input_len++] = params.file_id[i];

    /* (f) If R >= 4 and metadata not encrypted */
    if (params.revision >= 4 && params.encrypt_metadata == 0) {
        input[input_len++] = 0xFF;
        input[input_len++] = 0xFF;
        input[input_len++] = 0xFF;
        input[input_len++] = 0xFF;
    }

    /* MD5 hash */
    uchar hash[16];
    md5_hash(input, input_len, hash);

    /* (g) For R >= 3: iterate MD5 50 times on first key_bytes */
    if (params.revision >= 3) {
        for (uint i = 0; i < 50; i++) {
            md5_short(hash, params.key_bytes, hash);
        }
    }

    /* Output key */
    uint key_offset = tid * params.key_bytes;
    for (uint i = 0; i < params.key_bytes; i++)
        keys_out[key_offset + i] = hash[i];
}
