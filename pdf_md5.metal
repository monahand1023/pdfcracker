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

/* ── SHA-256 constants ──────────────────────────────────────────── */

constant uint SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ── SHA-256 block transform ───────────────────────────────────── */

static uint sha256_rotr(uint x, uint n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(thread uint *state, thread const uint *W)
{
    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    uint w[64];
    for (uint i = 0; i < 16; i++) w[i] = W[i];
    for (uint i = 16; i < 64; i++) {
        uint s0 = sha256_rotr(w[i-15], 7) ^ sha256_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        uint s1 = sha256_rotr(w[i-2], 17) ^ sha256_rotr(w[i-2], 19)  ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    for (uint i = 0; i < 64; i++) {
        uint S1  = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        uint ch  = (e & f) ^ (~e & g);
        uint t1  = h + S1 + ch + SHA256_K[i] + w[i];
        uint S0  = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2  = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ── SHA-256 hash of arbitrary data (up to 143 bytes: 127 pw + 8 salt + 8 spare) ── */

static void sha256_hash(thread const uchar *data, uint len, thread uchar *out)
{
    uint state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    /* Process complete 64-byte blocks */
    uint offset = 0;
    while (offset + 64 <= len) {
        uint W[16];
        for (uint i = 0; i < 16; i++) {
            uint idx = offset + i * 4;
            W[i] = (uint(data[idx]) << 24) | (uint(data[idx+1]) << 16) |
                   (uint(data[idx+2]) << 8) | uint(data[idx+3]);
        }
        sha256_transform(state, W);
        offset += 64;
    }

    /* Final block with padding */
    uchar block[128];
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

    /* Length in bits as 64-bit BE at end */
    uint bit_len = len * 8;
    block[block_len - 8] = 0;
    block[block_len - 7] = 0;
    block[block_len - 6] = 0;
    block[block_len - 5] = 0;
    block[block_len - 4] = uchar(bit_len >> 24);
    block[block_len - 3] = uchar(bit_len >> 16);
    block[block_len - 2] = uchar(bit_len >> 8);
    block[block_len - 1] = uchar(bit_len);

    /* Process final block(s) */
    uint W[16];
    for (uint i = 0; i < 16; i++) {
        uint idx = i * 4;
        W[i] = (uint(block[idx]) << 24) | (uint(block[idx+1]) << 16) |
               (uint(block[idx+2]) << 8) | uint(block[idx+3]);
    }
    sha256_transform(state, W);

    if (block_len == 128) {
        for (uint i = 0; i < 16; i++) {
            uint idx = 64 + i * 4;
            W[i] = (uint(block[idx]) << 24) | (uint(block[idx+1]) << 16) |
                   (uint(block[idx+2]) << 8) | uint(block[idx+3]);
        }
        sha256_transform(state, W);
    }

    /* Output as bytes (BE — SHA-256 is big-endian) */
    for (uint i = 0; i < 8; i++) {
        out[i*4+0] = uchar(state[i] >> 24);
        out[i*4+1] = uchar(state[i] >> 16);
        out[i*4+2] = uchar(state[i] >> 8);
        out[i*4+3] = uchar(state[i]);
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

/* ── R5/R6 GPU parameters ────────────────────────────────────── */

struct PDFR5GPU {
    uchar  u_hash[32];        /* first 32 bytes of U (the target hash) */
    uchar  u_salt[8];         /* U[32:40] validation salt */
    uchar  o_hash[32];        /* first 32 bytes of O */
    uchar  o_salt[8];         /* O[32:40] validation salt */
    uchar  u_full[48];        /* full U value (for owner password check) */
    uint   check_owner;       /* 1 = verify owner password, 0 = verify user */
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

/* ── Kernel: R5 SHA-256 password verification ────────────────── */
/*
 * R5 user:  SHA-256(password + validation_salt) == U[0:32]
 * R5 owner: SHA-256(password + validation_salt + U[0:48]) == O[0:32]
 *
 * Each thread verifies one password. Results: 1 = match, 0 = no match.
 * Passwords are packed at 128 bytes each (max 127 chars + alignment).
 */

kernel void pdf_sha256_verify(
    device const uchar   *passwords    [[buffer(0)]],  /* packed, 128 bytes each */
    device const uchar   *pass_lengths [[buffer(1)]],  /* 1 byte per password */
    constant PDFR5GPU    &params       [[buffer(2)]],
    device uchar          *results     [[buffer(3)]],  /* 1 byte per password: 1=match */
    uint tid [[thread_position_in_grid]])
{
    uint pw_offset = tid * 128;
    uint pw_len = uint(pass_lengths[tid]);
    if (pw_len > 127) pw_len = 127;

    /* Build input: password + salt [+ U for owner check] */
    uchar input[184]; /* max: 127 pw + 8 salt + 48 U + 1 spare */
    uint input_len = 0;

    for (uint i = 0; i < pw_len; i++)
        input[input_len++] = passwords[pw_offset + i];

    if (params.check_owner) {
        /* Owner: password + O_validation_salt + U[0:48] */
        for (uint i = 0; i < 8; i++)
            input[input_len++] = params.o_salt[i];
        for (uint i = 0; i < 48; i++)
            input[input_len++] = params.u_full[i];
    } else {
        /* User: password + U_validation_salt */
        for (uint i = 0; i < 8; i++)
            input[input_len++] = params.u_salt[i];
    }

    uchar hash[32];
    sha256_hash(input, input_len, hash);

    /* Compare against target hash (constant address space) */
    uchar match = 1;
    if (params.check_owner) {
        for (uint i = 0; i < 32; i++) {
            if (hash[i] != params.o_hash[i]) { match = 0; break; }
        }
    } else {
        for (uint i = 0; i < 32; i++) {
            if (hash[i] != params.u_hash[i]) { match = 0; break; }
        }
    }
    results[tid] = match;
}

/* ══════════════════════════════════════════════════════════════
 * R6 GPU acceleration: Algorithm 2.B (iterative hash + AES-CBC)
 * ══════════════════════════════════════════════════════════════ */

/* ── SHA-512 constants ──────────────────────────────────────────── */

constant ulong SHA512_K[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

static ulong sha512_rotr(ulong x, uint n) { return (x >> n) | (x << (64 - n)); }

static void sha512_transform(thread ulong *state, thread const ulong *W)
{
    ulong a = state[0], b = state[1], c = state[2], d = state[3];
    ulong e = state[4], f = state[5], g = state[6], h = state[7];

    ulong w[80];
    for (uint i = 0; i < 16; i++) w[i] = W[i];
    for (uint i = 16; i < 80; i++) {
        ulong s0 = sha512_rotr(w[i-15], 1) ^ sha512_rotr(w[i-15], 8) ^ (w[i-15] >> 7);
        ulong s1 = sha512_rotr(w[i-2], 19) ^ sha512_rotr(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    for (uint i = 0; i < 80; i++) {
        ulong S1 = sha512_rotr(e, 14) ^ sha512_rotr(e, 18) ^ sha512_rotr(e, 41);
        ulong ch = (e & f) ^ (~e & g);
        ulong t1 = h + S1 + ch + SHA512_K[i] + w[i];
        ulong S0 = sha512_rotr(a, 28) ^ sha512_rotr(a, 34) ^ sha512_rotr(a, 39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* SHA-512 hash of data in device memory, outputs 64 bytes */
static void sha512_hash_dev(device const uchar *data, uint len, thread uchar *out)
{
    ulong state[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    uint offset = 0;
    while (offset + 128 <= len) {
        ulong W[16];
        for (uint i = 0; i < 16; i++) {
            uint idx = offset + i * 8;
            W[i] = (ulong(data[idx]) << 56) | (ulong(data[idx+1]) << 48) |
                   (ulong(data[idx+2]) << 40) | (ulong(data[idx+3]) << 32) |
                   (ulong(data[idx+4]) << 24) | (ulong(data[idx+5]) << 16) |
                   (ulong(data[idx+6]) << 8)  | ulong(data[idx+7]);
        }
        sha512_transform(state, W);
        offset += 128;
    }

    /* Final block with padding */
    uchar block[256];
    uint remaining = len - offset;
    for (uint i = 0; i < remaining; i++)
        block[i] = data[offset + i];
    block[remaining] = 0x80;

    uint block_len;
    if (remaining < 112) {
        block_len = 128;
        for (uint i = remaining + 1; i < 112; i++) block[i] = 0;
    } else {
        block_len = 256;
        for (uint i = remaining + 1; i < 240; i++) block[i] = 0;
    }

    /* Length in bits as 128-bit BE at end (we only use lower 32 bits) */
    for (uint i = block_len - 16; i < block_len - 4; i++) block[i] = 0;
    uint bit_len = len * 8;
    block[block_len - 4] = uchar(bit_len >> 24);
    block[block_len - 3] = uchar(bit_len >> 16);
    block[block_len - 2] = uchar(bit_len >> 8);
    block[block_len - 1] = uchar(bit_len);

    ulong W[16];
    for (uint i = 0; i < 16; i++) {
        uint idx = i * 8;
        W[i] = (ulong(block[idx]) << 56) | (ulong(block[idx+1]) << 48) |
               (ulong(block[idx+2]) << 40) | (ulong(block[idx+3]) << 32) |
               (ulong(block[idx+4]) << 24) | (ulong(block[idx+5]) << 16) |
               (ulong(block[idx+6]) << 8)  | ulong(block[idx+7]);
    }
    sha512_transform(state, W);

    if (block_len == 256) {
        for (uint i = 0; i < 16; i++) {
            uint idx = 128 + i * 8;
            W[i] = (ulong(block[idx]) << 56) | (ulong(block[idx+1]) << 48) |
                   (ulong(block[idx+2]) << 40) | (ulong(block[idx+3]) << 32) |
                   (ulong(block[idx+4]) << 24) | (ulong(block[idx+5]) << 16) |
                   (ulong(block[idx+6]) << 8)  | ulong(block[idx+7]);
        }
        sha512_transform(state, W);
    }

    for (uint i = 0; i < 8; i++) {
        out[i*8+0] = uchar(state[i] >> 56);
        out[i*8+1] = uchar(state[i] >> 48);
        out[i*8+2] = uchar(state[i] >> 40);
        out[i*8+3] = uchar(state[i] >> 32);
        out[i*8+4] = uchar(state[i] >> 24);
        out[i*8+5] = uchar(state[i] >> 16);
        out[i*8+6] = uchar(state[i] >> 8);
        out[i*8+7] = uchar(state[i]);
    }
}

/* SHA-384: same as SHA-512 with different IV, truncated to 48 bytes */
static void sha384_hash_dev(device const uchar *data, uint len, thread uchar *out)
{
    ulong state[8] = {
        0xcbbb9d5dc1059ed8UL, 0x629a292a367cd507UL,
        0x9159015a3070dd17UL, 0x152fecd8f70e5939UL,
        0x67332667ffc00b31UL, 0x8eb44a8768581511UL,
        0xdb0c2e0d64f98fa7UL, 0x47b5481dbefa4fa4UL
    };

    uint offset = 0;
    while (offset + 128 <= len) {
        ulong W[16];
        for (uint i = 0; i < 16; i++) {
            uint idx = offset + i * 8;
            W[i] = (ulong(data[idx]) << 56) | (ulong(data[idx+1]) << 48) |
                   (ulong(data[idx+2]) << 40) | (ulong(data[idx+3]) << 32) |
                   (ulong(data[idx+4]) << 24) | (ulong(data[idx+5]) << 16) |
                   (ulong(data[idx+6]) << 8)  | ulong(data[idx+7]);
        }
        sha512_transform(state, W);
        offset += 128;
    }

    uchar block[256];
    uint remaining = len - offset;
    for (uint i = 0; i < remaining; i++)
        block[i] = data[offset + i];
    block[remaining] = 0x80;

    uint block_len;
    if (remaining < 112) {
        block_len = 128;
        for (uint i = remaining + 1; i < 112; i++) block[i] = 0;
    } else {
        block_len = 256;
        for (uint i = remaining + 1; i < 240; i++) block[i] = 0;
    }

    for (uint i = block_len - 16; i < block_len - 4; i++) block[i] = 0;
    uint bit_len = len * 8;
    block[block_len - 4] = uchar(bit_len >> 24);
    block[block_len - 3] = uchar(bit_len >> 16);
    block[block_len - 2] = uchar(bit_len >> 8);
    block[block_len - 1] = uchar(bit_len);

    ulong W[16];
    for (uint i = 0; i < 16; i++) {
        uint idx = i * 8;
        W[i] = (ulong(block[idx]) << 56) | (ulong(block[idx+1]) << 48) |
               (ulong(block[idx+2]) << 40) | (ulong(block[idx+3]) << 32) |
               (ulong(block[idx+4]) << 24) | (ulong(block[idx+5]) << 16) |
               (ulong(block[idx+6]) << 8)  | ulong(block[idx+7]);
    }
    sha512_transform(state, W);

    if (block_len == 256) {
        for (uint i = 0; i < 16; i++) {
            uint idx = 128 + i * 8;
            W[i] = (ulong(block[idx]) << 56) | (ulong(block[idx+1]) << 48) |
                   (ulong(block[idx+2]) << 40) | (ulong(block[idx+3]) << 32) |
                   (ulong(block[idx+4]) << 24) | (ulong(block[idx+5]) << 16) |
                   (ulong(block[idx+6]) << 8)  | ulong(block[idx+7]);
        }
        sha512_transform(state, W);
    }

    /* Output only first 48 bytes (6 of 8 words) */
    for (uint i = 0; i < 6; i++) {
        out[i*8+0] = uchar(state[i] >> 56);
        out[i*8+1] = uchar(state[i] >> 48);
        out[i*8+2] = uchar(state[i] >> 40);
        out[i*8+3] = uchar(state[i] >> 32);
        out[i*8+4] = uchar(state[i] >> 24);
        out[i*8+5] = uchar(state[i] >> 16);
        out[i*8+6] = uchar(state[i] >> 8);
        out[i*8+7] = uchar(state[i]);
    }
}

/* ── AES-128 implementation (T-table based) ────────────────────── */

constant uchar AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

constant uint AES_RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* AES-128 key expansion: 16-byte key → 11 round keys (44 uint words) */
static void aes128_expand_key(thread const uchar *key, thread uint *rk)
{
    for (uint i = 0; i < 4; i++) {
        rk[i] = uint(key[4*i]) | (uint(key[4*i+1]) << 8) |
                (uint(key[4*i+2]) << 16) | (uint(key[4*i+3]) << 24);
    }
    for (uint i = 4; i < 44; i++) {
        uint temp = rk[i - 1];
        if (i % 4 == 0) {
            /* RotWord + SubWord + Rcon */
            temp = (uint(AES_SBOX[(temp >> 8) & 0xFF]))       |
                   (uint(AES_SBOX[(temp >> 16) & 0xFF]) << 8) |
                   (uint(AES_SBOX[(temp >> 24) & 0xFF]) << 16) |
                   (uint(AES_SBOX[temp & 0xFF]) << 24);
            temp ^= AES_RCON[i / 4 - 1];
        }
        rk[i] = rk[i - 4] ^ temp;
    }
}

/* AES-128 encrypt a single 16-byte block in-place */
static void aes128_encrypt_block(thread const uint *rk, thread uchar *block)
{
    uint s0 = uint(block[0]) | (uint(block[1]) << 8) |
              (uint(block[2]) << 16) | (uint(block[3]) << 24);
    uint s1 = uint(block[4]) | (uint(block[5]) << 8) |
              (uint(block[6]) << 16) | (uint(block[7]) << 24);
    uint s2 = uint(block[8]) | (uint(block[9]) << 8) |
              (uint(block[10]) << 16) | (uint(block[11]) << 24);
    uint s3 = uint(block[12]) | (uint(block[13]) << 8) |
              (uint(block[14]) << 16) | (uint(block[15]) << 24);

    s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];

    for (uint r = 1; r < 10; r++) {
        /* SubBytes + ShiftRows then MixColumns (textbook, no T-tables) */
        uchar st[16];
        /* SubBytes + ShiftRows */
        st[0]  = AES_SBOX[s0 & 0xFF];
        st[1]  = AES_SBOX[(s1 >> 8) & 0xFF];
        st[2]  = AES_SBOX[(s2 >> 16) & 0xFF];
        st[3]  = AES_SBOX[(s3 >> 24) & 0xFF];
        st[4]  = AES_SBOX[s1 & 0xFF];
        st[5]  = AES_SBOX[(s2 >> 8) & 0xFF];
        st[6]  = AES_SBOX[(s3 >> 16) & 0xFF];
        st[7]  = AES_SBOX[(s0 >> 24) & 0xFF];
        st[8]  = AES_SBOX[s2 & 0xFF];
        st[9]  = AES_SBOX[(s3 >> 8) & 0xFF];
        st[10] = AES_SBOX[(s0 >> 16) & 0xFF];
        st[11] = AES_SBOX[(s1 >> 24) & 0xFF];
        st[12] = AES_SBOX[s3 & 0xFF];
        st[13] = AES_SBOX[(s0 >> 8) & 0xFF];
        st[14] = AES_SBOX[(s1 >> 16) & 0xFF];
        st[15] = AES_SBOX[(s2 >> 24) & 0xFF];

        /* MixColumns */
        for (uint c = 0; c < 4; c++) {
            uchar a0 = st[c*4], a1 = st[c*4+1], a2 = st[c*4+2], a3 = st[c*4+3];
            uchar x0 = (a0 << 1) ^ (uchar(a0 >> 7) * 0x1b); /* xtime = 2*a0 */
            uchar x1 = (a1 << 1) ^ (uchar(a1 >> 7) * 0x1b);
            uchar x2 = (a2 << 1) ^ (uchar(a2 >> 7) * 0x1b);
            uchar x3 = (a3 << 1) ^ (uchar(a3 >> 7) * 0x1b);
            st[c*4]   = x0 ^ x1 ^ a1 ^ a2 ^ a3; /* 2*a0 + 3*a1 + a2 + a3 */
            st[c*4+1] = a0 ^ x1 ^ x2 ^ a2 ^ a3; /* a0 + 2*a1 + 3*a2 + a3 */
            st[c*4+2] = a0 ^ a1 ^ x2 ^ x3 ^ a3; /* a0 + a1 + 2*a2 + 3*a3 */
            st[c*4+3] = x0 ^ a0 ^ a1 ^ a2 ^ x3; /* 3*a0 + a1 + a2 + 2*a3 */
        }

        s0 = uint(st[0]) | (uint(st[1]) << 8) | (uint(st[2]) << 16) | (uint(st[3]) << 24);
        s1 = uint(st[4]) | (uint(st[5]) << 8) | (uint(st[6]) << 16) | (uint(st[7]) << 24);
        s2 = uint(st[8]) | (uint(st[9]) << 8) | (uint(st[10]) << 16) | (uint(st[11]) << 24);
        s3 = uint(st[12]) | (uint(st[13]) << 8) | (uint(st[14]) << 16) | (uint(st[15]) << 24);

        s0 ^= rk[r*4]; s1 ^= rk[r*4+1]; s2 ^= rk[r*4+2]; s3 ^= rk[r*4+3];
    }

    /* Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
    uchar st[16];
    st[0]  = AES_SBOX[s0 & 0xFF];         st[1]  = AES_SBOX[(s1 >> 8) & 0xFF];
    st[2]  = AES_SBOX[(s2 >> 16) & 0xFF]; st[3]  = AES_SBOX[(s3 >> 24) & 0xFF];
    st[4]  = AES_SBOX[s1 & 0xFF];         st[5]  = AES_SBOX[(s2 >> 8) & 0xFF];
    st[6]  = AES_SBOX[(s3 >> 16) & 0xFF]; st[7]  = AES_SBOX[(s0 >> 24) & 0xFF];
    st[8]  = AES_SBOX[s2 & 0xFF];         st[9]  = AES_SBOX[(s3 >> 8) & 0xFF];
    st[10] = AES_SBOX[(s0 >> 16) & 0xFF]; st[11] = AES_SBOX[(s1 >> 24) & 0xFF];
    st[12] = AES_SBOX[s3 & 0xFF];         st[13] = AES_SBOX[(s0 >> 8) & 0xFF];
    st[14] = AES_SBOX[(s1 >> 16) & 0xFF]; st[15] = AES_SBOX[(s2 >> 24) & 0xFF];

    block[0]  = st[0]  ^ uchar(rk[40]);       block[1]  = st[1]  ^ uchar(rk[40] >> 8);
    block[2]  = st[2]  ^ uchar(rk[40] >> 16); block[3]  = st[3]  ^ uchar(rk[40] >> 24);
    block[4]  = st[4]  ^ uchar(rk[41]);       block[5]  = st[5]  ^ uchar(rk[41] >> 8);
    block[6]  = st[6]  ^ uchar(rk[41] >> 16); block[7]  = st[7]  ^ uchar(rk[41] >> 24);
    block[8]  = st[8]  ^ uchar(rk[42]);       block[9]  = st[9]  ^ uchar(rk[42] >> 8);
    block[10] = st[10] ^ uchar(rk[42] >> 16); block[11] = st[11] ^ uchar(rk[42] >> 24);
    block[12] = st[12] ^ uchar(rk[43]);       block[13] = st[13] ^ uchar(rk[43] >> 8);
    block[14] = st[14] ^ uchar(rk[43] >> 16); block[15] = st[15] ^ uchar(rk[43] >> 24);
}

/* AES-128-CBC encrypt: no padding, len must be multiple of 16 */
static void aes128_cbc_encrypt(thread const uchar *key, thread const uchar *iv,
                                device const uchar *input, uint len,
                                device uchar *output)
{
    uint rk[44];
    aes128_expand_key(key, rk);

    uchar prev[16];
    for (uint i = 0; i < 16; i++) prev[i] = iv[i];

    for (uint off = 0; off < len; off += 16) {
        uchar block[16];
        for (uint i = 0; i < 16; i++)
            block[i] = input[off + i] ^ prev[i];

        aes128_encrypt_block(rk, block);

        for (uint i = 0; i < 16; i++) {
            output[off + i] = block[i];
            prev[i] = block[i];
        }
    }
}

/* SHA-256 hash of data in device memory */
static void sha256_hash_dev(device const uchar *data, uint len, thread uchar *out)
{
    uint state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint offset = 0;
    while (offset + 64 <= len) {
        uint W[16];
        for (uint i = 0; i < 16; i++) {
            uint idx = offset + i * 4;
            W[i] = (uint(data[idx]) << 24) | (uint(data[idx+1]) << 16) |
                   (uint(data[idx+2]) << 8) | uint(data[idx+3]);
        }
        sha256_transform(state, W);
        offset += 64;
    }

    uchar block[128];
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

    uint bit_len = len * 8;
    block[block_len - 8] = 0;
    block[block_len - 7] = 0;
    block[block_len - 6] = 0;
    block[block_len - 5] = 0;
    block[block_len - 4] = uchar(bit_len >> 24);
    block[block_len - 3] = uchar(bit_len >> 16);
    block[block_len - 2] = uchar(bit_len >> 8);
    block[block_len - 1] = uchar(bit_len);

    uint W[16];
    for (uint i = 0; i < 16; i++) {
        uint idx = i * 4;
        W[i] = (uint(block[idx]) << 24) | (uint(block[idx+1]) << 16) |
               (uint(block[idx+2]) << 8) | uint(block[idx+3]);
    }
    sha256_transform(state, W);

    if (block_len == 128) {
        for (uint i = 0; i < 16; i++) {
            uint idx = 64 + i * 4;
            W[i] = (uint(block[idx]) << 24) | (uint(block[idx+1]) << 16) |
                   (uint(block[idx+2]) << 8) | uint(block[idx+3]);
        }
        sha256_transform(state, W);
    }

    for (uint i = 0; i < 8; i++) {
        out[i*4+0] = uchar(state[i] >> 24);
        out[i*4+1] = uchar(state[i] >> 16);
        out[i*4+2] = uchar(state[i] >> 8);
        out[i*4+3] = uchar(state[i]);
    }
}

/* ── R6 Algorithm 2.B kernel ────────────────────────────────────── */
/*
 * Each thread processes one password through the full R6 KDF:
 *   1. SHA-256(password + salt + extra)
 *   2. Loop: build K1 (64 copies of password+hash+extra), AES-CBC encrypt,
 *      select SHA-256/384/512, repeat until convergence
 *   3. Compare first 32 bytes of final hash against target
 *
 * Working memory per thread uses device-memory scratch space.
 * Each thread gets R6_SCRATCH_SIZE bytes at offset tid * R6_SCRATCH_SIZE.
 */

#define R6_SCRATCH_SIZE  16384  /* enough for K1 (max ~15KB) + AES output */

struct PDFR6GPU {
    uchar  target_hash[32];   /* U[0:32] or O[0:32] — what we're comparing against */
    uchar  salt[8];           /* validation salt (U[32:40] or O[32:40]) */
    uchar  extra[48];         /* extra data: empty for user, U[0:48] for owner */
    uint   extra_len;         /* 0 for user, 48 for owner */
};

kernel void pdf_r6_verify(
    device const uchar    *passwords    [[buffer(0)]],  /* packed, 128 bytes each */
    device const uchar    *pass_lengths [[buffer(1)]],  /* 1 byte per password */
    constant PDFR6GPU     &params       [[buffer(2)]],
    device uchar           *results     [[buffer(3)]],  /* 1 byte per password */
    device uchar           *scratch     [[buffer(4)]],  /* R6_SCRATCH_SIZE per thread */
    uint tid [[thread_position_in_grid]])
{
    uint pw_offset = tid * 128;
    uint pw_len = uint(pass_lengths[tid]);
    if (pw_len > 127) pw_len = 127;

    /* Scratch pointers for this thread */
    device uchar *K1      = scratch + (ulong)tid * R6_SCRATCH_SIZE;
    device uchar *aes_out = K1; /* reuse same buffer — AES is in-place for CBC */

    /* Step a: SHA-256(password + salt + extra) */
    /* Build initial input in K1 scratch (temporary) */
    uint init_len = 0;
    for (uint i = 0; i < pw_len; i++)
        K1[init_len++] = passwords[pw_offset + i];
    for (uint i = 0; i < 8; i++)
        K1[init_len++] = params.salt[i];
    for (uint i = 0; i < params.extra_len; i++)
        K1[init_len++] = params.extra[i];

    uchar hash[64]; /* large enough for SHA-512 */
    sha256_hash_dev(K1, init_len, hash);
    uint hash_len = 32;

    /* Step b-e: iterate until convergence */
    uint round = 0;

    for (;;) {
        /* Build sequence: password + hash + extra */
        uint seq_len = pw_len + hash_len + params.extra_len;
        /* Build one copy of sequence in K1 */
        uint pos = 0;
        for (uint i = 0; i < pw_len; i++)
            K1[pos++] = passwords[pw_offset + i];
        for (uint i = 0; i < hash_len; i++)
            K1[pos++] = hash[i];
        for (uint i = 0; i < params.extra_len; i++)
            K1[pos++] = params.extra[i];

        /* Repeat 64 times */
        uint K1_len = seq_len * 64;
        for (uint rep = 1; rep < 64; rep++) {
            for (uint i = 0; i < seq_len; i++)
                K1[rep * seq_len + i] = K1[i];
        }

        /* AES-128-CBC encrypt K1 with key=hash[0:16], iv=hash[16:32] */
        uchar aes_key[16], aes_iv[16];
        for (uint i = 0; i < 16; i++) aes_key[i] = hash[i];
        for (uint i = 0; i < 16; i++) aes_iv[i]  = hash[16 + i];

        /* Round K1_len down to multiple of 16 */
        uint aes_len = (K1_len / 16) * 16;
        aes128_cbc_encrypt(aes_key, aes_iv, K1, aes_len, aes_out);

        /* Choose hash based on sum of first 16 bytes mod 3 */
        uint sum = 0;
        for (uint i = 0; i < 16; i++) sum += uint(aes_out[i]);

        switch (sum % 3) {
            case 0:
                sha256_hash_dev(aes_out, aes_len, hash);
                hash_len = 32;
                break;
            case 1:
                sha384_hash_dev(aes_out, aes_len, hash);
                hash_len = 48;
                break;
            case 2:
                sha512_hash_dev(aes_out, aes_len, hash);
                hash_len = 64;
                break;
        }

        /* Check termination */
        uchar last_byte = aes_out[aes_len - 1];
        round++;

        if (round >= 64 && last_byte <= uchar(round - 32))
            break;

        /* Safety limit: spec says typically 64-80 rounds */
        if (round > 200) break;
    }

    /* Compare first 32 bytes of hash against target */
    uchar match = 1;
    for (uint i = 0; i < 32; i++) {
        if (hash[i] != params.target_hash[i]) { match = 0; break; }
    }
    results[tid] = match;
}

