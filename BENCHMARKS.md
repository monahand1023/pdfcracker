# pdfcracker Benchmarks

## Test System

| Component | Spec |
|-----------|------|
| Model | Mac mini (2024) |
| Chip | Apple M4 Pro |
| CPU | 14 cores (10 Performance + 4 Efficiency) |
| GPU | 20-core Apple M4 Pro, Metal 4 |
| Memory | 64 GB unified |
| OS | macOS 26.3.1 |

## Multi-Core + GPU Performance

Full system throughput using all 14 CPU cores and Metal GPU acceleration (where beneficial). These are the speeds you'll see in practice.

| Revision | Encryption | Speed | GPU | Notes |
|----------|-----------|-------|-----|-------|
| R2 | 40-bit RC4 | **3.8M/s** | Disabled (CPU faster) | Fastest. GPU overhead exceeds benefit for simple key derivation |
| R3 | 128-bit RC4 | **298K/s** | Enabled (+75%) | Most common encryption in the wild |
| R4 | AES-128 | **225K/s** | Enabled (+75%) | Same key derivation as R3, slightly slower verification |
| R5 | AES-256 / SHA-256 | **76.8M/s** | N/A | Simple SHA-256 check, extremely fast |
| R6 | AES-256 / SHA-256+KDF | **13.8K/s** | N/A | Deliberately slow (64+ rounds of SHA-256+AES). By design |

## GPU Impact

Comparison of CPU-only (14 cores) vs CPU+GPU for R3 128-bit, the most common revision:

| Mode | Speed | Improvement |
|------|-------|-------------|
| CPU only (14 cores) | 171K/s | baseline |
| CPU + GPU (14 cores + 20-core Metal) | 298K/s | **+75%** |

The GPU handles MD5 key derivation while CPU cores handle RC4 verification in parallel. For R2 (40-bit), the key derivation is too simple for GPU to help — CPU alone is faster.

## Single-Core Performance vs CoreGraphics API

Our direct crypto implementation vs Apple's CGPDFDocument API (which pdfcracker replaces):

| Revision | Direct Crypto | CoreGraphics API | Speedup |
|----------|--------------|-----------------|---------|
| R2 40-bit | 1,137K/s | 19K/s | **59x** |
| R3 128-bit | 46K/s | 5.1K/s | **9x** |
| R4 AES-128 | 54K/s | 4.9K/s | **11x** |
| R5 AES-256 | 20,161K/s | 20K/s | **1,014x** |
| R6 AES-256 | 2.9K/s | 589/s | **5x** |

The R5 speedup (1,014x) is because our implementation checks the password hash directly against the stored validation salt, while CoreGraphics does unnecessary decryption work.

## Time to Crack Estimates (Single M4 Pro)

How long a brute-force attack takes at R3 speeds (298K/s), using the default charset (a-z, A-Z, 0-9 = 62 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 4 | 15M | 50 seconds |
| 5 | 931M | 52 minutes |
| 6 | 57.7B | 2.2 days |
| 7 | 3.5T | 138 days |
| 8 | 221T | 23 years |

With a reduced charset (digits only, 10 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 6 | 1.1M | 4 seconds |
| 8 | 111M | 6 minutes |
| 10 | 11.1B | 10 hours |
| 12 | 1.1T | 43 days |

### Distributed scaling

Adding more machines scales roughly linearly. Two M4 Pros cut all times in half. The lease-based work distribution has minimal overhead — machines can join and leave freely without losing work.

## How the Crypto Works

### R2/R3/R4 (MD5 + RC4)

1. **Key derivation** (MD5): Hash the candidate password with document metadata (owner hash, permissions, file ID). For R3/R4, iterate MD5 50 times on the result.
2. **Verification** (RC4): Encrypt a known plaintext with the derived key. For R2, one RC4 pass. For R3/R4, 20 RC4 passes with XOR-modified keys.
3. **Compare**: Check against the stored /U value in the PDF.

The GPU accelerates step 1 (MD5 is pure arithmetic, great for SIMD). The CPU handles step 2 (RC4 has data-dependent memory access, terrible for GPU).

### R5 (SHA-256)

Simple: SHA-256(password + validation salt) compared against stored hash. No iteration, no RC4. Extremely fast.

### R6 (SHA-256 + AES-CBC iterative KDF)

Deliberately expensive: a loop of SHA-256/384/512 + AES-CBC that runs 64+ rounds, with the round count determined by the hash output. Designed to resist GPU attacks. Each verification takes ~70 microseconds — there's no shortcut.
