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

## Best Speeds (M4 Pro)

Optimal configuration for each revision using all available acceleration:

| Revision | Encryption | Speed | Engine | Notes |
|----------|-----------|-------|--------|-------|
| R2 | 40-bit RC4 | **15.9M/s** | CPU + NEON SIMD | 4-way parallel MD5 per core |
| R3 | 128-bit RC4 | **812K/s** | CPU + NEON SIMD | Use `-G` to disable GPU for best speed |
| R4 | AES-128 | **812K/s** | CPU + NEON SIMD | Same crypto as R3 |
| R5 | AES-256 / SHA-256 | **104M/s** | CPU + GPU | GPU does full SHA-256 verification |
| R6 | AES-256 / SHA-256+KDF | **14.3K/s** | CPU only | Deliberately slow KDF, GPU impractical |

### Optimization History

| Revision | Phase 1 (CommonCrypto) | Phase 2 (Metal GPU) | Phase 3 (NEON SIMD) | Total Improvement |
|----------|----------------------|--------------------|--------------------|-------------------|
| R2 | 3.5M/s | 3.8M/s (+9%) | **15.9M/s (+318%)** | **4.5x** |
| R3 | 188K/s | 298K/s (+58%) | **812K/s (+173%)** | **4.3x** |
| R5 | 20M/s | 20M/s (CPU only) | **104M/s (+420%)** | **5.2x** |

## Engine Comparison

### R2 40-bit (per engine)

| Engine | Speed |
|--------|-------|
| Single core | 412K/s |
| 14 cores | 3.9M/s |
| 14 cores + NEON SIMD | **15.9M/s** |
| GPU (Metal MD5) | 443K/s (slower than NEON) |

### R3 128-bit (per engine)

| Engine | Speed |
|--------|-------|
| Single core | 17K/s |
| 14 cores | 179K/s |
| 14 cores + NEON SIMD | **812K/s** |
| GPU (Metal MD5 + CPU RC4) | 116K/s (slower than NEON) |

NEON processes 4 passwords per core simultaneously. The GPU MD5 path is slower because RC4 verification creates a CPU bottleneck. Use `-G` to disable GPU and get pure NEON speed for R2-R4.

### R5 AES-256 (per engine)

| Engine | Speed |
|--------|-------|
| Single core | 7.1M/s |
| 14 cores | 4.8M/s* |
| GPU (Metal SHA-256) | **104M/s** |

*Multi-core is slower than single-core for R5 because the SHA-256 check is so fast that thread overhead dominates. GPU is the clear winner — it does the full verification (SHA-256 + compare) entirely on-chip with no CPU round-trip.

## Single-Core Performance vs CoreGraphics API

Our direct crypto implementation vs Apple's CGPDFDocument API (which pdfcracker replaces):

| Revision | Direct Crypto | CoreGraphics API | Speedup |
|----------|--------------|-----------------|---------|
| R2 40-bit | 1,137K/s | 19K/s | **59x** |
| R3 128-bit | 46K/s | 5.1K/s | **9x** |
| R4 AES-128 | 54K/s | 4.9K/s | **11x** |
| R5 AES-256 | 20,161K/s | 20K/s | **1,014x** |
| R6 AES-256 | 2.9K/s | 589/s | **5x** |

## Time to Crack Estimates (Single M4 Pro)

### R3 128-bit (812K/s with NEON, most common revision)

Full charset (a-z, A-Z, 0-9 = 62 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 4 | 15M | 18 seconds |
| 5 | 931M | 19 minutes |
| 6 | 57.7B | 20 hours |
| 7 | 3.5T | 50 days |
| 8 | 221T | 8.6 years |

Digits only (10 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 6 | 1.1M | 1.4 seconds |
| 8 | 111M | 2.3 minutes |
| 10 | 11.1B | 3.8 hours |
| 12 | 1.1T | 16 days |

### R5 AES-256 (104M/s with GPU)

Full charset:

| Max Length | Keyspace | Time |
|------------|----------|------|
| 4 | 15M | instant |
| 5 | 931M | 9 seconds |
| 6 | 57.7B | 9 minutes |
| 7 | 3.5T | 9.4 hours |
| 8 | 221T | 24 days |

### Distributed scaling

Adding more machines scales roughly linearly. Two M4 Pros cut all times in half. The lease-based work distribution has minimal overhead — machines can join and leave freely without losing work.

## How the Crypto Works

### R2/R3/R4 (MD5 + RC4)

1. **Key derivation** (MD5): Hash the candidate password with document metadata (owner hash, permissions, file ID). For R3/R4, iterate MD5 50 times on the result.
2. **Verification** (RC4): Encrypt a known plaintext with the derived key. For R2, one RC4 pass. For R3/R4, 20 RC4 passes with XOR-modified keys.
3. **Compare**: Check against the stored /U value in the PDF.

NEON SIMD accelerates step 1 by running 4 independent MD5 computations in parallel using 128-bit vector registers. RC4 (step 2) remains scalar since it has data-dependent memory access patterns.

### R5 (SHA-256)

Simple: SHA-256(password + validation salt) compared against stored hash. No iteration, no RC4. The Metal GPU does the entire verification — SHA-256 + compare — with no CPU round-trip, enabling 104M/s throughput.

### R6 (SHA-256 + AES-CBC iterative KDF)

Deliberately expensive: a loop of SHA-256/384/512 + AES-CBC that runs 64+ rounds, with the round count determined by the hash output. Designed to resist GPU attacks. Each verification takes ~70 microseconds — there's no shortcut.

## Acceleration Techniques

| Technique | Applicable To | Speedup | How It Works |
|-----------|--------------|---------|-------------|
| NEON SIMD | R2, R3, R4 | ~4x | 4 passwords per core using ARM vector registers |
| Metal GPU (MD5) | R2, R3, R4 | ~1.3x* | MD5 key derivation on GPU, RC4 on CPU |
| Metal GPU (SHA-256) | R5 | ~5x | Full verification on GPU, no CPU work |
| Frequency ordering | All | varies | Try common characters first (`-F` flag) |

*GPU MD5 is slower than NEON SIMD for R2-R4. Use `-G` to prefer NEON.
