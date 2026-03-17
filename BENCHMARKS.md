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

Optimal configuration for each revision using all available acceleration.
Speeds are measured from the live progress meter during an actual brute-force run.

| Revision | Encryption | Speed | Engine | Notes |
|----------|-----------|-------|--------|-------|
| R2 | 40-bit RC4 | **~5.5M/s** | CPU + NEON SIMD | 4-way parallel MD5 per core |
| R3 | 128-bit RC4 | **~265K/s** | CPU + NEON SIMD + GPU | RC4 20-pass bottleneck limits NEON gain |
| R4 | AES-128 | **~245K/s** | CPU + NEON SIMD + GPU | Same crypto as R3 |
| R5 | AES-256 / SHA-256 | **~45M/s** | GPU | GPU does full SHA-256 verification |
| R6 | AES-256 / SHA-256+KDF | **~15.6K/s** | GPU+CPU cooperative | Metal GPU + 14 CPU threads + NEON SHA-512 |

### Optimization History

| Revision | Phase 1 (CommonCrypto) | Phase 2 (Metal GPU) | Phase 3 (NEON SIMD) | Phase 4 (GPU+NEON simultaneous) |
|----------|----------------------|--------------------|--------------------|--------------------------------|
| R2 | 3.5M/s | 3.8M/s (+9%) | **~5M/s (+32%)** | **~5.5M/s (+10%)** |
| R3 | 188K/s | ~240K/s (+28%) | **~265K/s (+10%)** | **~265K/s (parity)** |
| R5 | 20M/s | 20M/s (CPU only) | **~45M/s (+125%)** | — |
| R6 | — | 7K/s | ~14K/s (+100%) | **~15.6K/s (+11%)** |

> **Note on R3/R4 NEON:** NEON parallelises the MD5 key derivation 4× but the 20-pass RC4
> verification remains serial. Because RC4 dominates at 128-bit key lengths, the measured
> end-to-end speedup is ~1.5× over 14 scalar cores (265K vs 185K/s), not the ~4× one might
> expect from NEON alone. The `Bench` estimate printed at startup reflects per-core throughput
> extrapolated linearly; actual wall-clock throughput will be lower due to RC4 contention.

---

## Engine Comparison

### R2 40-bit (per engine)

| Engine | Speed |
|--------|-------|
| Single core | ~370K/s |
| 14 cores scalar | ~4.3M/s |
| 14 cores + NEON SIMD | **~5.5M/s** |
| GPU (Metal MD5) | ~450K/s (slower than NEON) |

### R3 128-bit (per engine)

| Engine | Speed |
|--------|-------|
| Single core | ~16K/s |
| 14 cores scalar | ~185K/s |
| 14 cores + NEON SIMD | **~265K/s** |
| GPU (Metal MD5 + CPU RC4) | ~20K/s alone; combined with NEON ≈ parity |

NEON processes 4 passwords per core simultaneously for the MD5 key derivation step.
The GPU MD5 path is slower for R3/R4 due to the RC4 CPU bottleneck. GPU and NEON run
simultaneously (sharing a work counter) — for R2 the GPU is skipped because NEON alone wins.

### R5 AES-256 (per engine)

| Engine | Speed |
|--------|-------|
| Single core | ~22M/s |
| 14 cores | ~4.8M/s* |
| GPU (Metal SHA-256) | **~45M/s** |

*Multi-core is slower than single-core for R5 because the SHA-256 check is so fast that thread overhead dominates. GPU is the clear winner — it does the full verification (SHA-256 + compare) entirely on-chip with no CPU round-trip. R5 uses an async double-buffered GPU pipeline for optimal throughput.

### R6 AES-256 KDF (per engine)

| Engine | Speed |
|--------|-------|
| Single core | ~1,200/s |
| 14 cores | ~14,600/s |
| GPU (Metal SHA-256/384/512 + AES) | ~6,900/s |
| GPU+CPU cooperative | **~15,600/s** |

R6 uses Algorithm 2.B — an iterative KDF with SHA-256/384/512 and AES-CBC that runs 64+ rounds. The GPU kernel implements the full algorithm on-device. CPU and GPU share a work counter for cooperative processing. The CPU path uses NEON SHA-384/512 hardware intrinsics (ARM Crypto Extensions) for the ~67% of KDF iterations that use SHA-384/512, providing a measurable speedup over CommonCrypto. The double-dispatch pipeline overlaps GPU compute with CPU password preparation, and sub-batch dispatching enables early termination on match.

---

## Single-Core Performance vs CoreGraphics API

Our direct crypto implementation vs Apple's CGPDFDocument API (which pdfcracker replaces):

| Revision | Direct Crypto | CoreGraphics API | Speedup |
|----------|--------------|-----------------|---------|
| R2 40-bit | ~960K/s | ~20K/s | **~48x** |
| R3 128-bit | ~50K/s | ~5.3K/s | **~9x** |
| R4 AES-128 | ~50K/s | ~5.2K/s | **~10x** |
| R5 AES-256 | ~22M/s | ~20K/s | **~1,100x** |
| R6 AES-256 | ~3.3K/s | ~580/s | **~5.7x** |

---

## Time to Crack Estimates (Single M4 Pro)

### R6 AES-256 KDF (~15.6K/s cooperative GPU+CPU)

Full charset (62 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 4 | 15M | 16 minutes |
| 5 | 931M | 17 hours |
| 6 | 57.7B | 43 days |

Digits only (10 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 6 | 1.1M | 71 seconds |
| 8 | 111M | 2 hours |
| 10 | 11.1B | 8 days |

### R3 128-bit (~265K/s with NEON, most common revision)

Full charset (a-z, A-Z, 0-9 = 62 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 4 | 15M | 57 seconds |
| 5 | 931M | 59 minutes |
| 6 | 57.7B | 60 hours |
| 7 | 3.5T | 154 days |
| 8 | 221T | 26 years |

Digits only (10 characters):

| Max Length | Keyspace | Time |
|------------|----------|------|
| 6 | 1.1M | 4 seconds |
| 8 | 111M | 7 minutes |
| 10 | 11.1B | 12 hours |
| 12 | 1.1T | 48 days |

### R5 AES-256 (~45M/s with GPU)

Full charset:

| Max Length | Keyspace | Time |
|------------|----------|------|
| 4 | 15M | instant |
| 5 | 931M | 21 seconds |
| 6 | 57.7B | 21 minutes |
| 7 | 3.5T | 22 hours |
| 8 | 221T | 57 days |

### Distributed scaling

Adding more machines scales roughly linearly. Two M4 Pros cut all times in half. The lease-based work distribution has minimal overhead — machines can join and leave freely without losing work.

---

## How the Crypto Works

### R2/R3/R4 (MD5 + RC4)

1. **Key derivation** (MD5): Hash the candidate password with document metadata (owner hash, permissions, file ID). For R3/R4, iterate MD5 50 times on the result.
2. **Verification** (RC4): Encrypt a known plaintext with the derived key. For R2, one RC4 pass. For R3/R4, 20 RC4 passes with XOR-modified keys.
3. **Compare**: Check against the stored /U value in the PDF.

NEON SIMD accelerates step 1 by running 4 independent MD5 computations in parallel using 128-bit vector registers. RC4 (step 2) remains scalar since it has data-dependent memory access patterns that prevent vectorisation. For R3/R4, step 2 is the binding constraint — actual throughput is ~1.5× over scalar, not the ~4× theoretical NEON ceiling.

### R5 (SHA-256)

Simple: SHA-256(password + validation salt) compared against stored hash. No iteration, no RC4. The Metal GPU does the entire verification — SHA-256 + compare — with no CPU round-trip. An async double-buffered pipeline overlaps password preparation with GPU compute for maximum throughput.

### R6 (SHA-256 + AES-CBC iterative KDF)

Deliberately expensive: a loop of SHA-256/384/512 + AES-CBC that runs 64+ rounds, with the round count determined by the hash output. Designed to resist GPU attacks. Each verification takes ~60-70 microseconds — there's no shortcut.

---

## Acceleration Techniques

| Technique | Applicable To | Speedup | How It Works |
|-----------|--------------|---------|-------------|
| NEON SIMD | R2, R3, R4 | ~4× MD5; ~1.5× E2E for R3/R4 | 4 passwords per core using ARM vector registers |
| Metal GPU (MD5) | R2, R3, R4 | +10-20% alongside NEON | MD5 key derivation on GPU, RC4 on CPU |
| Metal GPU (SHA-256) | R5 | ~6× vs CPU | Full verification on GPU, no CPU work |
| Metal GPU (Algorithm 2.B) | R6 | ~5× vs 1-core | Full R6 KDF on GPU with double-dispatch pipeline |
| GPU+CPU cooperative | R2–R4, R6 | additive throughput | Shared work counter; GPU and NEON run simultaneously |
| NEON SHA-256/AES intrinsics | R6 CPU | ~11% | Hardware crypto for R6 CPU KDF path (SHA-384/512) |
| R5 async pipeline | R5 | overlap | Double-buffered GPU dispatch, no CPU stalls |
| Sub-batch dispatch | R6 | early exit | Split GPU batch for early termination on match |
| Frequency ordering | All | varies | Try common characters first (`-F` flag) |
