# pdfcracker — Session Handoff (2026-06-12)

Read this first if you're a future Claude session picking up this project. It tells you the current state, exactly what's left, and how to do it safely.

## TL;DR

A large hardening/refactor effort is **complete and merged to `master`** (49 commits, pushed to `origin`). Everything builds clean and passes: `make test` → 80 + saslprep + 6, `bash test_integration.sh` → 45/0, cracks verified R2–R6. The full plan and its checkboxes are in [`docs/superpowers/plans/2026-06-11-pdfcracker-hardening.md`](superpowers/plans/2026-06-11-pdfcracker-hardening.md).

**Three things were deliberately deferred and are the open work** — all GPU-related and all gated on the machine being idle (the owner had a heavy GPU task — Topaz + Python — running, which skews GPU benchmarks low and makes perf work unmeasurable). Do them when the GPU is free.

## How to build & verify (always do this before and after changes)

```bash
make                       # clean build, 0 warnings expected
make test                  # test_all (80) + saslprep + test_crypto (6)
bash test_integration.sh   # 45 passed, 0 failed
```
GPU correctness smoke (the real gate for any Metal change) — each must print "found":
```bash
printf 'z\ntest123\n' > /tmp/t.txt; ./pdfcrack -f test_encrypted.pdf  -d /tmp/t.txt --no-pot | grep -i found  # R3 (keygen GPU)
printf 'z\npass256\n' > /tmp/t.txt; ./pdfcrack -f test_r5_aes256.pdf   -d /tmp/t.txt --no-pot | grep -i found  # R5 (sha256 GPU)
printf 'z\nuser_r6\n' > /tmp/t.txt; ./pdfcrack -f test_pikepdf_r6.pdf  -d /tmp/t.txt --no-pot | grep -i found  # R6 (KDF GPU)
rm -f /tmp/t.txt
```
For ANY change to R5/R6 crypto, ALSO verify it does NOT false-positive (a broken KDF can "match" garbage):
```bash
printf 'wrong1\nwrong2\n' > /tmp/t.txt; ./pdfcrack -f test_pikepdf_r6.pdf -d /tmp/t.txt --no-pot | grep -iE 'found|not found'  # must say NOT found
rm -f /tmp/t.txt
```

Commit/push policy for this repo: **solo project, push straight to `master`, no PRs** (owner's explicit preference). Branch first only if doing something risky, then fast-forward.

---

## OPEN WORK

### 1. Finish Phase 8 — re-run benchmarks on an idle GPU, then update the docs

The documented speeds in `BENCHMARKS.md` and the README `## Performance` section are the PRE-optimization numbers measured from the live progress meter on an idle M4 Pro. The performance pass (Phase 6) changed the GPU path (R6 on-the-fly K1, Private-storage scratch, dropped per-batch memset), so R5/R6 may now be faster. **The numbers were NOT updated** because the GPU was loaded during this session (R6 single-core read 1168/s vs the documented ~3.3K/s — pure load skew, not a regression).

**Do this when the GPU is idle:**
1. Confirm idle: `bash bench.sh` — it prints a load warning if anything is burning >40% CPU/GPU. Wait until there's no warning.
2. Quick per-engine snapshot: `bash bench.sh`.
3. Doc-grade numbers come from the LIVE progress meter during a real attack, not from `-B`. For each revision, run a real attack with a charset that won't hit quickly, let the `.../s` meter stabilize (~10s), record it, Ctrl-C. Example for R5:
   `./pdfcrack -f test_r5_aes256.pdf -b -l 7 -c abcdefghij` → read steady-state rate.
   Do the same for R2 (`test_r2_40bit.pdf`), R3 (`test_encrypted.pdf`), R4 (`test_r4_aes128.pdf`), R6 (`test_pikepdf_r6.pdf`).
4. Update the R2–R6 rows in BOTH `BENCHMARKS.md` (the "Best Speeds" table) and `README.md` (the `## Performance` table). Also refresh the **time-to-crack estimate tables** in the README that derive from those rates.
5. If numbers are unchanged within noise, just note that the refactor preserved throughput.
6. Commit: `docs(bench): refresh R2–R6 throughput measured on idle M4 Pro`.

Reference baseline (documented, idle, pre-Phase-6): R2 ~5.5M/s · R3 ~265K/s · R4 ~245K/s · R5 ~45M/s · R6 ~15.6K/s.

### 2. Deferred Task 6.7 — move RC4 U-verification onto the GPU (R2–R4)

Today R2–R4 derive keys on the GPU (`metal_keygen`) and verify RC4 on the CPU (`verify_keys_rc4` in pdfcrack.c). Moving the RC4 Algorithm-4/5 U-comparison into a Metal kernel that returns a compact match index (mirroring `pdf_sha256_verify` / `pdf_r6_verify`) would drop the 4MB/batch key copy-out and the CPU RC4 loop. Full spec: plan Task 6.7 (line ~1248). **High risk** (new crypto kernel on the most common revisions), **unmeasurable benefit until benchmarked**. Gate strictly on the correctness smokes above (R2/R3/R4 find the real password AND correctly reject wrong ones). Acceptable to abandon if it can't be kept provably correct.

### 3. Deferred Task 7.1 — GPU owner-password search for R2–R4

Owner recovery (Algorithm 3 → decrypt `/O` → verify against `/U`) is CPU-only for R2–R4. Reuse the RC4 kernel from 6.7, so **do 6.7 first**. Plan Task 7.1 (line ~1285). Verify with `-O` owner cracks on R3/R4 (`owner456` / `owneraes`).

### 4. Deferred Task 7.6 — distributed TLS + PDF content-addressed caching

The distributed protocol is unauthenticated cleartext (Phase 4 added a trusted-LAN warning, a bootstrap-binary checksum in `join.sh`, web-port auth, and an optional shared-secret handshake — but no transport encryption). Adding optional TLS (Security.framework) and skipping PDF re-send/re-benchmark for reconnecting clients (key by `pdf_sha256`) are the remaining items. Plan Task 7.6 (line ~1366). Larger, lower urgency.

---

## Important context for whoever continues

### The worker-consolidation pattern (Phase 5.3)
`pdfcrack.c` used to have ~38 near-duplicate worker functions. They were consolidated into **engine drivers** + **candidate generators**:
- Drivers (one per engine): `run_gpu_sha256` (R5), `run_gpu_r6` (R6), `run_gpu_md5` (R3/R4 rule+hybrid), `run_cpu` (CPU scalar). Each owns the fetch/double-buffer/verify/found scaffold.
- Generators: `cand_gen` typedef + `sha256_*_gen` functions (the names are cosmetic — they're engine-independent index→candidate functions, reused across drivers).

**Some workers were deliberately LEFT bespoke** (look for `kept bespoke:` comments) because they don't fit the `cand_gen(idx)→string` model — do NOT try to force them in:
- `brute_worker` / `gpu_brute_worker` — multi-length + async double-buffered + `inc_pass` optimization.
- `dict_worker` / `gpu_dict_worker` — `--reverse` mode + interleaved partitioning + async.
- `brute_worker_neon` / `dict_worker_neon` — 4-way NEON SIMD.
- `rule_worker` — `rule_dedup_check()` inside the inner loop.
- `toggle_worker` — per-word alpha-position scan + variant fan-out.
- `prince_worker` / `prince_rule_worker` / `incr_consumer_worker` — entirely different structures.

If you ever consolidate one of these, use the same discipline that worked here: read the old body, confirm the generator produces byte-identical candidates, and **stop + report rather than silently change behavior** if it doesn't.

### Gotchas
- **Flaky integration test:** test 27 "Checkpoint resume end-to-end" (test_integration.sh ~230) interrupts at 2s then must brute its way to `passaes` within 60s — it's timing/throughput-dependent and **flakes under heavy load** (saw a spurious 44/1 during this session that was load, not a bug; it passes reliably in isolation). If you see exactly that one test fail, re-run it standalone before assuming a regression. Consider making it load-robust (smaller keyspace that still doesn't finish in 2s, or a longer resume timeout) if it keeps flaking.
- **Fuzzers need Homebrew LLVM:** Apple clang lacks the libFuzzer runtime. `make fuzz-rules` / `make fuzz-parse` use `FUZZ_CC` (defaults to `/opt/homebrew/opt/llvm/bin/clang`, falls back to `clang`). CI installs LLVM and passes `FUZZ_CC=$(brew --prefix llvm)/bin/clang`.
- **GPU structs are shared:** `PDFEncryptGPU`/`PDFR5GPU`/`PDFR6GPU`/`R6_SCRATCH_SIZE` live in `pdf_gpu_types.h`, included by BOTH `metal_keygen.m` and `pdf_md5.metal`. Edit them in ONE place; field layout must stay identical on host and GPU.
- **Metal frees must nil ObjC fields:** the `metal_*_free` functions null out every `id` field before `free(ctx)` (ARC won't release heap-struct fields otherwise). Preserve that pattern if you touch the contexts.
- **CI:** `.github/workflows/ci.yml` runs on `macos-14` (Apple Silicon, has the Metal toolchain). It builds, runs all unit + integration tests, an ASan/UBSan job, and a fuzz smoke. There's no Intel lane — "Intel supported" in the README is plausible (NEON/Metal are guarded) but **unverified**.

### Key files
| File | Role |
|------|------|
| `pdfcrack.c` (~6800 lines) | Cracker: attack modes, engine drivers + generators, workers, main |
| `pdf_encrypt.c` | Parser + all crypto (R2–R6); `/Perms` validation; NUL-safe owner recovery |
| `rules.c`/`rules.h` | Rule engine (linked by both the cracker and the fuzzer) |
| `metal_keygen.m` + `pdf_md5.metal` + `pdf_gpu_types.h` | GPU pipelines (R6 K1 is generated on-the-fly via `aes128_cbc_encrypt_from_seq`) |
| `server.c` / `client.c` / `protocol.h` | Distributed coordinator/worker (one unified HTTP dashboard now) |
| `checkpoint.c`/`.h` | Versioned, corruption-tolerant, document-bound checkpoints |
| `bench.sh` | Benchmark harness (run on idle machine) |
| `docs/superpowers/plans/2026-06-11-pdfcracker-hardening.md` | The full plan with every task + acceptance criteria |
