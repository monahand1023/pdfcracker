# pdfcracker Hardening & Improvement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address every finding from the codebase review — correctness/crash bugs, security gaps, test/CI absence, the worker-function duplication, performance opportunities, and feature gaps — without changing the crypto math that already works.

**Architecture:** Work proceeds in 7 dependency-ordered phases. Phase 1 stops active bugs with surgical fixes + regression tests. Phase 2 builds the test/CI safety net that protects everything after it. Phases 3–4 harden checkpointing and the distributed system. Phase 5 is the large maintainability refactor (worker consolidation) that later phases ride on. Phases 6–7 are performance and features. Each phase produces working, tested software on its own and can be merged independently.

**Tech Stack:** C11 (clang `-O3`), Objective-C + Metal (Apple Silicon GPU), ARM NEON / Crypto Extensions intrinsics, pthreads, CommonCrypto/CoreGraphics/Security frameworks, POSIX sockets. Build via `make`. Tests: `test_all.c` (unit, links `pdf_encrypt.o`), `test_integration.sh` (end-to-end CLI), `fuzz_rules.c` (libFuzzer).

---

## Phase ordering & dependencies

| Phase | Theme | Depends on | Mergeable alone |
|-------|-------|-----------|-----------------|
| 1 | Critical correctness & crash fixes | — | ✅ |
| 2 | Test & CI foundation | 1 (regression tests live here) | ✅ |
| 3 | Checkpoint robustness | 2 | ✅ |
| 4 | Distributed security & correctness | 2 | ✅ |
| 5 | Maintainability refactor (worker consolidation) | 2 (needs CI to be safe) | ✅ |
| 6 | Performance | 5 (easier after consolidation) | ✅ |
| 7 | Features & robustness | 5 | ✅ |

**Rule for every task:** make the change, build (`make`), run `make test` (defined in Task 2.1), commit. Each task below ends in a commit.

---

## File structure (created / modified)

- **New:** `rules.c`, `rules.h` (extracted rule engine, Task 5.1)
- **New:** `pdf_gpu_types.h` (GPU structs shared by `.m` and `.metal`, Task 5.2)
- **New:** `workers.h` (engine-driver + candidate-generator interface, Task 5.3)
- **New:** `test_parse_fuzz.c` (ASan malformed-PDF harness, Task 2.6)
- **New:** `.github/workflows/ci.yml` (Task 2.2)
- **Modified (heavily):** `pdfcrack.c`, `server.c`, `client.c`, `checkpoint.c`, `metal_keygen.m`, `pdf_md5.metal`, `pdf_encrypt.c`, `Makefile`, `test_integration.sh`, `README.md`

---

# Phase 1 — Critical correctness & crash fixes

These are small, localized, and high-value. Each gets a regression test (some tests land in Phase 2 where the harness is built; cross-referenced below).

### Task 1.1: Fix infinite recursion in distributed client verify (CRITICAL)

`client.c:188-195` — `test_password_fast_mode` recurses forever in the default `PW_MODE_BOTH`. This is the CPU verify path for every local brute/dict worker, so the distributed client never works in default mode.

**Files:**
- Modify: `client.c:188-195`
- Test: `test_integration.sh` (added in Task 2.4)

- [ ] **Step 1: Apply the fix**

Replace:
```c
static inline int test_password_fast_mode(const char *pass)
{
    if (g_password_mode == PW_MODE_USER)
        return pdf_verify_user_password(&g_enc_params, pass);
    if (g_password_mode == PW_MODE_OWNER)
        return pdf_verify_owner_password(&g_enc_params, pass);
    return test_password_fast_mode(pass);
}
```
with:
```c
static inline int test_password_fast_mode(const char *pass)
{
    if (g_password_mode == PW_MODE_USER)
        return pdf_verify_user_password(&g_enc_params, pass);
    if (g_password_mode == PW_MODE_OWNER)
        return pdf_verify_owner_password(&g_enc_params, pass);
    /* PW_MODE_BOTH */
    return pdf_verify_user_password(&g_enc_params, pass)
        || pdf_verify_owner_password(&g_enc_params, pass);
}
```

- [ ] **Step 2: Build**

Run: `make client`
Expected: compiles clean.

- [ ] **Step 3: Commit**

```bash
git add client.c
git commit -m "fix(client): stop infinite recursion in BOTH-mode CPU verify path

test_password_fast_mode recursed on itself for PW_MODE_BOTH (the default),
hanging/crashing every distributed client running the CPU verify path.
Now ORs the user and owner checks."
```

Regression test added in Task 2.4 (distributed loopback).

---

### Task 1.2: Clamp brute-force `-l` to MAX_PASS_LEN (CRITICAL — stack overflow)

`pdfcrack.c:6334` validates `-l` to `1..127`, but candidate buffers are `char pass[MAX_PASS_LEN+1]` (33 bytes). `-l 40` overflows the stack via `index_to_pass`.

**Files:**
- Modify: `pdfcrack.c` (after the prefix/suffix length adjustment at `6626-6631`)
- Test: `test_integration.sh` (Task 2.3)

- [ ] **Step 1: Add the clamp**

After line `6630` (`if (max_len < 0) max_len = 0;`) and the closing brace at `6631`, insert a clamp that covers both the interactive and non-interactive paths. Add immediately after line `6631`:
```c
    /* Brute-force candidate buffers are MAX_PASS_LEN; the middle we
     * actually enumerate cannot exceed it (prefix/suffix are separate). */
    if (max_len > MAX_PASS_LEN - g_prefix_len - g_suffix_len) {
        max_len = MAX_PASS_LEN - g_prefix_len - g_suffix_len;
        fprintf(stderr, "Note: max length clamped to %d (buffer limit)\n", max_len);
    }
    if (min_len > max_len) min_len = max_len;
```

- [ ] **Step 2: Build and smoke-test**

Run: `make pdfcrack && ./pdfcrack -f test_r2_40bit.pdf -b -l 40 -B`
Expected: prints the clamp note, runs benchmark, no crash.

- [ ] **Step 3: Commit**

```bash
git add pdfcrack.c
git commit -m "fix(brute): clamp -l to MAX_PASS_LEN to prevent stack overflow

-l accepted up to 127 but candidate buffers are MAX_PASS_LEN(32)+1.
index_to_pass wrote past the buffer for -l > 32."
```

ASan regression added in Task 2.3.

---

### Task 1.3: Stop truncating the found password in concatenating modes (HIGH)

`g_password` is `MAX_PASS_LEN+1` (33) but rule/hybrid/combinator/mutate candidates are up to 66 bytes. A long match is found but reported truncated/wrong.

**Files:**
- Modify: `pdfcrack.c:70` and all `strncpy(g_password, …, MAX_PASS_LEN)` sites
- Test: `test_all.c` (Task 2.5) — verify a >32-char rule candidate reports in full

- [ ] **Step 1: Enlarge the buffer**

Change `pdfcrack.c:70`:
```c
static char        g_password[MAX_PASS_LEN + 1] = {0};
```
to:
```c
/* Sized for concatenating modes (rule/hybrid/combinator/mutate) whose
 * candidate buffers are up to MAX_PASS_LEN*2 + 2. */
static char        g_password[MAX_PASS_LEN * 2 + 1] = {0};
```

- [ ] **Step 2: Copy the full candidate, not MAX_PASS_LEN bytes**

Replace every `strncpy(g_password, <X>, MAX_PASS_LEN)` with `strncpy(g_password, <X>, sizeof(g_password) - 1)`. There are ~40 sites (grep `strncpy(g_password,`). Mechanical, e.g.:
```bash
# inspect first, then apply
grep -n 'strncpy(g_password,.*MAX_PASS_LEN)' pdfcrack.c | wc -l
perl -0pi -e 's/strncpy\(g_password,\s*(.*?),\s*MAX_PASS_LEN\)/strncpy(g_password, $1, sizeof(g_password) - 1)/g' pdfcrack.c
```
All source buffers (`pass`, `pw[b]`, `g_words[i]`, `rev`, `datepw`, …) are ≤ 65 bytes, so copying `sizeof(g_password)-1` (64) never over-reads.

- [ ] **Step 3: Build**

Run: `make pdfcrack`
Expected: clean compile.

- [ ] **Step 4: Commit**

```bash
git add pdfcrack.c
git commit -m "fix: report full found password in concatenating modes

g_password was 33 bytes; rule/hybrid/combinator/mutate candidates can be
up to 64. A long match was found but printed truncated."
```

---

### Task 1.4: Bounds-guard three parser over-reads on malformed PDFs (HIGH)

`pdf_encrypt.c` parses untrusted input; three sites read up to 5 bytes past the `malloc(st_size)` buffer.

**Files:**
- Modify: `pdf_encrypt.c:292`, `:348`, `:439`
- Test: `test_parse_fuzz.c` (Task 2.6)

- [ ] **Step 1: Guard the trailer `<<` check (line 292)**

Replace:
```c
    if (*dict_start != '<' || *(dict_start + 1) != '<') {
```
with:
```c
    if (dict_start + 1 >= end || *dict_start != '<' || *(dict_start + 1) != '<') {
```

- [ ] **Step 2: Guard the inline-dict check (line 348)**

Replace:
```c
    if (*encrypt_val == '<' && encrypt_val + 1 < end && *(encrypt_val + 1) == '<') {
```
with:
```c
    if (encrypt_val < end && *encrypt_val == '<' &&
        encrypt_val + 1 < end && *(encrypt_val + 1) == '<') {
```

- [ ] **Step 3: Guard the `EncryptMetadata` memcmp (line 439)**

Replace:
```c
        if (memcmp(val, "false", 5) == 0)
```
with:
```c
        if (end - val >= 5 && memcmp(val, "false", 5) == 0)
```

- [ ] **Step 4: Build and run existing unit tests**

Run: `make test_all && ./test_all`
Expected: all existing tests still pass (these are well-formed PDFs).

- [ ] **Step 5: Commit**

```bash
git add pdf_encrypt.c
git commit -m "fix(parse): bounds-check three over-reads on malformed PDF input

dict_start (:292), encrypt_val (:348), and EncryptMetadata memcmp (:439)
could read past the file buffer on truncated/crafted PDFs."
```

ASan fuzz regression in Task 2.6.

---

### Task 1.5: Clamp untrusted lengths feeding fixed buffers (HIGH — memory safety)

Two more untrusted-input → fixed-buffer paths: GPU `file_id_len` (`metal_keygen.m:166` into `uchar file_id[48]`) and R6 `algorithm_2b` assuming `pw_len ≤ 127`.

**Files:**
- Modify: `pdf_encrypt.c` (clamp `file_id_len` and add `algorithm_2b` guard)
- Modify: `metal_keygen.m:166` (defensive clamp)

- [ ] **Step 1: Clamp `file_id_len` at parse time**

In `pdf_parse_encrypt` where `params.file_id_len` is set from the parsed `/ID`, add after assignment:
```c
    if (params.file_id_len > 48) params.file_id_len = 48;
```
Find the exact assignment site: `grep -n 'file_id_len' pdf_encrypt.c`.

- [ ] **Step 2: Defensive clamp at the GPU memcpy (`metal_keygen.m:166`)**

Replace the `memcpy(gpu_params.file_id, params->file_id, params->file_id_len)` line with a clamped length:
```c
    size_t fid = params->file_id_len > 48 ? 48 : params->file_id_len;
    memcpy(gpu_params.file_id, params->file_id, fid);
```

- [ ] **Step 3: Guard `algorithm_2b` password length**

At the top of `algorithm_2b` (`pdf_encrypt.c:638` region), before any write into `init_buf`/`K1`, add:
```c
    if (pw_len > 127) return; /* normalize_password_r6 caps at 127; defend the buffers */
```

- [ ] **Step 4: Build + unit tests**

Run: `make && make test_all && ./test_all`
Expected: clean, all pass.

- [ ] **Step 5: Commit**

```bash
git add pdf_encrypt.c metal_keygen.m
git commit -m "fix: clamp untrusted file_id_len and pw_len before fixed-buffer writes"
```

---

### Task 1.6: Document/assert `md5_x4` equal-length contract (MEDIUM, latent)

`md5_simd.h:233-246` produces wrong digests for unequal-length lanes; the header claims otherwise. No current caller hits it.

**Files:**
- Modify: `md5_simd.h` (doc + debug assert)

- [ ] **Step 1: Correct the doc and add an assert**

At the `md5_x4` declaration (`md5_simd.h:188` region), change the comment claiming "Each message can have a different length" to state lanes must share a block count, and add at function entry:
```c
    /* Contract: all four lanes must have equal length (same block count).
     * The re-pad path is only valid under that assumption. */
    assert(len0 == len1 && len1 == len2 && len2 == len3);
```
(Include `<assert.h>` if not already.) If a future caller needs ragged lengths, process per-lane block counts instead.

- [ ] **Step 2: Build + tests**

Run: `make test_all && ./test_all`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add md5_simd.h
git commit -m "docs(md5_simd): document md5_x4 equal-length contract + debug assert"
```

---

# Phase 2 — Test & CI foundation

Build the safety net before the big refactor. This phase also lands the regression tests for Phase 1.

### Task 2.1: Fix the Makefile (test_crypto rule, `make test` aggregate)

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add a `test_crypto` build rule** (mirrors `test_all`, currently only referenced in `clean`)

```makefile
test_crypto: test_crypto.c pdf_encrypt.o saslprep.o pdf_encrypt.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) -o $@ test_crypto.c pdf_encrypt.o saslprep.o
```

- [ ] **Step 2: Add a `test` aggregate target**

```makefile
test: test_all test_saslprep test_crypto
	./test_all
	./test_saslprep
	./test_crypto

.PHONY: all clean test-integration fuzz-rules pgo test
```
(Merge the `test` name into the existing `.PHONY` line.)

- [ ] **Step 3: Verify**

Run: `make test`
Expected: all three suites build and pass.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "build: add test_crypto rule and 'make test' aggregate"
```

---

### Task 2.2: Add GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: CI
on: [push, pull_request]
jobs:
  build-test:
    runs-on: macos-14   # Apple Silicon runner (has Metal toolchain)
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: make
      - name: Unit tests
        run: make test
      - name: Integration tests
        run: bash test_integration.sh
      - name: Build rules fuzzer
        run: make fuzz-rules
      - name: Smoke-fuzz rules (30s)
        run: ./fuzz_rules -max_total_time=30 || true
  asan:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - name: ASan unit + parser fuzz
        run: |
          make CFLAGS="-O1 -g -fsanitize=address,undefined -Wall" test_all test_crypto
          ./test_all && ./test_crypto
```

- [ ] **Step 2: Verify locally** that `make` + `make test` + `bash test_integration.sh` pass before relying on CI (Tasks 2.3–2.6 make integration hermetic).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions build/test/asan/fuzz on macos-14"
```

---

### Task 2.3: Make integration tests hermetic + add `-l` overflow regression

**Files:**
- Modify: `test_integration.sh`

- [ ] **Step 1: Isolate HOME and the pot file**

At the top of `test_integration.sh`, after the shebang, add:
```bash
export HOME="$(mktemp -d)"        # never touch the real ~/.pdfcracker
trap 'rm -rf "$HOME"' EXIT
```
Remove the hard-coded `rm -f ~/.pdfcracker/pdfcracker.pot` (test 17) — now redundant.

- [ ] **Step 2: Soften the hardware benchmark gate** (test 32, the `>= 10000/s` assert)

Replace the absolute throughput assertion with a "produced a number > 0" check so headless/slow runners don't flake:
```bash
rate=$(./pdfcrack -f test_r4_aes128.pdf -B 2>&1 | grep -oE '[0-9]+/s' | head -1 | tr -d '/s')
[ "${rate:-0}" -gt 0 ] && pass || fail
```

- [ ] **Step 3: Add a clamp/overflow regression for Task 1.2**

```bash
# Task 1.2: -l beyond MAX_PASS_LEN must clamp, not crash
out=$(./pdfcrack -f test_r2_40bit.pdf -b -l 40 -B 2>&1)
echo "$out" | grep -q "clamped" && pass || fail
```

- [ ] **Step 4: Run**

Run: `bash test_integration.sh`
Expected: all pass, real `~/.pdfcracker` untouched.

- [ ] **Step 5: Commit**

```bash
git add test_integration.sh
git commit -m "test: make integration tests hermetic; add -l clamp regression"
```

---

### Task 2.4: Distributed loopback test (regression for Task 1.1)

**Files:**
- Modify: `test_integration.sh` (new test block)

- [ ] **Step 1: Add a server↔client loopback test in default BOTH mode**

```bash
# Distributed: server + client must find the password in default (BOTH) mode.
# Regression for the client recursion bug (Task 1.1).
PORT=19999
./server -f test_r4_aes128.pdf -d <(printf 'wrong1\nwrong2\npassaes\n') -p $PORT &
SRV=$!
sleep 1
timeout 30 ./client 127.0.0.1 $PORT
RC=$?
wait $SRV 2>/dev/null
# client must exit cleanly (not hang/crash) and server must report found
[ $RC -eq 0 ] && pass || fail
```
(Adjust to the actual `server`/`client` CLI; confirm the wordlist injection form with `./server --help`. If `server` requires a real wordlist file, write one to `$HOME/wl.txt`.)

- [ ] **Step 2: Run before and after the Task 1.1 fix** to confirm it fails on the bug and passes on the fix.

Run: `bash test_integration.sh`
Expected: passes with Task 1.1 applied; would hang/timeout without it.

- [ ] **Step 3: Commit**

```bash
git add test_integration.sh
git commit -m "test: add distributed loopback test covering default BOTH mode"
```

---

### Task 2.5: Real GPU-vs-CPU and NEON-vs-scalar cross-validation (incl. R5/R6)

The current `test_all.c` "NEON vs scalar" asserts a hard-coded bitmask and skips `revision >= 5`; the integration "GPU vs CPU consistency" test runs only one path.

**Files:**
- Modify: `test_all.c` (cross-validate batch4 against scalar across ALL revisions, incl. the long-password case for Task 1.3)
- Modify: `test_integration.sh` (run the same crack with `-G` and without, assert identical found password)

- [ ] **Step 1: Replace the bitmask assert in `test_all.c:108-132`** with a true diff: for each of the 8 PDF variants and a set of candidate passwords (including the correct one and near-misses), assert `pdf_verify_user_batch4` lane results equal `pdf_verify_user_password` scalar results, and the same for owner. Remove the `revision >= 5` skip so R5/R6 SHA-256/384/512 + AES SIMD paths are validated.

```c
for (int v = 0; v < n_variants; v++) {
    load_variant(v);
    const char *cands[4] = { variant[v].correct_pw, "wrong0", "wrong1", "wrong2" };
    int scal[4], batch[4];
    for (int i = 0; i < 4; i++) scal[i] = pdf_verify_user_password(&params, cands[i]);
    pdf_verify_user_batch4(&params, cands, batch);
    for (int i = 0; i < 4; i++) ASSERT_EQ(scal[i], batch[i]);
}
```

- [ ] **Step 2: Add a >32-char-password assertion** (regression for Task 1.3): construct a candidate of length 40 and confirm the verify path and the reported string handle it (use a crafted PDF whose password is long, or assert at the buffer/`g_password` copy layer with a unit shim).

- [ ] **Step 3: Add a GPU-vs-CPU integration diff** in `test_integration.sh`: run `./pdfcrack -f test_r5_aes256.pdf -d wl.txt` and `./pdfcrack -f test_r5_aes256.pdf -d wl.txt -G`, assert both print the same `password found:` line.

- [ ] **Step 4: Run**

Run: `make test && bash test_integration.sh`
Expected: pass; a GPU/CPU divergence would now fail.

- [ ] **Step 5: Commit**

```bash
git add test_all.c test_integration.sh
git commit -m "test: real NEON/scalar + GPU/CPU cross-validation across R2-R6"
```

---

### Task 2.6: ASan malformed-PDF parser harness (regression for Task 1.4)

**Files:**
- Create: `test_parse_fuzz.c`
- Modify: `Makefile`

- [ ] **Step 1: Write a harness** that feeds truncated/corrupt buffers to `pdf_parse_encrypt`

```c
#include "pdf_encrypt.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* libFuzzer entry: parse arbitrary bytes; ASan/UBSan catch over-reads. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* pdf_parse_encrypt expects a NUL-free byte buffer + length; pass a copy. */
    uint8_t *buf = (uint8_t *)malloc(size ? size : 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    PDFEncryptParams p;
    (void)pdf_parse_encrypt_buffer(buf, size, &p);  /* see note */
    free(buf);
    return 0;
}
```
Note: if `pdf_parse_encrypt` only takes a file path, add a thin buffer-based entry `pdf_parse_encrypt_buffer(const uint8_t*, size_t, PDFEncryptParams*)` that the file path version already wraps (most of the parser already works on `data`/`len`). Confirm with `grep -n 'pdf_parse_encrypt' pdf_encrypt.c pdf_encrypt.h`.

- [ ] **Step 2: Add a Makefile target**

```makefile
fuzz-parse: test_parse_fuzz.c pdf_encrypt.c saslprep.c
	clang -O1 -g -fsanitize=fuzzer,address,undefined \
	  -o fuzz_parse test_parse_fuzz.c pdf_encrypt.c saslprep.c $(FRAMEWORKS)
```
Add `fuzz-parse` to `.PHONY` and `fuzz_parse` to `clean`.

- [ ] **Step 3: Seed and run**

```bash
make fuzz-parse
mkdir -p corpus && cp test_*.pdf corpus/
./fuzz_parse corpus -max_total_time=60
```
Expected: no ASan/UBSan crash (with Task 1.4/1.5 applied). Wire the 30–60s run into `ci.yml`.

- [ ] **Step 4: Commit**

```bash
git add test_parse_fuzz.c Makefile
git commit -m "test: add ASan/UBSan fuzz harness for the PDF encrypt parser"
```

---

# Phase 3 — Checkpoint robustness

### Task 3.1: Version + magic + graceful corruption handling

`checkpoint.c:151-233` — `ckpt_load` always returns `valid=1`; corruption either `exit(1)`s (via `safe_atoi`) or resumes from garbage. The `.incr` side-file already versions correctly; mirror it.

**Files:**
- Modify: `checkpoint.c` (`ckpt_save`, `ckpt_load`), `checkpoint.h` (add `#define CKPT_MAGIC`/`CKPT_VERSION`)

- [ ] **Step 1:** In `checkpoint.h` add:
```c
#define CKPT_MAGIC   "PDFCRACK-CKPT"
#define CKPT_VERSION 1
```

- [ ] **Step 2:** In `ckpt_save`, write the magic+version as the FIRST line before any field.

- [ ] **Step 3:** In `ckpt_load`, read the first line; if it isn't `CKPT_MAGIC` + a supported version, return `(Checkpoint){ .valid = 0 }` (do NOT `exit`). Replace every `safe_atoi(...)` call inside `ckpt_load` with a local `ckpt_atoi(const char *s, long lo, long hi, int *ok)` that sets `*ok=0` on bad input instead of exiting; if any required field fails, return `{.valid=0}`. Require at least `attack_mode` and `current_*` to be present and in range for `valid=1`.

- [ ] **Step 4:** Bound-check `current_idx`/`completed_prior` (currently raw `atol` at `:202`/`:204`): reject negatives and values exceeding the keyspace for the restored length.

- [ ] **Step 5:** Bounds-check `mode_names[g_attack_mode]` at `checkpoint.c:93`:
```c
if (g_attack_mode < 0 || g_attack_mode >= (int)(sizeof(mode_names)/sizeof(mode_names[0]))) return;
```

- [ ] **Step 6: Test** — write a corrupt/empty/truncated `.ckpt` and confirm `ckpt_load` returns invalid and the program starts fresh (no `exit(1)`). Add to `test_integration.sh`, replacing the misleading test 28:
```bash
echo "garbage" > test_r2_40bit.pdf.ckpt
./pdfcrack -f test_r2_40bit.pdf -b -l 2 -r -B 2>&1 | grep -qi "checkpoint" # starts fresh, no abort
```

- [ ] **Step 7: Commit**

```bash
git add checkpoint.c checkpoint.h test_integration.sh
git commit -m "fix(checkpoint): add magic/version, reject corrupt files gracefully (no exit)"
```

---

### Task 3.2: Single source of truth for the attack-mode table (save/load symmetry)

`ckpt_save` serializes 16 modes; `ckpt_load` parses only 13 — `combinator`, `mask_rule`, `incremental` silently resume wrong.

**Files:**
- Modify: `checkpoint.c`, `checkpoint.h`

- [ ] **Step 1:** Define one table in a shared spot (e.g. `checkpoint.h`):
```c
/* index == ATTACK_* value; keep in lockstep with the ATTACK_* defines in pdfcrack.c */
static const char *const CKPT_MODE_NAMES[] = {
    "brute","dict","mask","rule","hybrid","auto","prince","fingerprint",
    "combinator","mask_rule","incremental","dates","mutate","leet","smart","pattern"
};
```

- [ ] **Step 2:** Drive both `ckpt_save` (write `CKPT_MODE_NAMES[g_attack_mode]`) and `ckpt_load` (linear search the table to map name → mode id) from this array. Remove the hand-written per-mode `strncmp` ladder.

- [ ] **Step 3:** Add an `_Static_assert` (or runtime check) that the array length equals the highest `ATTACK_*` + 1.

- [ ] **Step 4: Test** — save+resume each of the three previously-broken modes and assert the mode is restored. Add to `test_integration.sh`.

- [ ] **Step 5: Commit**

```bash
git add checkpoint.c checkpoint.h test_integration.sh
git commit -m "fix(checkpoint): drive save/load from one mode table; fix combinator/mask_rule/incremental resume"
```

---

### Task 3.3: Resume without skipping (completed low-water-mark)

Checkpoint saves `g_next_idx` (next claimed), but chunked claims + GPU double-buffering leave `[completed, g_next_idx)` untested on resume.

**Files:**
- Modify: `pdfcrack.c` (worker chunk-claim accounting), `checkpoint.c`

- [ ] **Step 1:** Add a global `atomic_long g_completed_idx` (the minimum start index across all not-yet-finished claimed chunks is too costly; instead track the highest *fully verified* contiguous index). Simplest correct approach: each worker, on finishing a claimed chunk, records its chunk's end; a small monotonic "contiguous completed" tracker advances `g_completed_idx` only across chunks with no gap. For the common case (workers finish roughly in order), this is cheap; worst case it lags slightly and re-tests a little on resume (safe direction).

- [ ] **Step 2:** Checkpoint `g_completed_idx` (not `g_next_idx`) as the resume index. On resume, `atomic_store(&g_next_idx, g_completed_idx)`.

- [ ] **Step 3:** Document the trade-off in a comment: resume may re-test up to `nthreads × chunk` candidates but will never skip.

- [ ] **Step 4: Test** — start a brute run, SIGINT mid-run, resume, and assert the known password (placed just past the interrupt point) is still found. Add to `test_integration.sh`.

- [ ] **Step 5: Commit**

```bash
git add pdfcrack.c checkpoint.c test_integration.sh
git commit -m "fix(checkpoint): resume from contiguous-completed index to avoid skipping candidates"
```

---

### Task 3.4: Bind checkpoint to PDF identity

`ckpt_save` writes `pdf_path` but `ckpt_load` ignores it; resuming `-r` against a different PDF with the same base name replays stale indices.

**Files:**
- Modify: `checkpoint.c`

- [ ] **Step 1:** On save, write a short fingerprint of the encryption params (e.g. hex of `/O` + `/U` + `/P` + `file_id`, or a SHA-256 of the raw `/Encrypt` dict bytes).
- [ ] **Step 2:** On load with `-r`, recompute and compare; if mismatch, return `{.valid=0}` with a warning ("checkpoint is for a different document; starting fresh").
- [ ] **Step 3: Test** — resume with a different PDF; assert it starts fresh. Add to `test_integration.sh`.
- [ ] **Step 4: Commit**

```bash
git add checkpoint.c test_integration.sh
git commit -m "fix(checkpoint): bind checkpoint to PDF encryption fingerprint"
```

---

### Task 3.5: Atomic `.ckpt`/`.incr` consistency

`.incr` is written after the `.ckpt` rename; an interrupt between them leaves them inconsistent. No directory fsync.

**Files:**
- Modify: `checkpoint.c`

- [ ] **Step 1:** Write `.incr` to a tmp file and fsync it BEFORE renaming `.ckpt`, so `.ckpt` only becomes visible once `.incr` is durable; or fold the incremental heap into the same atomic write. Add an `fsync` of the containing directory after the final `rename`.
- [ ] **Step 2: Commit**

```bash
git add checkpoint.c
git commit -m "fix(checkpoint): order .incr durability before .ckpt rename; fsync dir"
```

---

# Phase 4 — Distributed security & correctness

### Task 4.1: Server-side `FOUND` re-verification (HIGH — result integrity)

`server.c:1124-1145` trusts any client's `FOUND` without checking it against the PDF it holds.

**Files:**
- Modify: `server.c`

- [ ] **Step 1:** Before setting `g_password`/`g_found`, re-verify with the local crypto:
```c
int ok = (g_password_mode == PW_MODE_OWNER)
       ? pdf_verify_owner_password(&g_enc_params, claimed_pw)
       : pdf_verify_user_password(&g_enc_params, claimed_pw)
         || (g_password_mode == PW_MODE_BOTH &&
             pdf_verify_owner_password(&g_enc_params, claimed_pw));
if (!ok) { /* log and ignore the bogus claim, keep searching */ }
```
- [ ] **Step 2: Test** — extend the loopback test (Task 2.4) with a stub that sends a wrong `FOUND`; assert the server ignores it and keeps going.
- [ ] **Step 3: Commit**

```bash
git add server.c
git commit -m "fix(server): re-verify FOUND against the PDF before accepting"
```

---

### Task 4.2: Client heartbeat thread (HIGH — prevents duplicate work)

Client never sends `HEARTBEAT`, so the reaper expires *busy* clients after 60s → double-counted/redone work.

**Files:**
- Modify: `client.c` (spawn a heartbeat thread that sends `HEARTBEAT <lease> <tested>` every ~15s while a chunk runs), optionally `server.c` (refresh `last_seen` on heartbeat — already does on any line).

- [ ] **Step 1:** Add a detached heartbeat thread started when a lease begins, stopped on COMPLETE/FOUND. Use the current lease id + an atomic tested counter.
- [ ] **Step 2:** Confirm `reaper_thread` (`server.c:1296-1303`) now only expires genuinely-silent clients.
- [ ] **Step 3: Test** — loopback test with an artificially slow chunk (e.g. R6 or a large lease) running > 60s; assert the lease is not requeued and `g_total_tested` is not inflated beyond keyspace.
- [ ] **Step 4: Commit**

```bash
git add client.c server.c
git commit -m "feat(client): send periodic HEARTBEAT so busy leases aren't reaped"
```

---

### Task 4.3: Lock/atomic the shared `ClientInfo` fields (HIGH — data races)

After the handshake, `client_handler` writes `last_seen`/`speed`/`chunk_size`/`tested`/`current_lease_id` with no lock while other threads read them under `g_clients_lock`.

**Files:**
- Modify: `server.c`

- [ ] **Step 1:** Either take `g_clients_lock` around each `ci->…` write, or convert the numeric fields to `_Atomic`. Prefer atomics for the hot counters (`tested`, `last_seen`) and the lock for the rest.
- [ ] **Step 2:** Fix the same class on `g_password`/`g_found` reads in `http_serve_api_status`/`web_serve_api_status` — settle on one synchronization scheme and document it.
- [ ] **Step 3:** Change `g_shutdown` from `volatile int` to `volatile sig_atomic_t` (`server.c:140`).
- [ ] **Step 4: Test** — run loopback under TSan (`-fsanitize=thread`) for a short crack; assert no warnings.
- [ ] **Step 5: Commit**

```bash
git add server.c
git commit -m "fix(server): synchronize ClientInfo/g_password access; sig_atomic_t shutdown"
```

---

### Task 4.4: Reclaim client slots (HIGH — DoS)

`slot_free` is never set back to 1, so 64 distinct UUIDs permanently wedge the coordinator.

**Files:**
- Modify: `server.c`

- [ ] **Step 1:** When a client has been disconnected longer than a grace window (e.g. 10× heartbeat timeout) and holds no active lease, mark its slot `slot_free=1` so `alloc_client_slot` can reuse it. Reconnection within the window still matches the persistent UUID.
- [ ] **Step 2: Test** — connect/disconnect > MAX_CLIENTS times with random UUIDs in the loopback harness; assert new clients still get slots.
- [ ] **Step 3: Commit**

```bash
git add server.c
git commit -m "fix(server): reclaim stale client slots to prevent exhaustion DoS"
```

---

### Task 4.5: Socket read timeouts + EINTR retries

No `SO_RCVTIMEO` on cracking sockets; a silent peer parks a thread forever. `read_exact`/`write_exact`/`sock_readline` treat EINTR as fatal.

**Files:**
- Modify: `server.c` (set `SO_RCVTIMEO` on accepted sockets, like the web port does at `:1952`), `protocol.h` (retry on `EINTR`)

- [ ] **Step 1:** Set `SO_RCVTIMEO` (e.g. 120s) on each accepted cracking socket; drop handshake-stalled connections.
- [ ] **Step 2:** In `protocol.h:103-166`, loop on `EINTR` instead of returning -1.
- [ ] **Step 3: Commit**

```bash
git add server.c protocol.h
git commit -m "fix(net): add socket read timeouts; retry I/O on EINTR"
```

---

### Task 4.6: Clamp network-controlled lengths and sizes

`g_max_len` (`client.c:1247`), `blen` (`:1426`), and `PDF <nbytes>` (`:1299`) are unbounded; `index_to_password` overflows a 33-byte stack buffer; `malloc(pdf_size)` can OOM. `http_serve_file` uses unchecked `write()`.

**Files:**
- Modify: `client.c`, `server.c`, `protocol.h`

- [ ] **Step 1:** On receipt, reject `g_max_len`/`blen > MAX_PASS_LEN`; clamp server-side `-l` (`server.c:2081/2119`).
- [ ] **Step 2:** Cap `pdf_size` to a sane max (e.g. 512 MB) before `malloc`; fail closed on overflow.
- [ ] **Step 3:** Replace `http_serve_file`'s raw `write()` loop (`server.c:587-589`) with `write_exact` (`protocol.h:115`) so the client binary can't be truncated.
- [ ] **Step 4: Commit**

```bash
git add client.c server.c protocol.h
git commit -m "fix(net): clamp network-controlled length/size; write_exact for binary serve"
```

---

### Task 4.7: Define and fix `PARTIAL` semantics

`hwm` mixes absolute and relative indices (`server.c:1083-1121`, `client.c:1405`), double-adding the chunk start and mis-crediting progress.

**Files:**
- Modify: `client.c`, `server.c`, `protocol.h` (doc the field)

- [ ] **Step 1:** Define `PARTIAL <tested_in_this_lease>` as passwords tested *within this lease* (relative). Make every worker path maintain it (GPU and non-GPU).
- [ ] **Step 2:** Server computes `new_start = le->brute_start + tested` and credits `tested` exactly once.
- [ ] **Step 3: Test** — interrupt a client mid-lease (SIGINT), assert the requeued range starts at the right offset and `g_total_tested` stays ≤ keyspace.
- [ ] **Step 4: Commit**

```bash
git add client.c server.c protocol.h
git commit -m "fix(net): make PARTIAL relative-tested; fix double-credit and range math"
```

---

### Task 4.8: Don't send `DONE` while work is outstanding

`server.c:997-1025` sends terminal `DONE` after ~6s of no-work even when leases are active; the client then exits permanently.

**Files:**
- Modify: `server.c`, `client.c`, `protocol.h`

- [ ] **Step 1:** Add a `WAIT` response (or reuse a retry signal): when no assignable work but active leases exist, tell the client to back off and re-`GETWORK`. Only send `DONE` when there is no work AND no active leases.
- [ ] **Step 2:** Client treats `WAIT` as "sleep briefly, retry" rather than exit.
- [ ] **Step 3: Test** — loopback with two clients where one chunk is slow; assert the idle client doesn't exit before the slow lease completes/requeues.
- [ ] **Step 4: Commit**

```bash
git add server.c client.c protocol.h
git commit -m "fix(net): add WAIT response; only DONE when no active leases remain"
```

---

### Task 4.9: Distributed trust model — warning, optional auth, binary integrity

`curl|bash` pulls a binary over plaintext HTTP; protocol is unauthenticated; PDF is sent to any peer; `--auth-token` doesn't cover the web port and breaks `join.sh`; token compare isn't constant-time.

**Files:**
- Modify: `README.md`, `server.c`, `join.sh`

- [ ] **Step 1 (docs, do first):** Add a prominent README warning that the distributed mode is designed for a trusted LAN; the PDF and a binary cross the wire unauthenticated. State the recommended posture (VPN/trusted subnet, or use the SSH `deploy.sh` push instead of the HTTP pull).
- [ ] **Step 2 (integrity):** Have `server.c` emit the client binary's SHA-256 into the generated `join.sh`, and have `join.sh` verify the checksum before `chmod +x; exec`.
- [ ] **Step 3 (auth):** Add an optional shared-secret to the protocol handshake (`HELLO … <token>`); reject mismatches. Apply `http_check_auth` to the `--web-port` dashboard too; propagate the token into generated URLs; use a constant-time compare; bind to a configurable interface (default loopback or a specified address) rather than `INADDR_ANY` when a token isn't set.
- [ ] **Step 4: Test** — loopback with a token: correct token connects, wrong token is rejected; tampered binary fails the checksum in `join.sh`.
- [ ] **Step 5: Commit**

```bash
git add README.md server.c join.sh
git commit -m "security(dist): warn on trust model; checksum bootstrap binary; optional shared-secret auth"
```

---

# Phase 5 — Maintainability refactor

This is the big structural investment. Do it with CI (Phase 2) green so behavior is locked in. Each task keeps the test suite passing at every commit.

### Task 5.1: Extract the rule engine into `rules.c`/`rules.h`

`fuzz_rules.c:44,135` hand-copies `parse_rule_op`/`apply_one_op` from `pdfcrack.c` — the fuzzer can pass while the real parser regresses.

**Files:**
- Create: `rules.c`, `rules.h`
- Modify: `pdfcrack.c` (remove the copies, `#include "rules.h"`, link `rules.o`), `fuzz_rules.c` (include + link the real code), `Makefile`

- [ ] **Step 1:** Move `RuleType`, `Rule`, `RuleOp`, `parse_rule_op`, `apply_one_op`, `apply_rule`, `add_rule_1`, `load_rules_file`, `init_rules`, `rule_dedup_check` into `rules.c`/`rules.h`. Keep signatures identical.
- [ ] **Step 2:** `pdfcrack.c` and `fuzz_rules.c` both `#include "rules.h"` and link `rules.o`. Delete the duplicated bodies from both.
- [ ] **Step 3:** Update `Makefile` (`rules.o` target; add to `pdfcrack` and `fuzz-rules` deps).
- [ ] **Step 4: Verify**

Run: `make && make fuzz-rules && ./fuzz_rules -max_total_time=20 && make test && bash test_integration.sh`
Expected: all pass; fuzzer now exercises production code.

- [ ] **Step 5: Commit**

```bash
git add rules.c rules.h pdfcrack.c fuzz_rules.c Makefile
git commit -m "refactor: extract rule engine to rules.c so the fuzzer links real code"
```

---

### Task 5.2: Shared GPU struct header (`pdf_gpu_types.h`)

`PDFEncryptGPU`/`PDFR5GPU`/`PDFR6GPU` and `R6_SCRATCH_SIZE` are hand-duplicated between `metal_keygen.m` and `pdf_md5.metal` with "must match" comments — a silent ABI break risk.

**Files:**
- Create: `pdf_gpu_types.h`
- Modify: `metal_keygen.m`, `pdf_md5.metal`

- [ ] **Step 1:** Put the three structs and the `R6_SCRATCH_SIZE`/packed-length `#define`s in `pdf_gpu_types.h` using plain C / `#define` (Metal accepts these). Guard any host-only bits with `#ifndef __METAL_VERSION__`.
- [ ] **Step 2:** `#include "pdf_gpu_types.h"` in both files; delete the local copies.
- [ ] **Step 3: Verify** GPU results unchanged.

Run: `make && make test && bash test_integration.sh`  (the GPU/CPU diff from Task 2.5 guards correctness)
Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add pdf_gpu_types.h metal_keygen.m pdf_md5.metal
git commit -m "refactor(gpu): share GPU structs/constants between host and shader"
```

---

### Task 5.3: Consolidate the ~38 worker functions into engine drivers + generators

The dominant maintainability problem: each attack mode is reimplemented per engine (scalar/NEON/GPU-MD5/GPU-SHA256/GPU-R6); ~80-90% of each is identical fetch/verify/double-buffer scaffold.

**Files:**
- Create: `workers.h` (interface)
- Modify: `pdfcrack.c`

**Target interface (`workers.h`):**
```c
/* Produce candidate `idx` of the keyspace into `out` (NUL-terminated, <= MAX cap). */
typedef void (*cand_gen)(long idx, char *out, void *ctx);

/* One driver per engine. Each pulls chunks from g_next_idx, calls gen, verifies,
 * sets g_found/g_password on a hit, and accounts g_tested. */
typedef struct {
    cand_gen gen;
    void    *ctx;
    long     total;       /* keyspace; 0 = unbounded/until g_found */
} WorkSpec;

void *run_scalar     (void *spec);   /* WorkSpec* */
void *run_neon       (void *spec);
void *run_gpu_md5    (void *spec);   /* R2-R4: GPU keygen + CPU RC4 verify */
void *run_gpu_sha256 (void *spec);   /* R5 */
void *run_gpu_r6     (void *spec);   /* R6 */
```

- [ ] **Step 1:** Implement the 5 drivers ONCE, lifting the common scaffold from the existing workers. The GPU drivers contain the double-buffer pipeline (currently copy-pasted ~10×). Example skeleton for the SHA-256 driver (consolidating `gpu_sha256_brute/dict/rule/hybrid/combinator/dates/mutate/leet/mask_rule_worker`):
```c
void *run_gpu_sha256(void *arg) {
    WorkSpec *s = arg;
    char *pw_storage[2]; const char *pw_ptrs[2][GPU_BATCH_SIZE];
    /* ...allocate both buffers, init pending handle/count... */
    while (!atomic_load(&g_found)) {
        long base = atomic_fetch_add(&g_next_idx, GPU_BATCH_SIZE);
        if (s->total && base >= s->total) break;
        int n = clamp_batch(base, s->total);
        for (int i = 0; i < n; i++) s->gen(base + i, slot(pw_storage[cur], i), s->ctx);
        /* wait-prev -> check match -> submit-next -> swap (single copy of this logic) */
    }
    /* drain + free (single copy) */
    return NULL;
}
```
- [ ] **Step 2:** Write the ~11 small generators as `cand_gen` callbacks with a per-mode `ctx` struct: `gen_brute`, `gen_dict`, `gen_rule`, `gen_hybrid`, `gen_combinator`, `gen_dates`, `gen_mutate`, `gen_leet`, `gen_mask_rule`, `gen_toggle`, `gen_prince`. Each is the 1-6 line index→candidate body extracted from the old worker.
- [ ] **Step 3:** Replace the dispatch ternary chains (`g_r6_ctx ? gpu_r6_X : g_sha256_ctx ? gpu_sha256_X : gpu_X`, repeated at `pdfcrack.c:7154/7224/7910` and elsewhere) with one helper that picks the driver from the active engine and spawns it with the right `WorkSpec`.
- [ ] **Step 4:** Delete the 38 old worker functions as each mode is migrated. **Migrate one mode at a time, committing after each, with `make test && bash test_integration.sh` green between migrations.** Suggested order: brute → dict → rule → hybrid → dates → mutate → leet → combinator → mask_rule → toggle → prince.
- [ ] **Step 5:** While migrating `toggle`, fix its quadratic scan and per-candidate atomic for free by using the standard chunked driver + a precomputed cumulative-offset array in the toggle `ctx` (addresses Task 6.5). While migrating, ensure `g_found_type` is set ONLY inside the `if (!atomic_exchange(&g_found,1))` winner-guard (fixes the data race).
- [ ] **Step 6:** This automatically yields a GPU-R6 path for `toggle` (Task 7.4) since the R6 driver is shared.
- [ ] **Step 7: Final verify**

Run: `make && make test && bash test_integration.sh`
Expected: all modes still pass; file is ~2500-3000 lines shorter.

- [ ] **Step 8: Commit** (one per migrated mode; final cleanup commit)

```bash
git add pdfcrack.c workers.h
git commit -m "refactor: consolidate 38 per-mode/per-engine workers into 5 drivers + generators"
```

---

### Task 5.4: Decompose `main()` and the triplicated length-loop

`main()` is ~1742 lines; the brute/freq/auto length-loop is copy-pasted at `pdfcrack.c:7140/7210/7894`.

**Files:**
- Modify: `pdfcrack.c`

- [ ] **Step 1:** Extract `static int dispatch_attack(WorkSpec base, ...)` that does the `atomic_store(&g_next_idx/g_total)`, spawns the engine driver + N CPU drivers, joins, and accumulates `g_completed_prior` — replacing the ~20-line ritual repeated per mode.
- [ ] **Step 2:** Extract `static void run_length_loop(int min_len, int max_len, ...)` for the brute/freq/auto sweep; call it from all three sites.
- [ ] **Step 3:** Move per-mode setup blocks into small `setup_<mode>()` helpers so `main` reads as parse-args → resolve-mode → dispatch.
- [ ] **Step 4: Verify**

Run: `make && make test && bash test_integration.sh`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add pdfcrack.c
git commit -m "refactor: extract dispatch_attack + run_length_loop; shrink main()"
```

---

### Task 5.5: De-duplicate the two HTTP servers in `server.c`

Main-port and `--web-port` each have their own dashboard HTML, JSON builder, and request parser, already diverging (auth coverage, JSON `id` shape).

**Files:**
- Modify: `server.c`

- [ ] **Step 1:** Extract one `serve_http(int fd, const char *path, int require_auth)` plus one `render_dashboard()` and one `render_status_json()`; both ports call them. Pick one JSON shape (prefer the UUID string `id`) and document it.
- [ ] **Step 2: Verify** both ports return identical dashboards/JSON.

Run: `make server` then curl both ports during a loopback run.
Expected: identical output; auth now applies on both.

- [ ] **Step 3: Commit**

```bash
git add server.c
git commit -m "refactor(server): unify the two HTTP servers and the dashboard/JSON renderers"
```

---

### Task 5.6: Group globals; shrink the checkpoint cross-TU coupling

~102 `g_` globals; `checkpoint.c` externs ~25 of them, so adding a resumable field means editing four places.

**Files:**
- Modify: `pdfcrack.c`, `checkpoint.c`, `checkpoint.h`

- [ ] **Step 1:** Introduce a `struct CheckpointableState` holding exactly the fields `ckpt_save`/`ckpt_load` need (attack mode, indices, charset, mask, hybrid suffix, auto phase, flags). Populate it from the globals at save time and apply it at load time, so `checkpoint.c` sees ONE extern struct instead of 25 globals.
- [ ] **Step 2 (optional, incremental):** Group the remaining clusters (`AttackConfig`, `ProgressState`) behind structs over subsequent commits — not required for correctness.
- [ ] **Step 3: Verify**

Run: `make && make test && bash test_integration.sh`
Expected: pass; checkpoint round-trips unchanged.

- [ ] **Step 4: Commit**

```bash
git add pdfcrack.c checkpoint.c checkpoint.h
git commit -m "refactor: funnel checkpoint state through one struct; cut cross-TU global coupling"
```

---

### Task 5.7: Crypto-layer dedup + split `pdf_parse_encrypt`

Duplicated blocks in `pdf_encrypt.c`: user-password recovery/trim (`:949-967` ≡ `:1155-1171`), key-byte clamp (4×), `/P` LE serialization (2×); `pdf_parse_encrypt` is ~225 lines.

**Files:**
- Modify: `pdf_encrypt.c`, `pdf_encrypt.h`

- [ ] **Step 1:** Extract `static int key_bytes_for(const PDFEncryptParams*)` (replaces the 4 clamp copies), `static void p_to_le32(int32_t perm, uint8_t out[4])`, and `static void recover_user_password(const uint8_t *o, const uint8_t *key, int key_len, int rev, uint8_t out[32])`. **Fix the embedded-NUL truncation bug here** by passing the recovered 32 padded bytes length-explicitly into Algorithm 2/5 instead of round-tripping through a C string.
- [ ] **Step 2:** Split `pdf_parse_encrypt` into `find_trailer_dict`, `resolve_encrypt_dict`, `extract_encrypt_values`.
- [ ] **Step 3:** Name the magic numbers (`R3_KEY_ITERATIONS=50`, RC4 pass counts, salt offsets). Drop the redundant global pragma at `pdf_encrypt.c:13`.
- [ ] **Step 4: Verify** against the unit suite (these blocks are exercised by `test_all`).

Run: `make test_all && ./test_all`
Expected: pass, including owner-password tests.

- [ ] **Step 5: Commit**

```bash
git add pdf_encrypt.c pdf_encrypt.h
git commit -m "refactor(crypto): dedup helpers, split parser, fix NUL-truncation in owner recovery"
```

---

### Task 5.8: `metal_keygen.m` dedup + fix the ARC context leak

Library-load boilerplate (3×), submit/encode sequence (~8×), the R6 owner KDF duplicated verbatim in the shader, and `metal_*_free` leaking all Metal objects under ARC.

**Files:**
- Modify: `metal_keygen.m`, `pdf_md5.metal`

- [ ] **Step 1:** Extract `static id<MTLLibrary> load_pdf_library(id<MTLDevice>, const char *path, NSError**)` (one copy).
- [ ] **Step 2:** Extract an encode helper for the `commandBuffer→encoder→setPipeline→setBuffers→dispatchThreads` block.
- [ ] **Step 3:** In the shader, extract a `device` function `r6_kdf(...)` and call it for both the primary and owner paths (`pdf_md5.metal:983-1039` ≡ `:1064-1111`).
- [ ] **Step 4: Fix the ARC leak** in `metal_*_free`: null out each `id` field (`ctx->device = nil;` etc.) before `free(ctx)` so ARC releases them; fix the init error paths too. Correct the misleading "ARC handles Metal objects" comment.
- [ ] **Step 5:** Replace the literal `128` packed-stride with an `R6_PW_PACKED_LEN` define (in `pdf_gpu_types.h` from Task 5.2). Fix the contradictory AES comment (`pdf_md5.metal:704`).
- [ ] **Step 6: Verify** GPU correctness (Task 2.5 diff) + run under `leaks` to confirm teardown frees.

Run: `make && make test && bash test_integration.sh`
Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add metal_keygen.m pdf_md5.metal
git commit -m "refactor(gpu): dedup loader/encoder/KDF; fix ARC context leak"
```

---

# Phase 6 — Performance

Easier and safer after Phase 5. The GPU/CPU cross-validation (Task 2.5) guards correctness for every change here.

### Task 6.1: R6 — generate K1 on the fly (biggest GPU win)

`pdf_md5.metal:963-1009` materializes ~15 KB of replicated K1 in device memory per round; ~200 rounds × 8192 threads.

**Files:**
- Modify: `pdf_md5.metal`

- [ ] **Step 1:** Replace the replicate-into-device-scratch + read-back with on-the-fly AES-CBC block generation from a ≤239-byte thread-local `seq[]` (the sequence is periodic, so block `j` maps to `seq[(j*16) % seq_len ...]`). Removes essentially all K1 device traffic.
- [ ] **Step 2: Verify** R6 results identical to CPU (Task 2.5) and benchmark before/after.

Run: `./pdfcrack -f test_r5_aes256.pdf -B` and an R6 PDF `-B`; record `/s`.
Expected: identical results, higher R6 throughput.

- [ ] **Step 3: Commit**

```bash
git add pdf_md5.metal
git commit -m "perf(gpu): generate R6 K1 on the fly instead of materializing in device memory"
```

---

### Task 6.2: R6 scratch → Private storage

`metal_keygen.m:769` allocates GPU-only scratch as `MTLResourceStorageModeShared` (256 MB across the double buffer).

**Files:**
- Modify: `metal_keygen.m`

- [ ] **Step 1:** Change `scratch_buf` to `MTLResourceStorageModePrivate` (leave `pw/len/results/keys` Shared — the CPU reads/writes those).
- [ ] **Step 2:** If Task 6.1 eliminates scratch entirely, this task may shrink to "remove the buffer." Reconcile.
- [ ] **Step 3: Verify + commit**

```bash
git add metal_keygen.m
git commit -m "perf(gpu): R6 scratch uses Private storage mode"
```

---

### Task 6.3: Drop the per-batch password memset

`metal_keygen.m:22` zeroes up to 32 MB per batch that the kernels never read past `pw_len`.

**Files:**
- Modify: `metal_keygen.m`, possibly `pdf_md5.metal`

- [ ] **Step 1:** Remove the `memset`; only write `len_buf[i]` (set len 0 for NULL/empty entries) and the actual password bytes. Confirm kernels read exactly `pw_len` bytes.
- [ ] **Step 2: Verify** (Task 2.5 diff) + benchmark; **commit**.

```bash
git add metal_keygen.m
git commit -m "perf(gpu): drop dead per-batch password zero-fill"
```

---

### Task 6.4: NEON-verify the owner batch4 path

`pdf_encrypt.c:1143-1175` derives owner keys 4-wide then verifies scalar per lane (~200 scalar MD5 each).

**Files:**
- Modify: `pdf_encrypt.c`

- [ ] **Step 1:** Collect the 4 recovered `user_str` and run them through `pdf_verify_user_batch4` instead of 4 scalar `pdf_verify_user_password` calls. (Uses the `recover_user_password` helper from Task 5.7.)
- [ ] **Step 2: Verify** owner tests pass (Task 2.5) + **commit**.

```bash
git add pdf_encrypt.c
git commit -m "perf(crypto): SIMD-verify owner batch4 instead of scalar per lane"
```

---

### Task 6.5: Fix the quadratic toggle worker

`pdfcrack.c:3820` is O(candidates × nwords). **Folded into Task 5.3 Step 5** (standard chunked driver + cumulative-offset array). If Phase 5 isn't done first, do it standalone here.

**Files:**
- Modify: `pdfcrack.c`

- [ ] **Step 1:** Precompute `long cumul[nwords+1]` of toggle-variant counts once; binary-search it to decode a flat index; grab candidates in chunks (not one atomic each).
- [ ] **Step 2: Verify + commit**

```bash
git add pdfcrack.c
git commit -m "perf(toggle): cumulative-offset decode + chunked claims (was O(n*words))"
```

---

### Task 6.6: Encode buffer index + count in the async GPU handle (correctness + pipelining)

`metal_keygen.m:299/646/954` derive the result buffer from mutable `current_buf ^ 1`; correct only because callers serialize wait-before-submit. Blocks true 2-deep pipelining and is a latent race.

**Files:**
- Modify: `metal_keygen.m`, `metal_keygen.h`

- [ ] **Step 1:** Make `submit_async` return a small handle `{ id<MTLCommandBuffer> cb; int buf_index; int count; }` (heap or caller-provided); `wait_results` reads results from the captured `buf_index`/`count`, not from shared state.
- [ ] **Step 2:** Validate `count <= max_batch` in submit; return the clamped count in the handle.
- [ ] **Step 3:** Now callers can submit two batches before waiting; update one GPU worker driver (Task 5.3) to keep 2 in flight and benchmark the gain.
- [ ] **Step 4: Verify + commit**

```bash
git add metal_keygen.m metal_keygen.h
git commit -m "perf(gpu): carry buffer index+count in async handle; enable 2-deep pipelining"
```

---

### Task 6.7: Move RC4 U-verification onto the GPU (R2-R4)

Currently GPU only derives keys; CPU runs the RC4 U-check, requiring a 4 MB/batch key copy-out and a CPU loop.

**Files:**
- Modify: `pdf_md5.metal`, `metal_keygen.m`, `metal_keygen.h`, callers in `pdfcrack.c`/`client.c`

- [ ] **Step 1:** Add a Metal kernel that runs Algorithm 4/5 (RC4 of the padding/`/U`) per thread and returns a compact match index (mirroring `pdf_sha256_verify`). Each thread handles one independent password, so per-thread RC4 seriality is fine for occupancy.
- [ ] **Step 2:** Switch the R2-R4 path to return a match index; drop the key copy-out and the CPU RC4 loop.
- [ ] **Step 3: Verify** R2-R4 results identical (Task 2.5) + benchmark; **commit**.

```bash
git add pdf_md5.metal metal_keygen.m metal_keygen.h pdfcrack.c client.c
git commit -m "perf(gpu): run RC4 U-verification on-GPU for R2-R4; return match index"
```

---

### Task 6.8: Hot-loop micro-optimizations

**Files:**
- Modify: `pdfcrack.c`, `protocol.h`, `server.c`

- [ ] **Step 1:** Cache word lengths at load (`int *g_word_lens` in `load_wordlist`); use in `combinator_worker`/`dict_worker_neon`/toggle instead of per-iteration `strlen`.
- [ ] **Step 2:** Give `smart_try` the chunked + local-accumulator pattern (drop per-candidate `g_tested` atomic); count hits too (fix the off-by-one).
- [ ] **Step 3:** Buffer `sock_readline` (`protocol.h:127`) like the existing `SockBuf` on both server and client (it reads 1 byte/syscall today); batch the per-word dict send (`server.c:1034`) into one buffer.
- [ ] **Step 4: Verify + commit**

```bash
git add pdfcrack.c protocol.h server.c
git commit -m "perf: cache word lengths, chunk smart_try, buffer socket reads, batch dict send"
```

---

# Phase 7 — Features & robustness

### Task 7.1: GPU-accelerate owner-password search for R2-R4

Owner recovery (RC4) is CPU-only; R5/R6 already support `check_owner`.

**Files:**
- Modify: `metal_keygen.m`, `pdf_md5.metal`, callers

- [ ] **Step 1:** Add an owner-key derivation + recovery kernel for R2-R4 (Algorithm 3 → decrypt `/O` → verify against `/U`), returning a match index. Reuse the RC4 kernel from Task 6.7.
- [ ] **Step 2: Verify** owner-only runs against an R3/R4 PDF; **commit**.

```bash
git add metal_keygen.m pdf_md5.metal pdfcrack.c client.c
git commit -m "feat(gpu): owner-password GPU acceleration for R2-R4"
```

---

### Task 7.2: Cross-validate with `/Perms` (R5/R6)

`params.perms_value`/`has_perms` are parsed (`pdf_encrypt.c:430`) but never checked.

**Files:**
- Modify: `pdf_encrypt.c`

- [ ] **Step 1:** After a candidate's SHA-256/key matches, AES-decrypt the 16-byte `/Perms` and confirm the `"adb"` marker + permission bits as a cheap extra correctness gate (rejects rare false positives).
- [ ] **Step 2: Test** with a PDF that has `/Perms`; **commit**.

```bash
git add pdf_encrypt.c
git commit -m "feat(crypto): validate /Perms block for R5/R6"
```

---

### Task 7.3: Parser robustness — string-aware scanning, ObjStm, correct xref object

`find_dict_value` (`pdf_encrypt.c:207`) is not string/comment-aware; `/Encrypt` inside an `/ObjStm` isn't found; `find_forward("N G obj")` returns the first (possibly superseded) object.

**Files:**
- Modify: `pdf_encrypt.c`

- [ ] **Step 1:** Make `find_dict_value` skip literal `(...)` strings, hex `<...>` strings, and `%` comments while tracking `<<`/`>>` depth.
- [ ] **Step 2:** When resolving an indirect `/Encrypt`, prefer the object at the xref-resolved offset; if scanning, take the LAST `N G obj` match (active definition), not the first.
- [ ] **Step 3:** Add `skip_ws` form-feed (`0x0C`) handling (`pdf_encrypt.c:75`). Add an overflow guard in `parse_int` (`:91`).
- [ ] **Step 4 (stretch):** Resolve `/Encrypt` living inside a compressed object stream (`/ObjStm`) — note as a TODO if deferred.
- [ ] **Step 5: Test** — add crafted PDFs (string containing `>>`, incremental update with a superseded Encrypt) to the fuzz corpus + a unit case; **commit**.

```bash
git add pdf_encrypt.c
git commit -m "feat(parse): string/comment-aware dict scan; honor active xref object; form-feed ws"
```

---

### Task 7.4: GPU-R6 toggle variant

Already obtained for free if Task 5.3 is done (shared R6 driver). If not, add `gpu_r6_toggle_worker` mirroring the SHA-256 variant.

- [ ] **Step 1:** Confirm `--toggle` against an R6 PDF uses the GPU path (no silent CPU-only fallback).
- [ ] **Step 2: Test + commit** (likely no-op commit if Task 5.3 covered it).

---

### Task 7.5: SASLprep correctness + honest tests

`saslprep.c` claims a bidi check it doesn't implement; tests are thin (no RandALCat, no NFKC of decomposables, no invalid-UTF-8).

**Files:**
- Modify: `saslprep.c`, `test_saslprep.c`

- [ ] **Step 1:** Either implement RFC 3454 §6 bidi handling or remove the claim from the header comment.
- [ ] **Step 2:** Add `test_saslprep.c` cases: RandALCat (C.8), NFKC normalization of full-width/ligature/decomposable chars, and invalid-UTF-8/surrogate inputs — since SASLprep governs R5/R6 password equivalence with CoreGraphics, these are the silent-miss cases.
- [ ] **Step 3: Verify + commit**

```bash
git add saslprep.c test_saslprep.c
git commit -m "feat(saslprep): align bidi behavior with docs; add normalization/UTF-8 tests"
```

---

### Task 7.6: Distributed TLS/auth + PDF caching (larger, optional)

**Files:**
- Modify: `server.c`, `client.c`, `protocol.h`

- [ ] **Step 1:** Optional TLS for the cracking sockets (Security.framework `SSLContext` or a thin wrapper) gated behind a flag; document the trade-off.
- [ ] **Step 2:** Content-address the PDF by SHA-256: skip re-sending and re-benchmarking when a reconnecting client already has it (`send_session_config:920`).
- [ ] **Step 3:** Add a small lease-id hash map to replace the O(MAX_LEASES) linear scans (`find_lease:339`, reaper sweep).
- [ ] **Step 4: Verify + commit** (separate commits per item).

---

### Task 7.7: Documentation sync

**Files:**
- Modify: `README.md`, `BENCHMARKS.md`

- [ ] **Step 1:** Update README claims that diverged from reality: "integration covers distributed protocol basics" (now true after Task 2.4), "Intel supported" (CI only proves Apple Silicon — state Intel is untested or add an Intel CI lane), and the GPU-vs-CPU consistency description.
- [ ] **Step 2:** Refresh `BENCHMARKS.md` numbers after Phase 6 perf changes.
- [ ] **Step 3:** Update the stale `test_integration.sh:239` comment about charset restore (already implemented).
- [ ] **Step 4: Commit**

```bash
git add README.md BENCHMARKS.md test_integration.sh
git commit -m "docs: sync README/BENCHMARKS with current behavior and new benchmarks"
```

---

## Self-review checklist (run before execution)

- **Spec coverage:** every review finding maps to a task — client recursion (1.1), `-l` overflow (1.2), found truncation (1.3), parser over-reads (1.4), file_id/pw_len clamps (1.5), md5_x4 (1.6); CI/test gaps (2.1-2.6); checkpoint version/corruption/mode-table/skip/identity/atomicity (3.1-3.5); FOUND verify, heartbeat, races, slot DoS, timeouts, length clamps, PARTIAL, DONE, trust model (4.1-4.9); rule/GPU-struct/worker/main/HTTP/global/crypto/Metal dedup (5.1-5.8); R6 K1, storage mode, memset, owner SIMD, toggle, async handle, RC4-on-GPU, micro-opts (6.1-6.8); owner GPU, /Perms, parser robustness, R6 toggle, SASLprep, TLS/caching, docs (7.1-7.7). No finding left unassigned.
- **Risk ordering:** crashes/correctness first, safety net second, then refactor under green CI, then perf/features.
- **Every task ends in a build + test + commit.** No task claims completion without `make test` / `bash test_integration.sh` passing.

---

## Execution handoff

This plan spans independent subsystems; each phase is mergeable on its own. Recommended: execute Phase 1 immediately (small, high-value), then Phase 2 to lock in a safety net, then proceed phase by phase.

---

# Phase 8 — Performance testing & benchmarking (added by request)

Run AFTER Phase 6 (and ideally Phase 7), so the measured numbers reflect the optimized code. The existing benchmark numbers live in two places that must stay consistent: `BENCHMARKS.md` (full engine-comparison tables + methodology) and the `## Performance` section of `README.md` (the R2–R6 best-speed table + time-to-crack estimates).

**Caveat:** benchmarks are only meaningful on an otherwise-idle machine. If a heavy GPU/CPU task is running concurrently, GPU-bound numbers (R5/R6) and the GPU+NEON cooperative numbers (R3/R4) will read low. Capture the system load state alongside the numbers, and re-run on an idle machine before committing any doc update.

### Task 8.1: Measure current engine throughput

- [ ] **Step 1: Single-core / per-engine benchmark.** For each test PDF (R2–R6), run `./pdfcrack -f <pdf> -B` and record the `Bench: scalar …/s, NEON …/s, GPU …/s` line and the selected engine. The `-B` path already reports per-engine rates; capture all of them.
- [ ] **Step 2: Live attack-speed measurement.** For each revision, run a real brute-force/dict attack long enough for the live progress meter to stabilize (a charset that won't hit early), record the steady-state `…/s`, then Ctrl-C. This is the number the docs quote (`BENCHMARKS.md` says speeds are "measured from the live progress meter during an actual brute-force run").
- [ ] **Step 3: Record machine + load state.** Note chip, core/GPU counts (`sysctl -n machdep.cpu.brand_string`, `hw.ncpu`), and whether anything else was using the GPU/CPU at measurement time.

### Task 8.2: Compare against documented numbers and update docs

- [ ] **Step 1:** Diff measured numbers vs the tables in `BENCHMARKS.md` and `README.md`. Flag any regression (could indicate a Phase 5/6 change slowed something) or improvement (Phase 6 perf wins: R6 on-the-fly K1, private scratch storage, dropped memset, SIMD owner verify, RC4-on-GPU).
- [ ] **Step 2:** If a real, reproducible delta exists (measured on an idle machine), update the R2–R6 rows in both `BENCHMARKS.md` and the README Performance table, and refresh the time-to-crack estimate tables that derive from those rates. Keep the two docs in sync.
- [ ] **Step 3:** If numbers are unchanged within noise, note that the refactors (Phase 5) preserved throughput and the perf work (Phase 6) is reflected.
- [ ] **Step 4: Commit** `docs(bench): refresh R2–R6 throughput numbers measured on <machine>` (only if a doc change is warranted).

### Task 8.3 (optional): Add a repeatable benchmark harness

- [ ] Consider a small `bench.sh` that runs the `-B` benchmark across all test PDFs and prints a table, so future runs are one command and comparable over time. Keep it out of the CI gate (hardware-dependent; CI runners are shared/headless).
