#!/bin/bash
# test_integration.sh — End-to-end tests for pdfcracker
set -o pipefail

export HOME="$(mktemp -d)"        # never touch the real ~/.pdfcracker

# Always run from the script's directory
cd "$(dirname "$0")" || exit 1

PASS=0
FAIL=0
PDFCRACK=./pdfcrack
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR \"$HOME\"" EXIT   # clean both the temp workdir and the isolated HOME

run_test() {
    local name="$1"
    local expected="$2"
    shift 2
    local output
    output=$(timeout 60 "$@" 2>/dev/null) || true
    if echo "$output" | grep -qF "$expected"; then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name (expected: $expected)"
        echo "         got: $(echo "$output" | head -1)"
        FAIL=$((FAIL + 1))
    fi
}

run_test_stderr() {
    # Like run_test but checks stderr instead of stdout
    local name="$1"
    local expected="$2"
    shift 2
    local output
    output=$(timeout 60 "$@" 2>&1 >/dev/null) || true
    if echo "$output" | grep -qF "$expected"; then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name (expected: $expected)"
        FAIL=$((FAIL + 1))
    fi
}

run_test_timeout() {
    # Like run_test but with a custom timeout
    local name="$1"
    local expected="$2"
    local tmout="$3"
    shift 3
    local output
    output=$(timeout "$tmout" "$@" 2>/dev/null) || true
    if echo "$output" | grep -qF "$expected"; then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name (expected: $expected)"
        echo "         got: $(echo "$output" | head -1)"
        FAIL=$((FAIL + 1))
    fi
}

# Verify binary exists
if [ ! -x "$PDFCRACK" ]; then
    echo "ERROR: $PDFCRACK not found or not executable. Run 'make' first."
    exit 1
fi

echo "=== pdfcracker integration tests ==="

# --- 1. Dictionary R3 ---
echo "test123" > "$TMPDIR/dict_r3.txt"
run_test "Dictionary R3" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_r3.txt" --no-pot

# --- 2. Dictionary R6 ---
echo "user_r6" > "$TMPDIR/dict_r6.txt"
run_test_timeout "Dictionary R6" "user_r6" 120 \
    $PDFCRACK -f test_pikepdf_r6.pdf -d "$TMPDIR/dict_r6.txt" --no-pot

# --- 3. Brute-force R2 ---
run_test "Brute-force R2 (minimal charset)" "pass40" \
    $PDFCRACK -f test_r2_40bit.pdf -b -l 6 -c "pasw04" --no-pot

# --- 4. Mask literal ---
run_test "Mask literal" "passaes" \
    $PDFCRACK -f test_r4_aes128.pdf -m "passaes" --no-pot

# --- 5. Mask with charsets ---
run_test "Mask with charsets" "test123" \
    $PDFCRACK -f test_encrypted.pdf -m "test?d?d?d" --no-pot

# --- 6. Rules attack ---
echo "TEST123" > "$TMPDIR/dict_rules.txt"
echo "l" > "$TMPDIR/rules.txt"
run_test "Rules attack (lowercase)" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_rules.txt" -R "$TMPDIR/rules.txt" --no-pot

# --- 7. Hybrid attack ---
echo "test" > "$TMPDIR/dict_hybrid.txt"
run_test "Hybrid attack (dict+suffix)" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_hybrid.txt" -H 3 -c 0123456789 --no-pot

# --- 8. PRINCE attack ---
printf "test\n123\n" > "$TMPDIR/dict_prince.txt"
run_test "PRINCE attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_prince.txt" --prince --no-pot

# --- 9. Fingerprint ---
run_test "Fingerprint attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf --fingerprint --no-pot

# --- 10. Owner password ---
echo "owner40" > "$TMPDIR/dict_owner.txt"
run_test "Owner password (-O)" "owner40" \
    $PDFCRACK -f test_r2_40bit.pdf -d "$TMPDIR/dict_owner.txt" -O --no-pot

# --- 11. User only ---
echo "test123" > "$TMPDIR/dict_user.txt"
run_test "User only (-U)" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_user.txt" -U --no-pot

# --- 12. Benchmark mode ---
run_test_stderr "Benchmark mode" "Single-core" \
    $PDFCRACK -f test_encrypted.pdf -B --no-pot

# --- 13. Rule dedup ---
echo "TEST123" > "$TMPDIR/dict_dedup.txt"
echo "l" > "$TMPDIR/rules_dedup.txt"
run_test "Rule dedup (--dedup)" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_dedup.txt" -R "$TMPDIR/rules_dedup.txt" --dedup --no-pot

# --- 14. Max rounds R6 ---
echo "user_r6" > "$TMPDIR/dict_maxrounds.txt"
run_test_timeout "Max rounds R6 (--max-rounds 100)" "user_r6" 120 \
    $PDFCRACK -f test_pikepdf_r6.pdf -d "$TMPDIR/dict_maxrounds.txt" --max-rounds 100 --no-pot

# --- 15. Not found ---
echo "wrongpassword" > "$TMPDIR/dict_notfound.txt"
run_test "Not found" "Password not found" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_notfound.txt" --no-pot

# --- 16. Checkpoint/resume ---
echo "checkpoint test..."
rm -f test_r4_aes128.ckpt
$PDFCRACK -f test_r4_aes128.pdf -b -l 8 --no-pot &
PID=$!
sleep 2
kill -INT $PID 2>/dev/null
wait $PID 2>/dev/null
if [ -f test_r4_aes128.ckpt ]; then
    echo "  [PASS] checkpoint created"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] checkpoint not created"
    FAIL=$((FAIL + 1))
fi
rm -f test_r4_aes128.ckpt

# --- 17. Pot file ---
# Clear pot file, crack, then verify pot lookup
echo "test123" > "$TMPDIR/dict_pot.txt"
$PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_pot.txt" >/dev/null 2>&1
run_test "Pot file lookup" "Found in pot file: test123" \
    $PDFCRACK -f test_encrypted.pdf -b -l 1

# --- 18. JSON output ---
run_test "JSON output" '"status":"found"' \
    $PDFCRACK -f test_encrypted.pdf --fingerprint --json

# --- 19. Toggle-case attack ---
echo "TEST123" > "$TMPDIR/dict_toggle.txt"
run_test "Toggle-case attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_toggle.txt" --toggle --no-pot

# --- 20. Combinator attack ---
echo "test" > "$TMPDIR/dict_combo1.txt"
echo "123" > "$TMPDIR/dict_combo2.txt"
run_test "Combinator attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_combo1.txt" --combinator "$TMPDIR/dict_combo2.txt" --no-pot

# --- 21. Mask+rules attack ---
echo ":" > "$TMPDIR/rules_identity.txt"
run_test "Mask+rules attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf -m "test?d?d?d" -R "$TMPDIR/rules_identity.txt" --no-pot

# --- 22. Progress file ---
PROGRESS_FILE="$TMPDIR/progress.json"
# Run brute-force long enough for the progress thread to write at least once (~0.5s intervals)
# Use a charset that won't find the password, let it run 2 seconds then kill
timeout 3 $PDFCRACK -f test_encrypted.pdf -b -l 4 -c "XYZW" --progress-file "$PROGRESS_FILE" --no-pot >/dev/null 2>&1 || true
if [ -f "$PROGRESS_FILE" ] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$PROGRESS_FILE" 2>/dev/null; then
    echo "  [PASS] Progress file (valid JSON)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Progress file (missing or invalid JSON)"
    FAIL=$((FAIL + 1))
fi

# --- 23. Custom pot file ---
CUSTOM_POT="$TMPDIR/custom.pot"
rm -f "$CUSTOM_POT"
echo "test123" > "$TMPDIR/dict_custompot.txt"
$PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_custompot.txt" --pot-file "$CUSTOM_POT" >/dev/null 2>&1
if [ -f "$CUSTOM_POT" ] && grep -qF "test123" "$CUSTOM_POT"; then
    echo "  [PASS] Custom pot file"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Custom pot file (missing or no password)"
    FAIL=$((FAIL + 1))
fi

# --- 24. Date attack ---
run_test "Date attack" "Password not found" \
    $PDFCRACK -f test_encrypted.pdf --dates --date-range 2020-2022 --no-pot

# --- 25. Mutate attack ---
echo "test" > "$TMPDIR/dict_mutate.txt"
run_test "Mutate attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_mutate.txt" --mutate --no-pot

# --- 26. Leet attack ---
echo "test123" > "$TMPDIR/dict_leet.txt"
run_test "Leet attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_leet.txt" --leet --no-pot

# --- 27. Checkpoint resume end-to-end ---
echo "checkpoint resume test..."
rm -f test_r4_aes128.ckpt
# Use timeout to stop first run (sends SIGTERM, pdfcrack saves checkpoint).
# Charset "aepstuvwxyz" (11 chars), len 7. ~19M passwords, ~15s to exhaust.
# timeout 2 interrupts after 2s, creating checkpoint.
timeout 2 $PDFCRACK -f test_r4_aes128.pdf -b -l 7 -c "aepstuvwxyz" --no-pot >/dev/null 2>/dev/null || true
sleep 1
if [ -f test_r4_aes128.ckpt ]; then
    # Resume from checkpoint — must re-specify charset and max-len
    # (checkpoint stores them but runtime doesn't restore charset yet)
    output=$(timeout 60 $PDFCRACK -f test_r4_aes128.pdf -b -l 7 -c "aepstuvwxyz" --no-pot -r 2>/dev/null) || true
    if echo "$output" | grep -qF "passaes"; then
        echo "  [PASS] Checkpoint resume end-to-end"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] Checkpoint resume end-to-end (password not found after resume)"
        echo "         got: $(echo "$output" | head -1)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  [FAIL] Checkpoint resume end-to-end (checkpoint not created)"
    FAIL=$((FAIL + 1))
fi
rm -f test_r4_aes128.ckpt

# --- 28. Malicious checkpoint values ---
echo "malicious checkpoint test..."
# Place malicious checkpoint where pdfcrack will auto-detect it
cat > test_encrypted.ckpt <<'CKPT'
current_idx=0
current_len=999999
attack_mode=0
charset=abc
CKPT
output=$($PDFCRACK -f test_encrypted.pdf -b --no-pot -r 2>&1) || true
rm -f test_encrypted.ckpt
if echo "$output" | grep -qiE "invalid|error|must be"; then
    echo "  [PASS] Malicious checkpoint rejected"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Malicious checkpoint rejected (no error for current_len=999999)"
    FAIL=$((FAIL + 1))
fi

# --- 29. Empty wordlist ---
run_test "Empty wordlist" "Password not found" \
    $PDFCRACK -f test_encrypted.pdf -d /dev/null --no-pot

# --- 30. R6 owner password ---
echo "owner_r6" > "$TMPDIR/dict_r6_owner.txt"
run_test_timeout "R6 owner password (-O)" "owner_r6" 120 \
    $PDFCRACK -f test_pikepdf_r6.pdf -d "$TMPDIR/dict_r6_owner.txt" -O --no-pot

# --- 31. Max-length password (32 chars) ---
# Use a mask to test a known 32-char password boundary
# We can't easily create a 32-char password PDF, so test that the tool
# handles 32-char input without crash
echo "abcdefghijklmnopqrstuvwxyz123456" > "$TMPDIR/dict_32char.txt"
output=$(timeout 10 $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_32char.txt" --no-pot 2>&1) || true
if ! echo "$output" | grep -qiE "crash|segfault|abort"; then
    echo "  [PASS] Max-length password (no crash)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Max-length password (crashed)"
    FAIL=$((FAIL + 1))
fi

# --- 32. Benchmark regression gate ---
bench_output=$(timeout 60 $PDFCRACK -f test_r4_aes128.pdf -B --no-pot 2>&1) || true
speed=$(echo "$bench_output" | grep -i "single-core" | grep -oE '[0-9]+' | head -1)
if [ "${speed:-0}" -gt 0 ]; then
    echo "  [PASS] Benchmark regression gate (${speed}/s > 0)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Benchmark regression gate (no positive throughput reported)"
    FAIL=$((FAIL + 1))
fi

# --- 33. GPU vs CPU consistency (R5) ---
# Both GPU and CPU-only paths must find the same password on R5 (AES-256).
GWL="$TMPDIR/gwl_r5.txt"
printf 'nope1\npass256\nnope2\n' > "$GWL"
g_out=$(timeout 30 $PDFCRACK -f test_r5_aes256.pdf -d "$GWL" --no-pot 2>&1 | grep -i 'found') || true
c_out=$(timeout 30 $PDFCRACK -f test_r5_aes256.pdf -d "$GWL" -G --no-pot 2>&1 | grep -i 'found') || true
if [ -n "$g_out" ] && [ "$g_out" = "$c_out" ]; then
    echo "  [PASS] GPU vs CPU consistency (R5)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] GPU vs CPU consistency (R5) g='$g_out' c='$c_out'"
    FAIL=$((FAIL + 1))
fi

# --- 34. Metadata seeds (no crash with --metadata-seeds) ---
echo "test123" > "$TMPDIR/dict_meta.txt"
run_test "Metadata seeds" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_meta.txt" --metadata-seeds --no-pot

# --- 35. Checkpoint charset restore ---
echo "checkpoint charset restore test..."
rm -f test_r4_aes128.ckpt
timeout 2 $PDFCRACK -f test_r4_aes128.pdf -b -l 7 -c "aepstuvwxyz" --no-pot >/dev/null 2>/dev/null || true
sleep 1
if [ -f test_r4_aes128.ckpt ]; then
    # Resume WITHOUT specifying -c — charset should be restored from checkpoint
    output=$(timeout 60 $PDFCRACK -f test_r4_aes128.pdf -b -l 7 --no-pot -r 2>&1) || true
    if echo "$output" | grep -qF "aepstuvwxyz"; then
        echo "  [PASS] Checkpoint charset restore"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] Checkpoint charset restore (charset not restored)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  [FAIL] Checkpoint charset restore (no checkpoint)"
    FAIL=$((FAIL + 1))
fi
rm -f test_r4_aes128.ckpt

# --- 36. Smart attack ---
run_test "Smart attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf --smart --no-pot

# --- 37. Smart attack with dict (reversed word) ---
echo "321tset" > "$TMPDIR/dict_smart_rev.txt"
run_test "Smart attack with dict (reversed word)" "test123" \
    $PDFCRACK -f test_encrypted.pdf --smart -d "$TMPDIR/dict_smart_rev.txt" --no-pot

# --- 38. Reverse dict attack ---
echo "321tset" > "$TMPDIR/dict_reverse.txt"
run_test "Reverse dict attack" "test123" \
    $PDFCRACK -f test_encrypted.pdf -d "$TMPDIR/dict_reverse.txt" --reverse --no-pot

# --- 39. Pattern attack (runs without crash) ---
run_test "Pattern attack (no crash)" "Password not found" \
    $PDFCRACK -f test_encrypted.pdf --pattern --no-pot

# --- 40. Reverse requires dict validation ---
output=$($PDFCRACK -f test_encrypted.pdf --reverse --no-pot 2>&1) || true
if echo "$output" | grep -qiE "requires.*-d|wordlist"; then
    echo "  [PASS] Reverse requires dict validation"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Reverse requires dict validation"
    FAIL=$((FAIL + 1))
fi

# --- 41. Smart attack with reversed dict word ---
echo "seassap" > "$TMPDIR/dict_smart_r4.txt"
run_test "Smart finds reversed dict word" "passaes" \
    $PDFCRACK -f test_r4_aes128.pdf --smart -d "$TMPDIR/dict_smart_r4.txt" --no-pot

# --- 42. -l clamp regression (-l beyond MAX_PASS_LEN must clamp, not crash) ---
out=$(./pdfcrack -f test_r2_40bit.pdf -b -l 40 -B 2>&1)
if echo "$out" | grep -q "clamped"; then
    echo "  [PASS] -l clamp regression"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] -l clamp regression (no 'clamped' in output)"
    FAIL=$((FAIL + 1))
fi

# --- 43. Distributed loopback (server+client, BOTH mode, CPU path) ---
# Coverage for the client recursion fix (test_password_fast_mode).
# The server binary is copied to $TMPDIR so its dirname has no sibling 'client'
# binary — this prevents the server from spawning its own local subprocess,
# which would race our test client to the password on a 4-word dict.
echo "distributed loopback test..."
DPORT=19099
DWL="$TMPDIR/dwl.txt"
printf 'wrong1\nwrong2\npassaes\nwrong3\n' > "$DWL"
cp ./server "$TMPDIR/srvbin"
"$TMPDIR/srvbin" -f test_r4_aes128.pdf -d "$DWL" -p $DPORT > "$TMPDIR/srv.log" 2>&1 &
SRVPID=$!
sleep 1
timeout 30 ./client -s 127.0.0.1 -p $DPORT -G > "$TMPDIR/cli.log" 2>&1
CRC=$?
sleep 1
kill $SRVPID 2>/dev/null; wait $SRVPID 2>/dev/null
if grep -qi 'passaes' "$TMPDIR/srv.log" && [ $CRC -ne 124 ]; then
    echo "  [PASS] Distributed loopback (server+client, BOTH mode, CPU path)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Distributed loopback (server+client, BOTH mode, CPU path)"
    echo "         srv: $(grep -i 'passaes\|password\|found' "$TMPDIR/srv.log" 2>/dev/null | head -3)"
    echo "         cli: $(head -3 "$TMPDIR/cli.log" 2>/dev/null)"
    echo "         client exit: $CRC"
    FAIL=$((FAIL + 1))
fi

# --- 44. Corrupt checkpoint must be rejected gracefully (start fresh, no abort) ---
# ckpt_make_path derives test_r2_40bit.ckpt from test_r2_40bit.pdf
echo "totally not a valid checkpoint" > test_r2_40bit.ckpt
out=$(./pdfcrack -f test_r2_40bit.pdf -b -l 1 -c "p" -r --no-pot 2>&1); rc=$?
rm -f test_r2_40bit.ckpt
# Must have run to completion (rc 0 = found, rc 1 = not-found), not crashed/aborted.
if [ $rc -le 1 ]; then
    echo "  [PASS] Corrupt checkpoint rejected gracefully (exit=$rc)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] Corrupt checkpoint rejected gracefully (exit=$rc, expected 0 or 1)"
    FAIL=$((FAIL + 1))
fi

# --- 45. Checkpoint bound to its document: fingerprint mismatch starts fresh ---
# ckpt_make_path derives test_r4_aes128.ckpt from test_r4_aes128.pdf
rm -f test_r4_aes128.ckpt
# Run brute on the R4 PDF long enough for a checkpoint to be saved.
timeout 2 $PDFCRACK -f test_r4_aes128.pdf -b -l 8 --no-pot >/dev/null 2>/dev/null || true
sleep 1
if [ -f test_r4_aes128.ckpt ]; then
    # Reuse R4's checkpoint under the R2 PDF's expected checkpoint path.
    # ckpt_make_path for test_r2_40bit.pdf → test_r2_40bit.ckpt
    cp test_r4_aes128.ckpt test_r2_40bit.ckpt
    out=$(./pdfcrack -f test_r2_40bit.pdf -b -l 1 -c "p" -r --no-pot 2>&1)
    rm -f test_r4_aes128.ckpt test_r2_40bit.ckpt
    if echo "$out" | grep -qi "different document"; then
        echo "  [PASS] Checkpoint document-mismatch rejection"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] Checkpoint document-mismatch rejection (expected 'different document' in output)"
        echo "         got: $(echo "$out" | grep -i 'checkpoint\|document\|fingerprint' | head -3)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  [FAIL] Checkpoint document-mismatch rejection (checkpoint not created in 2s)"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Summary ==="
echo "Total: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi
