#!/bin/bash
# bench.sh — repeatable per-engine benchmark across all R2–R6 test PDFs.
#
# Runs pdfcrack -B (benchmark mode) on each bundled test PDF and prints the
# per-engine throughput line. For authoritative numbers, run on an OTHERWISE
# IDLE machine — a competing GPU/CPU task skews the GPU-bound (R5/R6) and
# cooperative (R3/R4) figures low. This script warns if it detects heavy load.
#
# Usage: bash bench.sh
#
# NOTE: -B reports per-engine/per-core estimates. The headline numbers in
# BENCHMARKS.md / README are measured from the LIVE progress meter during a
# real attack run; treat -B as a quick relative check, not a doc source.

set -o pipefail
cd "$(dirname "$0")" || exit 1

if [ ! -x ./pdfcrack ]; then
    echo "ERROR: ./pdfcrack not found — run 'make' first." >&2
    exit 1
fi

echo "=== System ==="
echo "  CPU : $(sysctl -n machdep.cpu.brand_string)  ($(sysctl -n hw.ncpu) cores)"
echo "  OS  : $(sw_vers -productName) $(sw_vers -productVersion)"

# Crude load check: any non-pdfcrack process burning >40% CPU?
busy=$(ps aux | awk '$3 > 40 && $11 !~ /pdfcrack/ {print $3"% "$11}' | head -3)
if [ -n "$busy" ]; then
    echo
    echo "  ⚠️  WARNING: heavy load detected — GPU/CPU-bound numbers will read LOW:"
    echo "$busy" | sed 's/^/      /'
fi

echo
printf "%-22s %-34s %s\n" "PDF" "Revision" "Benchmark"
printf "%-22s %-34s %s\n" "----------------------" "----------------------------------" "---------"

for pdf in test_r2_40bit.pdf test_encrypted.pdf test_r4_aes128.pdf test_r5_aes256.pdf test_pikepdf_r6.pdf; do
    [ -f "$pdf" ] || continue
    crypto=$(./pdfcrack -f "$pdf" -B 2>&1 | grep -i '^Crypto' | sed 's/Crypto *: *//')
    bench=$(./pdfcrack -f "$pdf" -B 2>&1 | grep -iE '^Bench|Single-core' | head -1 | sed 's/^Bench *: *//;s/^ *//')
    printf "%-22s %-34s %s\n" "$pdf" "$crypto" "$bench"
done

echo
echo "For doc-grade numbers, run a real attack and read the live progress meter, e.g.:"
echo "  ./pdfcrack -f test_r5_aes256.pdf -b -l 7 -c abcdefgh   # watch the steady-state .../s"
