CC         = clang
CFLAGS     = -O3 -Wall
FRAMEWORKS = -framework CoreGraphics -framework Foundation -framework Security
METAL_FRAMEWORKS = -framework Metal -framework Foundation
LIBS       = -lpthread

all: pdfcrack server client

# ── SASLprep Unicode normalization ─────────────────────────────
saslprep.o: saslprep.c saslprep.h
	$(CC) $(CFLAGS) -c saslprep.c

# ── PDF encryption parser + crypto ────────────────────────────
pdf_encrypt.o: pdf_encrypt.c pdf_encrypt.h saslprep.h sha256_simd.h sha512_simd.h aes_simd.h
	$(CC) $(CFLAGS) -c pdf_encrypt.c

# ── Metal GPU key derivation ─────────────────────────────────
pdf_md5.air: pdf_md5.metal
	xcrun -sdk macosx metal -c pdf_md5.metal -o pdf_md5.air

pdf_md5.metallib: pdf_md5.air
	xcrun -sdk macosx metallib pdf_md5.air -o pdf_md5.metallib

metal_keygen.o: metal_keygen.m metal_keygen.h pdf_encrypt.h
	$(CC) $(CFLAGS) -fobjc-arc -c metal_keygen.m

# ── Checkpoint module ────────────────────────────────────────
checkpoint.o: checkpoint.c checkpoint.h
	$(CC) $(CFLAGS) -c checkpoint.c

# ── Rule engine ──────────────────────────────────────────────
rules.o: rules.c rules.h
	$(CC) $(CFLAGS) -c rules.c

# ── Targets ──────────────────────────────────────────────────
pdfcrack: pdfcrack.c checkpoint.o pdf_encrypt.o saslprep.o metal_keygen.o rules.o pdf_md5.metallib pdf_encrypt.h metal_keygen.h protocol.h checkpoint.h rules.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(METAL_FRAMEWORKS) $(LIBS) -o $@ pdfcrack.c checkpoint.o pdf_encrypt.o saslprep.o metal_keygen.o rules.o

server: server.c protocol.h pdf_encrypt.o saslprep.o pdf_encrypt.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(LIBS) -o $@ server.c pdf_encrypt.o saslprep.o

client: client.c pdf_encrypt.o saslprep.o metal_keygen.o pdf_md5.metallib pdf_encrypt.h metal_keygen.h protocol.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(METAL_FRAMEWORKS) $(LIBS) -o $@ client.c pdf_encrypt.o saslprep.o metal_keygen.o

# ── Test suite ───────────────────────────────────────────────
test_all: test_all.c pdf_encrypt.o saslprep.o pdf_encrypt.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) -o $@ test_all.c pdf_encrypt.o saslprep.o

test_saslprep: test_saslprep.c saslprep.o saslprep.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) -o $@ test_saslprep.c saslprep.o

test_crypto: test_crypto.c pdf_encrypt.o saslprep.o pdf_encrypt.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) -o $@ test_crypto.c pdf_encrypt.o saslprep.o

test: test_all test_saslprep test_crypto
	./test_all
	./test_saslprep
	./test_crypto

clean:
	rm -f pdfcrack server client test_all test_crypto test_saslprep fuzz_rules fuzz_parse checkpoint.o rules.o *.o *.air *.metallib *.profraw *.profdata

test-integration: pdfcrack
	./test_integration.sh

# Apple clang lacks the libFuzzer runtime; prefer Homebrew LLVM, fall back to clang.
FUZZ_CC ?= $(shell command -v /opt/homebrew/opt/llvm/bin/clang 2>/dev/null || echo clang)

fuzz-rules: fuzz_rules.c rules.c rules.h
	$(FUZZ_CC) -fsanitize=fuzzer,address,undefined -o fuzz_rules fuzz_rules.c rules.c

fuzz-parse: test_parse_fuzz.c pdf_encrypt.c saslprep.c
	$(FUZZ_CC) -O1 -g -fsanitize=fuzzer,address,undefined \
	  -o fuzz_parse test_parse_fuzz.c pdf_encrypt.c saslprep.c $(FRAMEWORKS)

# ── Profile-guided optimization (PGO) ───────────────────────
pgo:
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) -fprofile-generate"
	./pdfcrack -f test_r4_aes128.pdf -B
	$(MAKE) clean
	$(MAKE) CFLAGS="$(CFLAGS) -fprofile-use -fprofile-correction"

.PHONY: all clean test test-integration fuzz-rules fuzz-parse pgo
