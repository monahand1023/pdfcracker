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
pdf_encrypt.o: pdf_encrypt.c pdf_encrypt.h saslprep.h
	$(CC) $(CFLAGS) -c pdf_encrypt.c

# ── Metal GPU key derivation ─────────────────────────────────
pdf_md5.air: pdf_md5.metal
	xcrun -sdk macosx metal -c pdf_md5.metal -o pdf_md5.air

pdf_md5.metallib: pdf_md5.air
	xcrun -sdk macosx metallib pdf_md5.air -o pdf_md5.metallib

metal_keygen.o: metal_keygen.m metal_keygen.h pdf_encrypt.h
	$(CC) $(CFLAGS) -fobjc-arc -c metal_keygen.m

# ── Targets ──────────────────────────────────────────────────
pdfcrack: pdfcrack.c pdf_encrypt.o saslprep.o metal_keygen.o pdf_md5.metallib pdf_encrypt.h metal_keygen.h protocol.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(METAL_FRAMEWORKS) $(LIBS) -o $@ pdfcrack.c pdf_encrypt.o saslprep.o metal_keygen.o

server: server.c protocol.h pdf_encrypt.o saslprep.o pdf_encrypt.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(LIBS) -o $@ server.c pdf_encrypt.o saslprep.o

client: client.c pdf_encrypt.o saslprep.o metal_keygen.o pdf_md5.metallib pdf_encrypt.h metal_keygen.h protocol.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(METAL_FRAMEWORKS) $(LIBS) -o $@ client.c pdf_encrypt.o saslprep.o metal_keygen.o

# ── Test suite ───────────────────────────────────────────────
test_all: test_all.c pdf_encrypt.o saslprep.o pdf_encrypt.h
	$(CC) $(CFLAGS) $(FRAMEWORKS) -o $@ test_all.c pdf_encrypt.o saslprep.o

clean:
	rm -f pdfcrack server client test_all *.o *.air *.metallib

.PHONY: all clean
