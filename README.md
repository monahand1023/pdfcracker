# pdfcracker

Fast PDF password cracker for macOS, optimized for Apple Silicon. Supports dictionary and brute-force attacks using all CPU cores and GPU via Metal compute shaders.

## Requirements

- macOS (Apple Silicon or Intel)
- Xcode Command Line Tools: `xcode-select --install`

No other dependencies. Uses CommonCrypto, CoreGraphics, and Metal — all built into macOS.

## Build

```bash
git clone <repo-url> && cd pdfcracker
make
```

This builds three binaries: `pdfcrack` (standalone), `server` (distributed coordinator), and `client` (distributed worker).

## Quick Start

### Standalone (single machine)

```bash
# Dictionary attack
./pdfcrack -f document.pdf -d wordlist.txt

# Brute-force (all letters + digits, up to 8 characters)
./pdfcrack -f document.pdf -b -l 8

# Brute-force with digits only
./pdfcrack -f document.pdf -b -l 10 -c 0123456789

# Interactive mode — asks about known password details
./pdfcrack -f document.pdf -i
```

### Options

| Flag | Description |
|------|-------------|
| `-f <file>` | PDF file to crack (required) |
| `-d <wordlist>` | Dictionary attack with wordlist file |
| `-b` | Brute-force mode |
| `-l <length>` | Max password length for brute-force (default: 4) |
| `-c <charset>` | Custom charset (default: a-z A-Z 0-9) |
| `-t <threads>` | Number of CPU threads (default: all cores) |
| `-G` | Disable GPU acceleration |
| `-r` | Resume from checkpoint |
| `-i` | Interactive mode — prompts for password hints |

### Checkpoints

Interrupted runs are saved automatically. Resume with:

```bash
./pdfcrack -f document.pdf -b -l 8 -r
```

## Distributed Cracking

For cracking across multiple Macs on the same network. The server coordinates work and also cracks locally — other machines join to help.

### Start the server

On your main Mac:

```bash
# Brute-force
./server -f document.pdf -b -l 10

# Dictionary
./server -f document.pdf -d wordlist.txt

# Custom port
./server -f document.pdf -b -l 10 -p 8888
```

This starts cracking locally and listens for remote workers on port 9999 (default).

### Add more machines

On any other Mac on the network, run one command:

```bash
curl http://<server-ip>:9999/join.sh | bash
```

The server IP is printed when the server starts. This downloads the client binary and starts cracking automatically. The client installs to `~/.pdfcracker/`.

#### Alternative: push from server

If the remote Mac has SSH enabled (System Settings → General → Sharing → Remote Login):

```bash
# From the server machine
./deploy.sh user@other-mac.local

# Multiple machines
./deploy.sh user@mac-mini.local &
./deploy.sh user@macbook.local &
wait
```

### Firewall

The server binary needs to accept incoming connections. On the server Mac:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/server
```

Or allow it when macOS shows the "Allow incoming connections?" dialog on first run.

### How it works

- The server assigns work chunks with **leases** (deadlines). If a client disconnects or goes silent, the chunk is re-queued and given to another client.
- Clients auto-reconnect with exponential backoff if the connection drops.
- Each client has a persistent UUID (`~/.pdfcracker_id`) so the server recognizes reconnections.
- The server checkpoints progress every 30 seconds. Restore with `-R`:

```bash
./server -f document.pdf -b -l 10 -R document.pdf.server.ckpt
```

## Performance

Tested on M4 Pro (14 cores):

| Revision | Speed (CPU+GPU) | Notes |
|----------|----------------|-------|
| R2 (40-bit RC4) | ~4.5M/s | Fastest |
| R3 (128-bit RC4) | ~300K/s | Most common |
| R4 (AES-128) | ~300K/s | Same crypto as R3 |
| R5 (AES-256) | ~20M/s | SHA-256 based |
| R6 (AES-256) | ~3K/s | Deliberately slow KDF |

GPU acceleration provides ~30% speedup for R2-R4 by offloading MD5 key derivation to Metal while CPU handles RC4 verification.

## Supported PDF Encryption

| Revision | Algorithm | Status |
|----------|-----------|--------|
| R2 | 40-bit RC4 | Direct crypto (fast) |
| R3 | 128-bit RC4 | Direct crypto (fast) |
| R4 | AES-128 | Direct crypto (fast) |
| R5 | AES-256 / SHA-256 | Direct crypto (fast) |
| R6 | AES-256 / SHA-256+KDF | Direct crypto (slow by design) |

## Files

| File | Purpose |
|------|---------|
| `pdfcrack.c` | Standalone single-machine cracker |
| `server.c` | Distributed coordinator + local worker |
| `client.c` | Distributed worker node |
| `protocol.h` | Shared protocol constants and helpers |
| `pdf_encrypt.c` | PDF parser and crypto verification |
| `pdf_encrypt.h` | Parser/crypto API |
| `pdf_md5.metal` | Metal GPU shader for MD5 key derivation |
| `metal_keygen.m` | Objective-C Metal pipeline |
| `metal_keygen.h` | Metal API header |
| `deploy.sh` | Push client to remote Mac over SSH |
| `join.sh` | Pull client from server over SSH |
| `test_all.c` | Test suite (32 tests across 8 PDF variants) |
| `Makefile` | Build system |

## Running Tests

```bash
make test_all
./test_all
```

Runs 32 tests across 8 PDF variants (R2, R3, R4, R5, R6, pikepdf variants), verifying both password acceptance and rejection against Apple's CoreGraphics API.
