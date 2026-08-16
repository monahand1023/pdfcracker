# pdfunlock

**One command to recover an encrypted PDF's password *and* write a decrypted copy.**

`pdfunlock` is a small front-end around the two tools that already do the work:
it drives the local **`pdfcrack`** engine to recover the user (open) password,
then uses **`qpdf`** to write a fully-decrypted `"<name> (decrypted).pdf"` next
to the original. Point it at a file or a whole folder and walk away.

Your original PDFs are never modified.

---

## Build

```bash
make pdfunlock        # just this tool
# or
make                  # pdfcrack, server, client, and pdfunlock
```

`pdfunlock` itself is plain C with no special dependencies. It relies on two
external programs at run time:

| Tool       | Needed for            | Get it                     |
|------------|-----------------------|----------------------------|
| `pdfcrack` | cracking the password | built here with `make`     |
| `qpdf`     | writing the decrypted copy | `brew install qpdf` (skip with `--no-decrypt`) |

---

## Quick start

```bash
# Just go: scan the current directory and decrypt everything encrypted here
./pdfunlock

# Crack + decrypt every encrypted PDF in a folder
./pdfunlock "/path/to/Green Card Docs/"

# A single file, trying a personal wordlist first (names, dates, etc.)
./pdfunlock -d hints.txt "locked.pdf"

# Just tell me the password, don't write a decrypted copy
./pdfunlock --no-decrypt "locked.pdf"

# Escalate to the slow, thorough attack if the quick passes miss
./pdfunlock --deep "locked.pdf"
```

Typical output:

```
pdfunlock: 5 PDFs to process
  engine : ./pdfcrack
  decrypt: qpdf
  log    : /path/to/Green Card Docs/pdfunlock-passwords.txt

  →  I-130 - MONAHAN, Daniel-Monahan2016.pdf            cracking...
  ✓  I-130 - MONAHAN, Daniel-Monahan2016.pdf            password: Monahan2016  -> I-130 - MONAHAN, Daniel-Monahan2016 (decrypted).pdf
  ...
pdfunlock: 5/5 unlocked.
Passwords saved to: /path/to/Green Card Docs/pdfunlock-passwords.txt
```

---

## How it cracks (staged — stops at the first hit)

1. **pot lookup + fingerprint sweep** — instant if the password was recovered
   before (cached in `~/.pdfcracker/pdfcracker.pot`); otherwise a fast sweep of
   common passwords, keyboard walks, dates, and short PINs (~1.3M candidates,
   seconds).
2. **`-d <wordlist>`** — your wordlist with mutations + reversals applied
   (only if you pass `-d`). This is the fast lane for personal passwords
   (a name, a surname + year, etc.).
3. **`--deep`** — the full multi-phase `--smart` attack (metadata seeds, name +
   date cross-products, PINs, short brute-force). Thorough but can take a long
   time; only runs when you ask.

> **Tip:** most human-chosen PDF passwords are a name, a word + a year, a date,
> or a short PIN. A 10-line `-d` wordlist of relevant names/words usually beats
> hours of brute force. Put one candidate per line.

---

## Options

| Flag | Meaning |
|------|---------|
| `-d, --dict <file>` | Targeted wordlist (tried with mutations + reversal). |
| `--deep` | Also run the slow `--smart` attack if the quick passes miss. |
| `-o, --outdir <dir>` | Write decrypted copies here (default: beside each original). |
| `-P, --passwords <file>` | Password log path (default: `<target-dir>/pdfunlock-passwords.txt`). |
| `--no-decrypt` | Only recover/print the password; don't run qpdf. |
| `-r, --recursive` | Descend into sub-directories when given a folder. |
| `-q, --quiet` | Hide `pdfcrack`'s live progress meter. |
| `--pdfcrack <path>` | Explicit path to the `pdfcrack` binary. |
| `--qpdf <path>` | Explicit path to the `qpdf` binary. |
| `-h, --help` | Built-in help. |

---

## Running it from anywhere

`pdfunlock` finds `pdfcrack` in this order: `$PDFCRACK` → the same directory as
the `pdfunlock` binary → your `PATH`. So the easy options are:

```bash
# Option A — run it from the repo directory (simplest)
cd /Users/danm/Development/pdfcracker
./pdfunlock "~/Documents/whatever/"

# Option B — put the repo on your PATH (run from anywhere)
echo 'export PATH="$PATH:/Users/danm/Development/pdfcracker"' >> ~/.zshrc
# then: pdfunlock "~/Documents/whatever/"

# Option C — install both binaries somewhere on PATH
sudo cp pdfcrack pdfunlock /usr/local/bin/
```

(If you copy only `pdfunlock` somewhere and leave `pdfcrack` behind, point it
back with `PDFCRACK=/path/to/pdfcrack pdfunlock ...` or `--pdfcrack`.)

---

## Notes & troubleshooting

- **Owner-locked PDFs** (permission restrictions, empty open password) are
  detected automatically — the password logs as `(empty / owner-locked)` and a
  fully-unrestricted copy is still written.
- **Password not found?** Add `-d <wordlist>` with likely candidates, then try
  `--deep`. The two combine: `--deep -d hints.txt` seeds the smart attack with
  your words.
- **Re-runs are instant.** Once a password is recovered it's cached in the pot
  file, so running `pdfunlock` on the same document again returns immediately.
- **Security:** the recovered password is handed to `qpdf` over stdin
  (`--password-file=-`), so it never appears in `ps` output.
- **`make pdfcrack` fails with "missing Metal Toolchain":** the GPU shader
  needs Xcode's Metal toolchain (`xcodebuild -downloadComponent MetalToolchain`).
  The already-built `pdfcrack` binary and `pdf_md5.metallib` work without it;
  `pdfunlock` itself has no such dependency.

---

## Only recover the password (no decrypt)

If you'd rather not produce decrypted copies:

```bash
./pdfunlock --no-decrypt -d hints.txt "locked.pdf"
# -> prints the password and logs it; qpdf is never invoked.
```
