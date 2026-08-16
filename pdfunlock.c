/* ================================================================
 * pdfunlock — one-command "crack + decrypt" front-end for pdfcracker
 * ----------------------------------------------------------------
 * Point it at an encrypted PDF (or a folder of them). For each file it:
 *   1. recovers the user (open) password with the local `pdfcrack`
 *      engine — instant if the password is already in the pot file,
 *      otherwise a fingerprint sweep, an optional targeted dictionary,
 *      and an optional deep (--smart) pass;
 *   2. writes a fully-decrypted "<name> (decrypted).pdf" alongside the
 *      original using `qpdf` (originals are never modified);
 *   3. appends "<file> <TAB> <password>" to a passwords log.
 *
 * It shells out to the existing tools rather than re-implementing them:
 * pdfcrack does the cracking, qpdf does the decrypt/rewrite. The
 * password is handed to qpdf over stdin (--password-file=-) so it never
 * shows up in `ps`.
 *
 * Build:  make pdfunlock      (or: cc -O2 -Wall -o pdfunlock pdfunlock.c)
 * Help:   ./pdfunlock --help
 * ================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#define MAX_PW      512
#define MAX_PATH    4096
#define MAX_TARGETS 4096

/* ---- resolved tool paths & options (set in main) ------------------ */
static const char *g_pdfcrack = NULL;   /* path to pdfcrack binary   */
static const char *g_qpdf     = NULL;   /* path to qpdf binary       */
static const char *g_dict     = NULL;   /* optional -d wordlist      */
static const char *g_outdir   = NULL;   /* optional output directory */
static const char *g_logpath  = NULL;   /* passwords log path        */
static int  g_deep       = 0;           /* also run --smart          */
static int  g_no_decrypt = 0;           /* crack only, no qpdf        */
static int  g_recursive  = 0;           /* recurse into subdirs      */
static int  g_quiet      = 0;           /* suppress pdfcrack banners */

/* ================================================================
 * Run a child process, capture its stdout into buf, let its stderr
 * pass through to the terminal (so pdfcrack's live progress shows).
 * Optionally feed `stdin_data` to the child's stdin.
 * Returns the child's exit code, or -1 on spawn failure.
 * ================================================================ */
static int run_capture(char *const argv[], char *buf, size_t bufsz,
                       const char *stdin_data)
{
    int outpipe[2] = {-1, -1};
    int inpipe[2]  = {-1, -1};
    if (buf && pipe(outpipe) != 0) return -1;
    if (stdin_data && pipe(inpipe) != 0) {
        if (buf) { close(outpipe[0]); close(outpipe[1]); }
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (buf) { close(outpipe[0]); close(outpipe[1]); }
        if (stdin_data) { close(inpipe[0]); close(inpipe[1]); }
        return -1;
    }

    if (pid == 0) {
        /* ---- child ---- */
        if (buf) {
            dup2(outpipe[1], STDOUT_FILENO);
            close(outpipe[0]); close(outpipe[1]);
        }
        if (stdin_data) {
            dup2(inpipe[0], STDIN_FILENO);
            close(inpipe[0]); close(inpipe[1]);
        }
        if (g_quiet && buf) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        }
        execvp(argv[0], argv);
        fprintf(stderr, "pdfunlock: cannot exec %s: %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }

    /* ---- parent ---- */
    if (stdin_data) {
        close(inpipe[0]);
        size_t n = strlen(stdin_data);
        ssize_t off = 0;
        while ((size_t)off < n) {
            ssize_t w = write(inpipe[1], stdin_data + off, n - (size_t)off);
            if (w <= 0) break;
            off += w;
        }
        close(inpipe[1]);
    }

    size_t total = 0;
    if (buf) {
        close(outpipe[1]);
        ssize_t r;
        while (total + 1 < bufsz &&
               (r = read(outpipe[0], buf + total, bufsz - 1 - total)) > 0)
            total += (size_t)r;
        buf[total] = '\0';
        close(outpipe[0]);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

/* ================================================================
 * Parse pdfcrack's captured stdout for a recovered password.
 * Returns 1 and fills pw if found (pw may be empty for owner-locked
 * files with an empty user password), 0 if not found.
 * ================================================================ */
static int parse_password(const char *out, char *pw, size_t pwsz)
{
    /* Prefixes pdfcrack prints on stdout when it succeeds. Order
     * matters: the "(empty)" case must be checked before the generic
     * "Password found: " prefix. */
    static const char *pfx[] = {
        "User password found: ",
        "Owner password found: ",
        "Found in pot file: ",
        NULL
    };

    /* Empty-password (owner-locked) case. */
    if (strstr(out, "Password found: (empty)")) { pw[0] = '\0'; return 1; }

    for (int i = 0; pfx[i]; i++) {
        const char *p = strstr(out, pfx[i]);
        if (!p) continue;
        p += strlen(pfx[i]);
        size_t j = 0;
        while (*p && *p != '\n' && *p != '\r' && j + 1 < pwsz) pw[j++] = *p++;
        pw[j] = '\0';
        return 1;
    }

    /* Generic "Password found: <pw>" fallback. */
    const char *p = strstr(out, "Password found: ");
    if (p) {
        p += strlen("Password found: ");
        size_t j = 0;
        while (*p && *p != '\n' && *p != '\r' && j + 1 < pwsz) pw[j++] = *p++;
        pw[j] = '\0';
        return 1;
    }
    return 0;
}

/* Run one pdfcrack attack pass. extra[] holds the mode-specific args. */
static int crack_pass(const char *pdf, char *pw, size_t pwsz,
                      const char **extra, int n_extra)
{
    char *argv[16];
    int a = 0;
    argv[a++] = (char *)g_pdfcrack;
    argv[a++] = "-f";
    argv[a++] = (char *)pdf;
    for (int i = 0; i < n_extra && a < 14; i++) argv[a++] = (char *)extra[i];
    argv[a] = NULL;

    char out[8192];
    int rc = run_capture(argv, out, sizeof(out), NULL);
    if (rc < 0) {
        fprintf(stderr, "pdfunlock: failed to run pdfcrack (%s)\n", g_pdfcrack);
        return -1;
    }
    return parse_password(out, pw, pwsz) ? 1 : 0;
}

/* Try the staged attack chain until the password is found. */
static int crack(const char *pdf, char *pw, size_t pwsz)
{
    /* Pass 1: fingerprint (also resolves an instant pot-file hit). */
    const char *fp[] = { "--fingerprint" };
    int r = crack_pass(pdf, pw, pwsz, fp, 1);
    if (r != 0) return r;

    /* Pass 2: targeted dictionary with mutations + reversal. */
    if (g_dict) {
        const char *dp[] = { "-d", g_dict, "--mutate", "--reverse" };
        r = crack_pass(pdf, pw, pwsz, dp, 4);
        if (r != 0) return r;
    }

    /* Pass 3: deep multi-phase (slow — only when asked). */
    if (g_deep) {
        if (g_dict) {
            const char *sp[] = { "--smart", "-d", g_dict };
            r = crack_pass(pdf, pw, pwsz, sp, 3);
        } else {
            const char *sp[] = { "--smart" };
            r = crack_pass(pdf, pw, pwsz, sp, 1);
        }
        if (r != 0) return r;
    }
    return 0;
}

/* Write a decrypted copy via qpdf, password fed over stdin. */
static int decrypt(const char *pdf, const char *pw, const char *outpath)
{
    char *argv[] = {
        (char *)g_qpdf, "--decrypt", "--password-file=-",
        (char *)pdf, (char *)outpath, NULL
    };
    /* qpdf reads the first line of stdin as the password (newline stripped). */
    char stdin_data[MAX_PW + 2];
    snprintf(stdin_data, sizeof(stdin_data), "%s\n", pw);
    int rc = run_capture(argv, NULL, 0, stdin_data);
    /* qpdf: 0 = success, 3 = success with warnings. */
    return (rc == 0 || rc == 3) ? 0 : rc;
}

/* Build "<dir>/<base> (decrypted).pdf" for a given input path. */
static void decrypted_name(const char *pdf, char *out, size_t outsz)
{
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", pdf);
    char *slash = strrchr(tmp, '/');
    const char *dir  = g_outdir ? g_outdir : (slash ? tmp : ".");
    char *file = slash ? slash + 1 : tmp;

    if (slash && !g_outdir) *slash = '\0';       /* split dir / file */

    /* strip trailing ".pdf" (case-insensitive) from the base name */
    char base[MAX_PATH];
    snprintf(base, sizeof(base), "%s", file);
    size_t bl = strlen(base);
    if (bl >= 4 && strcasecmp(base + bl - 4, ".pdf") == 0) base[bl - 4] = '\0';

    snprintf(out, outsz, "%s/%s (decrypted).pdf", dir, base);
}

/* Append "<file>\t<password>" (or "(empty)") to the passwords log. */
static void log_password(const char *pdf, const char *pw)
{
    if (!g_logpath) return;
    FILE *f = fopen(g_logpath, "a");
    if (!f) { fprintf(stderr, "pdfunlock: cannot write log %s\n", g_logpath); return; }
    const char *base = strrchr(pdf, '/');
    base = base ? base + 1 : pdf;
    fprintf(f, "%s\t%s\n", base, pw[0] ? pw : "(empty / owner-locked)");
    fclose(f);
}

static int is_encrypted(const char *pdf)
{
    /* qpdf --is-encrypted: exit 0 = encrypted, 2 = not encrypted. */
    char *argv[] = { (char *)g_qpdf, "--is-encrypted", (char *)pdf, NULL };
    return run_capture(argv, NULL, 0, NULL) == 0;
}

/* Process one PDF file end-to-end. Returns 1 on success, 0 otherwise. */
static int process_file(const char *pdf)
{
    const char *base = strrchr(pdf, '/');
    base = base ? base + 1 : pdf;

    /* Never reprocess our own output. */
    size_t l = strlen(base);
    if (l >= 16 && strcasecmp(base + l - 16, " (decrypted).pdf") == 0) return 0;

    if (g_qpdf && !is_encrypted(pdf)) {
        printf("  •  %-50s not encrypted — skipped\n", base);
        return 0;
    }

    printf("  →  %-50s cracking...\n", base);
    fflush(stdout);

    char pw[MAX_PW];
    int found = crack(pdf, pw, sizeof(pw));
    if (found != 1) {
        printf("  ✗  %-50s password NOT found\n", base);
        if (!g_dict && !g_deep)
            printf("       try again with  -d <wordlist>  or  --deep\n");
        return 0;
    }

    log_password(pdf, pw);

    if (g_no_decrypt) {
        printf("  ✓  %-50s password: %s\n", base, pw[0] ? pw : "(empty)");
        return 1;
    }

    char outpath[MAX_PATH];
    decrypted_name(pdf, outpath, sizeof(outpath));
    int drc = decrypt(pdf, pw, outpath);
    if (drc == 0) {
        const char *ob = strrchr(outpath, '/');
        ob = ob ? ob + 1 : outpath;
        printf("  ✓  %-50s password: %-24s -> %s\n",
               base, pw[0] ? pw : "(empty)", ob);
        return 1;
    }
    printf("  ⚠  %-50s cracked (%s) but qpdf decrypt failed (exit %d)\n",
           base, pw[0] ? pw : "(empty)", drc);
    return 0;
}

/* Recursively/flat gather *.pdf paths under a directory. */
static void gather_dir(const char *dir, char targets[][MAX_PATH], int *n)
{
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "pdfunlock: cannot open %s\n", dir); return; }
    struct dirent *e;
    while ((e = readdir(d)) && *n < MAX_TARGETS) {
        if (e->d_name[0] == '.') continue;
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (g_recursive) gather_dir(path, targets, n);
            continue;
        }
        size_t nl = strlen(e->d_name);
        if (nl >= 4 && strcasecmp(e->d_name + nl - 4, ".pdf") == 0)
            snprintf(targets[(*n)++], MAX_PATH, "%s", path);
    }
    closedir(d);
}

static void usage(const char *prog)
{
    printf(
"pdfunlock — recover the password of an encrypted PDF and write a\n"
"           decrypted copy alongside it (uses the pdfcracker engine).\n"
"\n"
"USAGE\n"
"  %s                                    # scan the current directory\n"
"  %s [options] <file-or-directory> [more...]\n"
"\n"
"WHAT IT DOES\n"
"  For each encrypted PDF it recovers the user (open) password, then\n"
"  writes \"<name> (decrypted).pdf\" next to the original (originals are\n"
"  never changed) and appends the password to a log file.\n"
"\n"
"ATTACK STAGES (stops at the first hit)\n"
"  1. pot-file lookup + fingerprint sweep  (fast: common pw, dates, PINs)\n"
"  2. -d <wordlist>  dictionary + mutations + reversal   (if given)\n"
"  3. --deep         full multi-phase --smart attack      (slow; if given)\n"
"\n"
"OPTIONS\n"
"  -d, --dict <file>     targeted wordlist (names, dates, etc.)\n"
"      --deep            also run the slow --smart attack if needed\n"
"  -o, --outdir <dir>    write decrypted copies here (default: beside original)\n"
"  -P, --passwords <f>   password log path (default: <target-dir>/pdfunlock-passwords.txt)\n"
"      --no-decrypt      only recover/print the password, don't write a copy\n"
"  -r, --recursive       descend into sub-directories\n"
"  -q, --quiet           hide pdfcrack's live progress\n"
"      --pdfcrack <path> path to the pdfcrack binary\n"
"      --qpdf <path>     path to the qpdf binary\n"
"  -h, --help            this help\n"
"\n"
"EXAMPLES\n"
"  %s \"Green Card Docs/\"                    # crack + decrypt every PDF in a folder\n"
"  %s -d hints.txt file.pdf                 # try a personal wordlist first\n"
"  %s --deep file.pdf                       # escalate to the full smart attack\n"
"  %s --no-decrypt file.pdf                 # just tell me the password\n"
"\n"
"REQUIREMENTS\n"
"  pdfcrack  — built here with `make` (found next to this binary, on PATH,\n"
"              or via $PDFCRACK / --pdfcrack).\n"
"  qpdf      — for the decrypt step (`brew install qpdf`); not needed with\n"
"              --no-decrypt. Found on PATH or via --qpdf.\n"
"\n"
"NOTES\n"
"  • Passwords already recovered are cached in ~/.pdfcracker/pdfcracker.pot,\n"
"    so re-running is instant.\n"
"  • The password is passed to qpdf over stdin, so it never appears in `ps`.\n",
    prog, prog, prog, prog, prog, prog);
}

/* Resolve the pdfcrack binary: $PDFCRACK, then beside argv[0], then PATH. */
static const char *resolve_pdfcrack(const char *argv0)
{
    const char *env = getenv("PDFCRACK");
    if (env && access(env, X_OK) == 0) return env;

    if (strchr(argv0, '/')) {
        static char guess[MAX_PATH];
        char tmp[MAX_PATH];
        snprintf(tmp, sizeof(tmp), "%s", argv0);
        snprintf(guess, sizeof(guess), "%s/pdfcrack", dirname(tmp));
        if (access(guess, X_OK) == 0) return guess;
    }
    return "pdfcrack";   /* fall back to PATH */
}

int main(int argc, char **argv)
{
    const char *pdfcrack_override = NULL;
    const char *targets_in[MAX_TARGETS];
    int n_in = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "-d") || !strcmp(a, "--dict"))       g_dict   = argv[++i];
        else if (!strcmp(a, "-o") || !strcmp(a, "--outdir"))     g_outdir = argv[++i];
        else if (!strcmp(a, "-P") || !strcmp(a, "--passwords"))  g_logpath = argv[++i];
        else if (!strcmp(a, "--deep"))                           g_deep = 1;
        else if (!strcmp(a, "--no-decrypt"))                     g_no_decrypt = 1;
        else if (!strcmp(a, "-r") || !strcmp(a, "--recursive"))  g_recursive = 1;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet"))      g_quiet = 1;
        else if (!strcmp(a, "--pdfcrack"))                       pdfcrack_override = argv[++i];
        else if (!strcmp(a, "--qpdf"))                           g_qpdf = argv[++i];
        else if (a[0] == '-') {
            fprintf(stderr, "pdfunlock: unknown option '%s' (see --help)\n", a);
            return 2;
        } else if (n_in < MAX_TARGETS) {
            targets_in[n_in++] = a;
        }
    }

    /* No path given → just go: scan the current directory. Running
     * `pdfunlock` on its own should decrypt everything it finds here. */
    if (n_in == 0) {
        targets_in[n_in++] = ".";
        fprintf(stderr,
            "pdfunlock: no path given — scanning the current directory.\n"
            "           (pass files/folders explicitly, add -r to recurse, "
            "or -h for help.)\n\n");
    }

    g_pdfcrack = pdfcrack_override ? pdfcrack_override : resolve_pdfcrack(argv[0]);
    if (!g_qpdf) g_qpdf = "qpdf";

    if (access(g_pdfcrack, X_OK) != 0 && strchr(g_pdfcrack, '/')) {
        fprintf(stderr, "pdfunlock: pdfcrack not found at %s\n", g_pdfcrack);
        fprintf(stderr, "           build it with `make`, or pass --pdfcrack <path>.\n");
        return 3;
    }

    /* Expand targets (files + directories) into a flat PDF list. */
    static char targets[MAX_TARGETS][MAX_PATH];
    int n = 0;
    for (int i = 0; i < n_in && n < MAX_TARGETS; i++) {
        struct stat st;
        if (stat(targets_in[i], &st) != 0) {
            fprintf(stderr, "pdfunlock: no such path: %s\n", targets_in[i]);
            continue;
        }
        if (S_ISDIR(st.st_mode)) gather_dir(targets_in[i], targets, &n);
        else snprintf(targets[n++], MAX_PATH, "%s", targets_in[i]);
    }
    if (n == 0) { fprintf(stderr, "pdfunlock: no PDF files to process.\n"); return 1; }

    /* Default password log: <dir-of-first-target>/pdfunlock-passwords.txt */
    static char logbuf[MAX_PATH];
    if (!g_logpath && !g_no_decrypt) g_logpath = "pdfunlock-passwords.txt";
    if (g_logpath && !strchr(g_logpath, '/')) {
        char first[MAX_PATH];
        snprintf(first, sizeof(first), "%s", targets[0]);
        char *slash = strrchr(first, '/');
        if (slash) { *slash = '\0'; snprintf(logbuf, sizeof(logbuf), "%s/%s", first, g_logpath); }
        else snprintf(logbuf, sizeof(logbuf), "%s", g_logpath);
        g_logpath = logbuf;
    }

    printf("pdfunlock: %d PDF%s to process\n", n, n == 1 ? "" : "s");
    printf("  engine : %s\n", g_pdfcrack);
    if (!g_no_decrypt) printf("  decrypt: %s\n", g_qpdf);
    if (g_logpath)     printf("  log    : %s\n", g_logpath);
    printf("\n");

    int ok = 0;
    for (int i = 0; i < n; i++)
        ok += process_file(targets[i]);

    printf("\npdfunlock: %d/%d unlocked.\n", ok, n);
    if (g_logpath && ok) printf("Passwords saved to: %s\n", g_logpath);
    return ok == n ? 0 : 1;
}
