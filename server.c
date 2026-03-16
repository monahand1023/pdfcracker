/*
 * server.c — Distributed PDF cracker coordinator
 *
 * Loads the PDF (and optional wordlist), listens for clients, distributes
 * work chunks, aggregates progress, and announces when the password is found.
 *
 * Build:
 *   clang -O3 -lpthread -o server server.c
 *
 * Usage:
 *   ./server -f file.pdf -b -l 6                    # brute-force
 *   ./server -f file.pdf -b -l 6 -c 0123456789      # digits only
 *   ./server -f file.pdf -d wordlist.txt             # dictionary
 *   ./server -f file.pdf -b -l 6 -p 8888            # custom port
 */

#include "protocol.h"
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/stat.h>
#include <signal.h>

/* ── PDF bytes (read-only, sent to each client) ───────────────── */
static unsigned char *g_pdf_data = NULL;
static long           g_pdf_size = 0;

/* ── Wordlist (dict mode) ─────────────────────────────────────── */
static char **g_words  = NULL;
static long   g_nwords = 0;

/* ── Mode config ──────────────────────────────────────────────── */
static int   g_brute   = 0;
static int   g_max_len = 4;
static char *g_charset = NULL;
static int   g_cs_len  = 0;

/* ── Work queue (mutex-protected) ─────────────────────────────── */
static pthread_mutex_t g_work_lock = PTHREAD_MUTEX_INITIALIZER;
static int  g_brute_len = 1;   /* current length being distributed */
static long g_brute_idx = 0;   /* next index within current length */
static long g_dict_idx  = 0;   /* next word index */

/* ── Found state ──────────────────────────────────────────────── */
static atomic_int g_found = 0;
static char       g_password[MAX_PASS_LEN + 1] = {0};

/* ── Progress tracking ────────────────────────────────────────── */
static atomic_long g_total_tested = 0;
static long        g_keyspace     = 0;  /* total passwords to test */

/* ── Client tracking ──────────────────────────────────────────── */
typedef struct {
    int  fd;
    int  id;
    int  cores;
    int  active;
    long tested;
} ClientInfo;

static ClientInfo       g_clients[MAX_CLIENTS];
static int              g_nclient_ids = 0;
static pthread_mutex_t  g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

/* ================================================================
 * Load PDF file into memory
 * ================================================================ */
static int load_pdf(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) { perror(path); return 0; }
    g_pdf_size = (long)st.st_size;
    g_pdf_data = malloc((size_t)g_pdf_size);
    if (!g_pdf_data) { perror("malloc"); return 0; }

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 0; }
    if ((long)fread(g_pdf_data, 1, (size_t)g_pdf_size, f) != g_pdf_size) {
        perror("fread"); fclose(f); return 0;
    }
    fclose(f);
    return 1;
}

/* ================================================================
 * Load wordlist
 * ================================================================ */
static int load_wordlist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    long n = 0;
    int c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') n++;
    rewind(f);

    g_words = malloc((size_t)(n + 1) * sizeof(char *));
    if (!g_words) { fclose(f); return 0; }

    char line[MAX_PASS_LEN + 4];
    long idx = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (!len) continue;
        if ((g_words[idx] = malloc(len + 1)))
            memcpy(g_words[idx++], line, len + 1);
    }
    g_nwords = idx;
    fclose(f);
    return 1;
}

/* ================================================================
 * Get next work chunk (caller holds g_work_lock)
 * Returns: 1 = got chunk, 0 = no more work
 *
 * For brute: sets *out_len, *out_start, *out_end
 * For dict:  sets *out_start (word offset), *out_count
 * ================================================================ */
static int next_brute_chunk(int *out_len, long *out_start, long *out_end)
{
    while (g_brute_len <= g_max_len) {
        long ks = keyspace_for_length(g_brute_len, g_cs_len);
        if (g_brute_idx < ks) {
            *out_len   = g_brute_len;
            *out_start = g_brute_idx;
            *out_end   = g_brute_idx + CHUNK_BRUTE;
            if (*out_end > ks) *out_end = ks;
            g_brute_idx = *out_end;
            return 1;
        }
        g_brute_len++;
        g_brute_idx = 0;
    }
    return 0;
}

static int next_dict_chunk(long *out_start, long *out_count)
{
    if (g_dict_idx >= g_nwords) return 0;
    *out_start = g_dict_idx;
    *out_count = CHUNK_DICT;
    if (*out_start + *out_count > g_nwords)
        *out_count = g_nwords - *out_start;
    g_dict_idx += *out_count;
    return 1;
}

/* ================================================================
 * Client handler thread
 * ================================================================ */
static void *client_handler(void *arg)
{
    ClientInfo *ci = (ClientInfo *)arg;
    int fd = ci->fd;
    int id = ci->id;
    char line[MAX_LINE];

    /* ── Handshake: expect HELLO <ncores> ──────────────────────── */
    if (sock_readline(fd, line, sizeof(line)) < 0) goto done;
    int ncores = 0;
    if (sscanf(line, "HELLO %d", &ncores) != 1 || ncores < 1) {
        fprintf(stderr, "[client %d] bad handshake: %s\n", id, line);
        goto done;
    }
    ci->cores = ncores;
    fprintf(stderr, "[client %d] connected, %d cores\n", id, ncores);

    /* ── Send config ───────────────────────────────────────────── */
    if (g_brute) {
        sock_printf(fd, "CONFIG BRUTE %d", g_max_len);
        sock_printf(fd, "CHARSET %s", g_charset);
    } else {
        sock_printf(fd, "CONFIG DICT");
    }

    /* ── Send PDF ──────────────────────────────────────────────── */
    sock_printf(fd, "PDF %ld", g_pdf_size);
    if (write_exact(fd, g_pdf_data, (size_t)g_pdf_size) < 0) {
        fprintf(stderr, "[client %d] failed sending PDF\n", id);
        goto done;
    }

    /* ── Wait for READY ────────────────────────────────────────── */
    if (sock_readline(fd, line, sizeof(line)) < 0) goto done;
    if (strcmp(line, "READY") != 0) {
        fprintf(stderr, "[client %d] expected READY, got: %s\n", id, line);
        goto done;
    }
    fprintf(stderr, "[client %d] ready for work\n", id);

    /* ── Work loop ─────────────────────────────────────────────── */
    while (sock_readline(fd, line, sizeof(line)) >= 0) {
        if (atomic_load(&g_found)) {
            sock_printf(fd, "FOUND %s", g_password);
            break;
        }

        /* ── GETWORK <tested> ─────────────────────────────────── */
        if (strncmp(line, "GETWORK", 7) == 0) {
            long tested = 0;
            sscanf(line, "GETWORK %ld", &tested);
            if (tested > 0) {
                atomic_fetch_add(&g_total_tested, tested);
                ci->tested += tested;
            }

            if (atomic_load(&g_found)) {
                sock_printf(fd, "FOUND %s", g_password);
                break;
            }

            pthread_mutex_lock(&g_work_lock);
            if (g_brute) {
                int len; long start, end;
                if (next_brute_chunk(&len, &start, &end)) {
                    pthread_mutex_unlock(&g_work_lock);
                    sock_printf(fd, "BRUTE %d %ld %ld", len, start, end);
                } else {
                    pthread_mutex_unlock(&g_work_lock);
                    sock_printf(fd, "DONE");
                    break;
                }
            } else {
                long start, count;
                if (next_dict_chunk(&start, &count)) {
                    pthread_mutex_unlock(&g_work_lock);
                    /* Send DICT header + words */
                    sock_printf(fd, "DICT %ld", count);
                    for (long i = start; i < start + count; i++)
                        sock_printf(fd, "%s", g_words[i]);
                } else {
                    pthread_mutex_unlock(&g_work_lock);
                    sock_printf(fd, "DONE");
                    break;
                }
            }
        }

        /* ── FOUND <password> ─────────────────────────────────── */
        else if (strncmp(line, "FOUND ", 6) == 0) {
            if (!atomic_exchange(&g_found, 1)) {
                strncpy(g_password, line + 6, MAX_PASS_LEN);
                fprintf(stderr,
                    "\n\n  *** PASSWORD FOUND by client %d: %s ***\n\n",
                    id, g_password);
            }
            sock_printf(fd, "OK");
            break;
        }

        /* ── EXHAUSTED ────────────────────────────────────────── */
        else if (strcmp(line, "EXHAUSTED") == 0) {
            /* chunk done, client will send GETWORK next */
        }
    }

done:
    fprintf(stderr, "[client %d] disconnected (tested %ld passwords)\n",
            id, ci->tested);

    pthread_mutex_lock(&g_clients_lock);
    ci->active = 0;
    pthread_mutex_unlock(&g_clients_lock);

    close(fd);
    return NULL;
}

/* ================================================================
 * Progress display thread
 * ================================================================ */
static void print_bar(double pct)
{
    int w = 35;
    int filled = (int)(pct / 100.0 * w);
    fputc('[', stderr);
    for (int i = 0; i < w; i++) fputc(i < filled ? '#' : '.', stderr);
    fputc(']', stderr);
}

static void *progress_thread(void *arg)
{
    (void)arg;
    long   prev = 0;
    time_t t0   = time(NULL);

    while (!atomic_load(&g_found)) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);

        long cur     = atomic_load(&g_total_tested);
        long rate    = cur - prev;
        prev         = cur;
        long elapsed = (long)(time(NULL) - t0);

        /* Count active clients */
        int nactive = 0;
        pthread_mutex_lock(&g_clients_lock);
        for (int i = 0; i < g_nclient_ids; i++)
            if (g_clients[i].active) nactive++;
        pthread_mutex_unlock(&g_clients_lock);

        fputs("\r  ", stderr);

        if (g_keyspace > 0) {
            double pct = (double)cur / (double)g_keyspace * 100.0;
            if (pct > 100.0) pct = 100.0;
            print_bar(pct);

            long eta = -1;
            if (rate > 0 && g_keyspace > cur)
                eta = (g_keyspace - cur) / rate;

            fprintf(stderr,
                " %5.1f%%  clients: %d  tested: %ld  %ld/s  elapsed: %lds",
                pct, nactive, cur, rate, elapsed);
            if (eta >= 0) {
                if (eta > 3600)
                    fprintf(stderr, "  ETA: %ldh%02ldm", eta/3600, (eta%3600)/60);
                else if (eta > 60)
                    fprintf(stderr, "  ETA: %ldm%02lds", eta/60, eta%60);
                else
                    fprintf(stderr, "  ETA: %lds", eta);
            }
            fputs("   ", stderr);
        } else {
            fprintf(stderr,
                "clients: %d  tested: %ld  %ld/s  elapsed: %lds   ",
                nactive, cur, rate, elapsed);
        }
        fflush(stderr);
    }
    return NULL;
}

/* ================================================================
 * Usage
 * ================================================================ */
static void usage(const char *p)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s -f <pdf> -d <wordlist> [-p <port>]             dictionary\n"
        "  %s -f <pdf> -b [-l <maxlen>] [-c <charset>] [-p <port>]  brute-force\n"
        "\nClients connect and receive work chunks automatically.\n",
        p, p);
    exit(1);
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    const char *pdf_path  = NULL;
    const char *dict_path = NULL;
    const char *charset   = DEFAULT_CHARSET;
    int         brute     = 0;
    int         max_len   = 4;
    int         port      = DEFAULT_PORT;

    int opt;
    while ((opt = getopt(argc, argv, "f:d:bl:c:p:")) != -1) {
        switch (opt) {
            case 'f': pdf_path  = optarg;       break;
            case 'd': dict_path = optarg;       break;
            case 'b': brute     = 1;            break;
            case 'l': max_len   = atoi(optarg); break;
            case 'c': charset   = optarg;       break;
            case 'p': port      = atoi(optarg); break;
            default:  usage(argv[0]);
        }
    }

    if (!pdf_path)            { fprintf(stderr, "-f required\n");       usage(argv[0]); }
    if (!brute && !dict_path) { fprintf(stderr, "-d or -b required\n"); usage(argv[0]); }

    /* ── Load PDF ──────────────────────────────────────────────── */
    if (!load_pdf(pdf_path)) return 1;
    fprintf(stderr, "PDF loaded: %s (%ld bytes)\n", pdf_path, g_pdf_size);

    /* ── Setup mode ────────────────────────────────────────────── */
    g_brute   = brute;
    g_max_len = max_len;
    g_charset = strdup(charset);
    g_cs_len  = (int)strlen(charset);

    if (brute) {
        g_keyspace = total_keyspace(max_len, g_cs_len);
        fprintf(stderr, "Mode   : brute-force (len 1..%d, charset \"%s\")\n",
                max_len, charset);
        fprintf(stderr, "Keyspace: %ld passwords\n", g_keyspace);
    } else {
        if (!load_wordlist(dict_path)) return 1;
        g_keyspace = g_nwords;
        fprintf(stderr, "Mode   : dictionary (%ld words from %s)\n",
                g_nwords, dict_path);
    }

    /* ── Start progress thread ─────────────────────────────────── */
    pthread_t prog;
    pthread_create(&prog, NULL, progress_thread, NULL);

    /* ── Create listening socket ───────────────────────────────── */
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("socket"); return 1; }

    int yes = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(listenfd, 16) < 0) { perror("listen"); return 1; }

    fprintf(stderr, "\nListening on port %d — waiting for clients...\n\n", port);

    /* ── Accept loop ───────────────────────────────────────────── */
    while (!atomic_load(&g_found)) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int fd = accept(listenfd, (struct sockaddr *)&cli_addr, &cli_len);
        if (fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        /* Disable Nagle for snappy protocol exchange */
        int flag = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        pthread_mutex_lock(&g_clients_lock);
        if (g_nclient_ids >= MAX_CLIENTS) {
            pthread_mutex_unlock(&g_clients_lock);
            fprintf(stderr, "Max clients reached, rejecting\n");
            close(fd);
            continue;
        }
        int cid = g_nclient_ids++;
        g_clients[cid] = (ClientInfo){
            .fd     = fd,
            .id     = cid,
            .cores  = 0,
            .active = 1,
            .tested = 0,
        };
        pthread_mutex_unlock(&g_clients_lock);

        pthread_t th;
        pthread_create(&th, NULL, client_handler, &g_clients[cid]);
        pthread_detach(th);
    }

    /* ── Done ──────────────────────────────────────────────────── */
    /* Give progress thread a moment to print final state */
    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);
    atomic_store(&g_found, 1);
    pthread_join(prog, NULL);

    fputs("\n\n", stderr);
    if (g_password[0]) {
        printf("Password found: %s\n", g_password);
        printf("Total tested:   %ld\n", atomic_load(&g_total_tested));
    } else {
        printf("Password not found.\n");
    }

    close(listenfd);
    return g_password[0] ? 0 : 1;
}
