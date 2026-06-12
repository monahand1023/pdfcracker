/*
 * server.c — Distributed PDF cracker coordinator (v2, lease-based)
 *
 * BOINC-style lease system: work chunks are assigned with deadlines,
 * expired leases are re-queued, clients can reconnect via UUID.
 *
 * Build:
 *   clang -O3 -Wall -lpthread -o server server.c
 *
 * Usage:
 *   ./server -f file.pdf -b -l 6                         # brute-force
 *   ./server -f file.pdf -b -l 6 -c 0123456789           # digits only
 *   ./server -f file.pdf -d wordlist.txt                  # dictionary
 *   ./server -f file.pdf -b -l 6 -p 8888                 # custom port
 *   ./server -f file.pdf -b -l 6 -R file.server.ckpt     # restore
 */

#include "protocol.h"
#include "pdf_encrypt.h"
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include <libgen.h>
#include <dns_sd.h>

/* Named constant for the lease-recheck nanosleep interval (~200 ms) */
#define LEASE_RECHECK_NS 200000000

/* ================================================================
 * Data Structures
 * ================================================================ */

typedef struct {
    uint64_t  lease_id;
    int       is_brute;
    int       brute_len;
    long      brute_start, brute_end;
    long      dict_start, dict_count;
    double    deadline;          /* monotonic time */
    int       client_idx;
    long      tested_so_far;
    double    last_heartbeat;    /* monotonic time */
    int       active;            /* 1=assigned, 0=completed/expired */
} LeaseEntry;

typedef struct RequeueNode {
    int       is_brute;
    int       brute_len;
    long      brute_start, brute_end;
    long      dict_start, dict_count;
    struct RequeueNode *next;
} RequeueNode;

typedef struct {
    int       fd;
    int       id;
    int       cores;
    int       active;            /* 1=connected, 0=disconnected */
    int       slot_free;         /* 1=slot can be reused by new client */
    long      tested;            /* cumulative across reconnections */
    char      uuid[UUID_LEN + 1];
    char      ip_str[INET_ADDRSTRLEN];
    double    speed;             /* passwords/sec */
    long      chunk_size;        /* adaptive next chunk size */
    uint64_t  current_lease_id;
    double    last_seen;         /* monotonic time of last message */
} ClientInfo;

/* ================================================================
 * Globals
 * ================================================================ */

/* PDF bytes (read-only, sent to each client) */
static unsigned char *g_pdf_data = NULL;
static long           g_pdf_size = 0;
static PDFEncryptParams g_srv_enc;   /* parsed once for FOUND re-verification */

/* Wordlist (dict mode) */
static char **g_words     = NULL;
static long   g_nwords    = 0;
static char  *g_dict_path = NULL;  /* kept for hashing */

/* Mode config */
static int   g_brute   = 0;
static int   g_max_len = 4;
static char *g_charset = NULL;
static int   g_cs_len  = 0;
static int   g_password_mode = PW_MODE_BOTH;

/* Extended attack mode tracking (for checkpoint v2) */
#define ATTACK_BRUTE   0
#define ATTACK_DICT    1
#define ATTACK_MASK    2
#define ATTACK_RULE    3
#define ATTACK_HYBRID  4
#define ATTACK_AUTO    5
static int   g_attack_mode       = ATTACK_BRUTE;
static int   g_auto_phase        = 0;
static char  g_mask_pattern[256] = {0};
static int   g_hybrid_suffix_len = 0;
static int   g_freq_mode         = 0;
static int   g_pdf_revision      = 0;  /* PDF encryption revision (0=unknown, 6=R6) */

/* Work cursor (protected by g_work_lock) */
static pthread_mutex_t g_work_lock = PTHREAD_MUTEX_INITIALIZER;
static int  g_brute_len = 1;
static long g_brute_idx = 0;
static long g_dict_idx  = 0;

/* Requeue list (protected by g_work_lock) */
static RequeueNode *g_requeue_head = NULL;

/* Lease ring buffer (protected by g_lease_lock) */
#define MAX_LEASES 4096
static pthread_mutex_t g_lease_lock = PTHREAD_MUTEX_INITIALIZER;
static LeaseEntry      g_leases[MAX_LEASES];
static int             g_lease_count    = 0;
static uint64_t        g_next_lease_id  = 1;

/* Found state */
static atomic_int g_found = 0;
static char       g_password[MAX_PASS_LEN + 1] = {0};

/* Progress tracking */
static atomic_long g_total_tested = 0;
static long        g_keyspace     = 0;

/* SHA-256 hashes */
static char g_pdf_sha256[SHA256_HEX_LEN + 1]      = {0};
static char g_wordlist_sha256[SHA256_HEX_LEN + 1]  = {0};

/* Client tracking */
static ClientInfo       g_clients[MAX_CLIENTS];
static int              g_nclient_ids = 0;
static pthread_mutex_t  g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

/* Shutdown */
static volatile int g_shutdown = 0;

/* PDF path (for checkpoint naming) */
static const char *g_pdf_path = NULL;

/* Listen fd (for shutdown) */
static int g_listenfd = -1;

/* Web dashboard port (0 = disabled) */
static int g_web_port = 0;

/* Server binary directory (for serving files over HTTP) */
static char g_server_dir[PATH_MAX] = ".";

/* Optional HTTP auth token */
static char g_auth_token[256] = {0};

/* Start time (monotonic, for elapsed calculation) */
static double g_start_time = 0;

/* Bonjour service reference */
static DNSServiceRef g_mdns_ref = NULL;

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
    g_srv_enc = pdf_parse_encrypt(g_pdf_data, (size_t)g_pdf_size);
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
        if (len > MAX_PASS_LEN) {
            fprintf(stderr, "warning: skipping word longer than %d chars\n",
                    MAX_PASS_LEN);
            continue;
        }
        if ((g_words[idx] = malloc(len + 1)))
            memcpy(g_words[idx++], line, len + 1);
    }
    g_nwords = idx;
    fclose(f);
    return 1;
}

/* ================================================================
 * Hashing
 * ================================================================ */
static void compute_pdf_hash(void)
{
    sha256_hex(g_pdf_data, (size_t)g_pdf_size, g_pdf_sha256);
}

static void compute_wordlist_hash(void)
{
    if (!g_dict_path) { g_wordlist_sha256[0] = '\0'; return; }

    struct stat st;
    if (stat(g_dict_path, &st) != 0) { g_wordlist_sha256[0] = '\0'; return; }

    size_t sz = (size_t)st.st_size;
    unsigned char *buf = malloc(sz);
    if (!buf) { g_wordlist_sha256[0] = '\0'; return; }

    FILE *f = fopen(g_dict_path, "rb");
    if (!f) { free(buf); g_wordlist_sha256[0] = '\0'; return; }
    if (fread(buf, 1, sz, f) != sz) {
        fclose(f); free(buf); g_wordlist_sha256[0] = '\0'; return;
    }
    fclose(f);

    sha256_hex(buf, sz, g_wordlist_sha256);
    free(buf);
}

/* ================================================================
 * Requeue management (caller holds g_work_lock)
 * ================================================================ */
static void push_requeue_brute(int len, long start, long end)
{
    RequeueNode *n = malloc(sizeof(RequeueNode));
    if (!n) return;
    n->is_brute    = 1;
    n->brute_len   = len;
    n->brute_start = start;
    n->brute_end   = end;
    n->dict_start  = 0;
    n->dict_count  = 0;
    n->next        = g_requeue_head;
    g_requeue_head = n;
}

static void push_requeue_dict(long start, long count)
{
    RequeueNode *n = malloc(sizeof(RequeueNode));
    if (!n) return;
    n->is_brute    = 0;
    n->brute_len   = 0;
    n->brute_start = 0;
    n->brute_end   = 0;
    n->dict_start  = start;
    n->dict_count  = count;
    n->next        = g_requeue_head;
    g_requeue_head = n;
}

static int pop_requeue(int *is_brute, int *brute_len,
                       long *start, long *end, long *dict_count)
{
    if (!g_requeue_head) return 0;
    RequeueNode *n = g_requeue_head;
    g_requeue_head = n->next;
    *is_brute  = n->is_brute;
    *brute_len = n->brute_len;
    if (n->is_brute) {
        *start      = n->brute_start;
        *end        = n->brute_end;
        *dict_count = 0;
    } else {
        *start      = n->dict_start;
        *end        = 0;
        *dict_count = n->dict_count;
    }
    free(n);
    return 1;
}

/* Forward declaration (needed because create_lease may call expire_lease) */
static void expire_lease(uint64_t lease_id);

/* ================================================================
 * Lease management (caller holds g_lease_lock)
 * ================================================================ */
static uint64_t create_lease(int client_idx, int is_brute,
                             int brute_len, long start, long end,
                             long dict_start, long dict_count,
                             int deadline_secs)
{
    int slot = g_lease_count % MAX_LEASES;
    uint64_t lid = g_next_lease_id++;

    /* If slot holds an active lease, expire it first to requeue its work */
    if (g_lease_count >= MAX_LEASES && g_leases[slot].active) {
        expire_lease(g_leases[slot].lease_id);
    }

    g_leases[slot] = (LeaseEntry){
        .lease_id       = lid,
        .is_brute       = is_brute,
        .brute_len      = brute_len,
        .brute_start    = start,
        .brute_end      = end,
        .dict_start     = dict_start,
        .dict_count     = dict_count,
        .deadline       = mono_time() + deadline_secs,
        .client_idx     = client_idx,
        .tested_so_far  = 0,
        .last_heartbeat = mono_time(),
        .active         = 1,
    };
    g_lease_count++;
    return lid;
}

/* Find lease slot by ID. Returns index or -1. Caller holds g_lease_lock. */
static int find_lease(uint64_t lease_id)
{
    /* Search backwards from newest — most likely to find recent leases */
    int count = g_lease_count < MAX_LEASES ? g_lease_count : MAX_LEASES;
    for (int i = 0; i < count; i++) {
        int slot = ((g_lease_count - 1 - i) % MAX_LEASES + MAX_LEASES) % MAX_LEASES;
        if (g_leases[slot].lease_id == lease_id)
            return slot;
    }
    return -1;
}

static void complete_lease(uint64_t lease_id, long final_tested)
{
    int slot = find_lease(lease_id);
    if (slot < 0) return;

    LeaseEntry *le = &g_leases[slot];
    le->active = 0;
    le->tested_so_far = final_tested;

    /* Remove matching chunk from requeue list (race: reaper may have expired it) */
    pthread_mutex_lock(&g_work_lock);
    RequeueNode **pp = &g_requeue_head;
    while (*pp) {
        RequeueNode *n = *pp;
        int match = 0;
        if (le->is_brute && n->is_brute &&
            n->brute_len == le->brute_len &&
            n->brute_start == le->brute_start &&
            n->brute_end == le->brute_end) {
            match = 1;
        } else if (!le->is_brute && !n->is_brute &&
                   n->dict_start == le->dict_start &&
                   n->dict_count == le->dict_count) {
            match = 1;
        }
        if (match) {
            *pp = n->next;
            free(n);
            break;
        }
        pp = &n->next;
    }
    pthread_mutex_unlock(&g_work_lock);
}

static void expire_lease(uint64_t lease_id)
{
    int slot = find_lease(lease_id);
    if (slot < 0) return;

    LeaseEntry *le = &g_leases[slot];
    if (!le->active) return;
    le->active = 0;

    /* Push chunk back to requeue */
    pthread_mutex_lock(&g_work_lock);
    if (le->is_brute) {
        push_requeue_brute(le->brute_len, le->brute_start, le->brute_end);
    } else {
        push_requeue_dict(le->dict_start, le->dict_count);
    }
    pthread_mutex_unlock(&g_work_lock);
}

/* ================================================================
 * Work chunk generation (caller holds g_work_lock)
 * ================================================================ */
static int next_brute_chunk(long chunk_size, int *out_len,
                            long *out_start, long *out_end)
{
    if (chunk_size <= 0) chunk_size = DEFAULT_CHUNK_BRUTE;
    while (g_brute_len <= g_max_len) {
        long ks = keyspace_for_length(g_brute_len, g_cs_len);
        if (g_brute_idx < ks) {
            *out_len   = g_brute_len;
            *out_start = g_brute_idx;
            *out_end   = g_brute_idx + chunk_size;
            if (*out_end > ks) *out_end = ks;
            g_brute_idx = *out_end;
            return 1;
        }
        g_brute_len++;
        g_brute_idx = 0;
    }
    return 0;
}

static int next_dict_chunk(long chunk_size, long *out_start, long *out_count)
{
    if (chunk_size <= 0) chunk_size = DEFAULT_CHUNK_DICT;
    if (g_dict_idx >= g_nwords) return 0;
    *out_start = g_dict_idx;
    *out_count = chunk_size;
    if (*out_start + *out_count > g_nwords)
        *out_count = g_nwords - *out_start;
    g_dict_idx += *out_count;
    return 1;
}

/* ================================================================
 * Work assignment
 * ================================================================ */
static uint64_t assign_work(ClientInfo *ci, int *is_brute,
                            int *out_len, long *out_start, long *out_end,
                            long *out_dict_start, long *out_dict_count,
                            int deadline_secs)
{
    int got = 0;
    int rq_brute = 0, rq_len = 0;
    long rq_start = 0, rq_end = 0, rq_dict_count = 0;

    pthread_mutex_lock(&g_work_lock);

    /* Try requeue first */
    if (pop_requeue(&rq_brute, &rq_len, &rq_start, &rq_end, &rq_dict_count)) {
        *is_brute = rq_brute;
        if (rq_brute) {
            *out_len   = rq_len;
            *out_start = rq_start;
            *out_end   = rq_end;
            *out_dict_start = 0;
            *out_dict_count = 0;
        } else {
            *out_len        = 0;
            *out_start      = 0;
            *out_end        = 0;
            *out_dict_start = rq_start;
            *out_dict_count = rq_dict_count;
        }
        got = 1;
    } else {
        /* Generate new chunk from cursor */
        long csz = ci->chunk_size;
        if (g_brute) {
            /* R6-aware defaults: smaller chunks for slow-per-password R6 */
            if (g_pdf_revision == 6) {
                if (csz <= 0) csz = DEFAULT_CHUNK_BRUTE_R6;
                if (csz < MIN_CHUNK_BRUTE_R6) csz = MIN_CHUNK_BRUTE_R6;
                if (csz > MAX_CHUNK_BRUTE_R6) csz = MAX_CHUNK_BRUTE_R6;
            } else {
                if (csz <= 0) csz = DEFAULT_CHUNK_BRUTE;
                if (csz < MIN_CHUNK_BRUTE) csz = MIN_CHUNK_BRUTE;
                if (csz > MAX_CHUNK_BRUTE) csz = MAX_CHUNK_BRUTE;
            }
            int len;
            long start, end;
            if (next_brute_chunk(csz, &len, &start, &end)) {
                *is_brute       = 1;
                *out_len        = len;
                *out_start      = start;
                *out_end        = end;
                *out_dict_start = 0;
                *out_dict_count = 0;
                got = 1;
            }
        } else {
            if (csz <= 0) csz = DEFAULT_CHUNK_DICT;
            if (csz < MIN_CHUNK_DICT) csz = MIN_CHUNK_DICT;
            if (csz > MAX_CHUNK_DICT) csz = MAX_CHUNK_DICT;
            long start, count;
            if (next_dict_chunk(csz, &start, &count)) {
                *is_brute       = 0;
                *out_len        = 0;
                *out_start      = 0;
                *out_end        = 0;
                *out_dict_start = start;
                *out_dict_count = count;
                got = 1;
            }
        }
    }

    pthread_mutex_unlock(&g_work_lock);

    if (!got) return 0;

    /* Create lease */
    pthread_mutex_lock(&g_lease_lock);
    uint64_t lid;
    if (*is_brute) {
        lid = create_lease(ci->id, 1, *out_len, *out_start, *out_end,
                           0, 0, deadline_secs);
    } else {
        lid = create_lease(ci->id, 0, 0, 0, 0,
                           *out_dict_start, *out_dict_count, deadline_secs);
    }
    pthread_mutex_unlock(&g_lease_lock);

    ci->current_lease_id = lid;
    return lid;
}

/* ================================================================
 * Client management
 * ================================================================ */
static int alloc_client_slot(void)
{
    /* Scan for free slot */
    for (int i = 0; i < g_nclient_ids; i++) {
        if (g_clients[i].slot_free) {
            g_clients[i].slot_free = 0;
            return i;
        }
    }
    /* Append if room */
    if (g_nclient_ids >= MAX_CLIENTS) return -1;
    int idx = g_nclient_ids++;
    memset(&g_clients[idx], 0, sizeof(ClientInfo));
    g_clients[idx].id = idx;
    return idx;
}

static int find_client_by_uuid(const char *uuid)
{
    for (int i = 0; i < g_nclient_ids; i++) {
        if (!g_clients[i].slot_free && strcmp(g_clients[i].uuid, uuid) == 0)
            return i;
    }
    return -1;
}

/* ================================================================
 * Client handler thread
 * ================================================================ */
/* ================================================================
 * HTTP bootstrap — serve client binary on the same port
 * ================================================================ */

static void http_serve_file(int fd, const char *path, const char *content_type)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        dprintf(fd, "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    dprintf(fd, "HTTP/1.0 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %ld\r\n"
                "\r\n", content_type, sz);

    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        write(fd, buf, n);
    }
    fclose(fp);
}

/* ================================================================
 * JSON API endpoint — /api/status
 * ================================================================ */
static void http_serve_api_status(int fd)
{
    double now = mono_time();
    long tested = atomic_load(&g_total_tested);
    int found = atomic_load(&g_found);
    long elapsed = (long)(now - g_start_time);

    /* Sum per-client speeds */
    double total_speed = 0;
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < g_nclient_ids; i++) {
        if (g_clients[i].active)
            total_speed += g_clients[i].speed;
    }

    /* ETA */
    long eta_secs = -1;
    long speed = (long)total_speed;
    if (speed > 0 && g_keyspace > tested)
        eta_secs = (g_keyspace - tested) / speed;

    double pct = 0;
    if (g_keyspace > 0)
        pct = (double)tested / (double)g_keyspace * 100.0;
    if (pct > 100.0) pct = 100.0;

    /* Build JSON in a buffer */
    char body[8192];
    int off = 0;
    off += snprintf(body + off, sizeof(body) - (size_t)off,
        "{\"progress_pct\":%.4f,\"tested\":%ld,\"speed\":%ld,"
        "\"eta_secs\":%ld,\"keyspace\":%ld,\"elapsed\":%ld,"
        "\"found\":%d,\"password\":\"%s\",\"clients\":[",
        pct, tested, speed, eta_secs, g_keyspace, elapsed,
        found, found ? g_password : "");

    for (int i = 0; i < g_nclient_ids; i++) {
        ClientInfo *ci = &g_clients[i];
        if (ci->slot_free) continue;
        int ago = ci->active ? (int)(now - ci->last_seen) : -1;
        if (off > 0 && body[off - 1] == '}') {
            off += snprintf(body + off, sizeof(body) - (size_t)off, ",");
        }
        off += snprintf(body + off, sizeof(body) - (size_t)off,
            "{\"id\":%d,\"ip\":\"%s\",\"cores\":%d,\"speed\":%ld,"
            "\"tested\":%ld,\"last_seen_ago\":%d,\"lease_id\":%llu,\"active\":%d}",
            ci->id, ci->ip_str, ci->cores, (long)ci->speed,
            ci->tested, ago,
            (unsigned long long)ci->current_lease_id,
            ci->active);
    }
    pthread_mutex_unlock(&g_clients_lock);

    off += snprintf(body + off, sizeof(body) - (size_t)off, "]}");

    dprintf(fd, "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %d\r\n"
                "\r\n%s", off, body);
}

/* ================================================================
 * Web dashboard — /
 * ================================================================ */
static void http_serve_dashboard(int fd)
{
    static const char html[] =
        "<!DOCTYPE html>\n"
        "<html><head><meta charset=\"utf-8\">\n"
        "<title>pdfcracker dashboard</title>\n"
        "<style>\n"
        "  * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;\n"
        "         background: #0d1117; color: #c9d1d9; padding: 24px; }\n"
        "  h1 { font-size: 1.4em; margin-bottom: 16px; color: #58a6ff; }\n"
        "  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;\n"
        "          padding: 16px; margin-bottom: 16px; }\n"
        "  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr)); gap: 12px; }\n"
        "  .stat-label { font-size: 0.75em; color: #8b949e; text-transform: uppercase; }\n"
        "  .stat-value { font-size: 1.5em; font-weight: 600; color: #f0f6fc; }\n"
        "  .bar-bg { background: #21262d; border-radius: 4px; height: 20px; margin: 12px 0; overflow: hidden; }\n"
        "  .bar-fg { background: #238636; height: 100%; border-radius: 4px; transition: width 0.5s; }\n"
        "  table { width: 100%; border-collapse: collapse; font-size: 0.9em; }\n"
        "  th { text-align: left; color: #8b949e; font-weight: 500; padding: 8px 12px;\n"
        "       border-bottom: 1px solid #30363d; }\n"
        "  td { padding: 8px 12px; border-bottom: 1px solid #21262d; }\n"
        "  tr:hover td { background: #1c2128; }\n"
        "  .online { color: #3fb950; }\n"
        "  .offline { color: #f85149; }\n"
        "  .found { background: #238636; color: #fff; padding: 8px 16px; border-radius: 6px;\n"
        "           font-size: 1.2em; font-weight: 700; display: none; text-align: center; }\n"
        "</style>\n"
        "</head><body>\n"
        "<h1>pdfcracker dashboard</h1>\n"
        "<div id=\"found\" class=\"found\"></div>\n"
        "<div class=\"card\">\n"
        "  <div class=\"bar-bg\"><div id=\"bar\" class=\"bar-fg\" style=\"width:0%\"></div></div>\n"
        "  <div class=\"stats\">\n"
        "    <div><div class=\"stat-label\">Progress</div><div class=\"stat-value\" id=\"pct\">--</div></div>\n"
        "    <div><div class=\"stat-label\">Tested</div><div class=\"stat-value\" id=\"tested\">--</div></div>\n"
        "    <div><div class=\"stat-label\">Speed</div><div class=\"stat-value\" id=\"speed\">--</div></div>\n"
        "    <div><div class=\"stat-label\">ETA</div><div class=\"stat-value\" id=\"eta\">--</div></div>\n"
        "    <div><div class=\"stat-label\">Elapsed</div><div class=\"stat-value\" id=\"elapsed\">--</div></div>\n"
        "    <div><div class=\"stat-label\">Keyspace</div><div class=\"stat-value\" id=\"keyspace\">--</div></div>\n"
        "  </div>\n"
        "</div>\n"
        "<div class=\"card\">\n"
        "  <table><thead><tr>\n"
        "    <th>ID</th><th>IP</th><th>Cores</th><th>Speed</th>\n"
        "    <th>Lease</th><th>Tested</th><th>Last Seen</th><th>Status</th>\n"
        "  </tr></thead><tbody id=\"clients\"></tbody></table>\n"
        "</div>\n"
        "<script>\n"
        "function fmt(n) {\n"
        "  if (n >= 1e9) return (n/1e9).toFixed(1)+'G';\n"
        "  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';\n"
        "  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';\n"
        "  return n.toString();\n"
        "}\n"
        "function ftime(s) {\n"
        "  if (s < 0) return '---';\n"
        "  if (s >= 3600) return Math.floor(s/3600)+'h'+String(Math.floor(s%3600/60)).padStart(2,'0')+'m';\n"
        "  if (s >= 60) return Math.floor(s/60)+'m'+String(Math.floor(s%60)).padStart(2,'0')+'s';\n"
        "  return Math.floor(s)+'s';\n"
        "}\n"
        "async function refresh() {\n"
        "  try {\n"
        "    const r = await fetch('/api/status');\n"
        "    const d = await r.json();\n"
        "    document.getElementById('pct').textContent = d.progress_pct.toFixed(2)+'%';\n"
        "    document.getElementById('bar').style.width = Math.min(d.progress_pct,100)+'%';\n"
        "    document.getElementById('tested').textContent = fmt(d.tested);\n"
        "    document.getElementById('speed').textContent = fmt(d.speed)+'/s';\n"
        "    document.getElementById('eta').textContent = ftime(d.eta_secs);\n"
        "    document.getElementById('elapsed').textContent = ftime(d.elapsed);\n"
        "    document.getElementById('keyspace').textContent = fmt(d.keyspace);\n"
        "    if (d.found) {\n"
        "      var el = document.getElementById('found');\n"
        "      el.textContent = 'PASSWORD FOUND: ' + d.password;\n"
        "      el.style.display = 'block';\n"
        "    }\n"
        "    var tb = document.getElementById('clients');\n"
        "    tb.innerHTML = '';\n"
        "    d.clients.forEach(function(c) {\n"
        "      var tr = document.createElement('tr');\n"
        "      var status = c.active ? '<span class=\"online\">online</span>' : '<span class=\"offline\">offline</span>';\n"
        "      var seen = c.last_seen_ago >= 0 ? c.last_seen_ago+'s ago' : '---';\n"
        "      tr.innerHTML = '<td>'+c.id+'</td><td>'+c.ip+'</td><td>'+c.cores+'</td>'\n"
        "        +'<td>'+fmt(c.speed)+'/s</td><td>'+c.lease_id+'</td>'\n"
        "        +'<td>'+fmt(c.tested)+'</td><td>'+seen+'</td><td>'+status+'</td>';\n"
        "      tb.appendChild(tr);\n"
        "    });\n"
        "  } catch(e) {}\n"
        "}\n"
        "refresh();\n"
        "setInterval(refresh, 2000);\n"
        "</script>\n"
        "</body></html>\n";

    int body_len = (int)sizeof(html) - 1;  /* sizeof includes null terminator */
    char hdr[128];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "\r\n", body_len);
    write(fd, hdr, hdr_len);
    write(fd, html, body_len);
}

/* Check HTTP auth token in query string. Returns 1 if OK, 0 if denied. */
static int http_check_auth(const char *path)
{
    if (!g_auth_token[0]) return 1;  /* no token configured */
    const char *q = strchr(path, '?');
    if (!q) return 0;
    q++;  /* skip '?' */
    /* Look for token=<value> in query string */
    const char *p = q;
    while (*p) {
        if (strncmp(p, "token=", 6) == 0) {
            p += 6;
            const char *end = strchr(p, '&');
            size_t tlen = end ? (size_t)(end - p) : strlen(p);
            if (tlen == strlen(g_auth_token) && memcmp(p, g_auth_token, tlen) == 0)
                return 1;
            return 0;
        }
        const char *amp = strchr(p, '&');
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static void handle_http_request(int fd, const char *request_line)
{
    /* Parse "GET /path HTTP/1.x" — extract full path+query between first / and next space */
    char full_path[512] = {0};
    char path[256] = {0};
    {
        const char *start = strchr(request_line, '/');
        if (start) {
            start++;  /* skip the / */
            const char *end = strchr(start, ' ');
            if (!end) end = start + strlen(start);
            size_t len = (size_t)(end - start);
            if (len >= sizeof(full_path)) len = sizeof(full_path) - 1;
            memcpy(full_path, start, len);
            full_path[len] = '\0';
            /* Strip query string for path matching */
            const char *qmark = strchr(full_path, '?');
            size_t plen = qmark ? (size_t)(qmark - full_path) : len;
            if (plen >= sizeof(path)) plen = sizeof(path) - 1;
            memcpy(path, full_path, plen);
            path[plen] = '\0';
        }
    }

    /* Drain remaining HTTP headers */
    char hdr[MAX_LINE];
    while (sock_readline(fd, hdr, sizeof(hdr)) > 0) {
        if (hdr[0] == '\0' || hdr[0] == '\r') break;
    }

    /* Auth check — exempt join.sh (bootstrap entry point) */
    if (strcmp(path, "join.sh") != 0 && !http_check_auth(full_path)) {
        dprintf(fd, "HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    }

    /* GET / — serve the dashboard */
    if (path[0] == '\0') {
        http_serve_dashboard(fd);
        return;
    }

    /* Only serve known files */
    if (strcmp(path, "api/status") == 0) {
        http_serve_api_status(fd);
    } else if (strcmp(path, "client") == 0) {
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/client", g_server_dir);
        http_serve_file(fd, fpath, "application/octet-stream");
    } else if (strcmp(path, "pdf_md5.metallib") == 0) {
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/pdf_md5.metallib", g_server_dir);
        http_serve_file(fd, fpath, "application/octet-stream");
    } else if (strcmp(path, "join.sh") == 0) {
        /* Generate join.sh dynamically with correct IP and port */
        struct sockaddr_in local_addr;
        socklen_t local_len = sizeof(local_addr);
        char server_ip[INET_ADDRSTRLEN] = "SERVER_IP";
        int server_port = DEFAULT_PORT;
        if (getsockname(fd, (struct sockaddr *)&local_addr, &local_len) == 0) {
            inet_ntop(AF_INET, &local_addr.sin_addr, server_ip, sizeof(server_ip));
            server_port = ntohs(local_addr.sin_port);
        }
        /* If bound to 0.0.0.0, try to detect real IP */
        if (strcmp(server_ip, "0.0.0.0") == 0) {
            struct sockaddr_in peer_addr;
            socklen_t peer_len = sizeof(peer_addr);
            if (getpeername(fd, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
                /* Use the local address that routes to this peer */
                getsockname(fd, (struct sockaddr *)&local_addr, &local_len);
                inet_ntop(AF_INET, &local_addr.sin_addr, server_ip, sizeof(server_ip));
            }
        }

        char body[2048];
        int blen = snprintf(body, sizeof(body),
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "DIR=\"$HOME/.pdfcracker\"\n"
            "mkdir -p \"$DIR\"\n"
            "echo \"Downloading client...\"\n"
            "curl -sL http://%s:%d/client -o \"$DIR/client\"\n"
            "curl -sL http://%s:%d/pdf_md5.metallib -o \"$DIR/pdf_md5.metallib\"\n"
            "chmod +x \"$DIR/client\"\n"
            "echo \"Starting pdfcracker client -> %s:%d\"\n"
            "echo \"Press Ctrl+C to stop.\"\n"
            "echo \"---\"\n"
            "cd \"$DIR\"\n"
            "exec ./client -s %s -p %d\n",
            server_ip, server_port,
            server_ip, server_port,
            server_ip, server_port,
            server_ip, server_port);
        dprintf(fd, "HTTP/1.0 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %d\r\n"
                    "\r\n%s", blen, body);
    } else {
        dprintf(fd, "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }
}

/* ================================================================
 * send_session_config — send CONFIG/CHARSET/PWMODE/PDF to a newly
 * registered client and wait for READY.
 * Returns 0 on success, -1 on I/O error.
 * ================================================================ */
static int send_session_config(int fd, int ci_idx)
{
    char line[MAX_LINE];

    /* ── Send config ───────────────────────────────────────────── */
    if (g_brute) {
        sock_printf(fd, "CONFIG BRUTE %d %d", g_max_len, g_password_mode);
        sock_printf(fd, "CHARSET %s", g_charset);
    } else {
        sock_printf(fd, "CONFIG DICT %d", g_password_mode);
    }

    /* Send PWMODE (v4 protocol — older clients will ignore unknown lines) */
    {
        const char *pw_str = "both";
        if (g_password_mode == PW_MODE_USER) pw_str = "user";
        else if (g_password_mode == PW_MODE_OWNER) pw_str = "owner";
        sock_printf(fd, "PWMODE %s", pw_str);
    }

    /* ── Send PDF ──────────────────────────────────────────────── */
    sock_printf(fd, "PDF %ld", g_pdf_size);
    if (write_exact(fd, g_pdf_data, (size_t)g_pdf_size) < 0) {
        fprintf(stderr, "[client %d] failed sending PDF\n", ci_idx);
        return -1;
    }

    /* ── Wait for READY ────────────────────────────────────────── */
    if (sock_readline(fd, line, sizeof(line)) < 0) return -1;
    if (strcmp(line, "READY") != 0) {
        fprintf(stderr, "[client %d] expected READY, got: %s\n", ci_idx, line);
        return -1;
    }
    fprintf(stderr, "[client %d] ready for work\n", ci_idx);
    return 0;
}

/* ================================================================
 * handle_protocol_message — handle one application-level message
 * from the work loop (GETWORK, HEARTBEAT, COMPLETE, PARTIAL, FOUND).
 *
 * Returns:
 *   0  — continue the work loop
 *   1  — break the work loop (DONE / FOUND / ABORT sent)
 * ================================================================ */
static int handle_protocol_message(int fd, ClientInfo *ci,
                                   int ci_idx, const char *line)
{
    /* ── GETWORK <tested> <elapsed> ─────────────────────────────── */
    if (strncmp(line, "GETWORK", 7) == 0) {
        long tested = 0;
        double elapsed = 0.0;
        sscanf(line, "GETWORK %ld %lf", &tested, &elapsed);

        /* Note: tested count credited only in COMPLETE/PARTIAL handlers
         * to avoid double-counting. Here we only use it for speed. */

        /* Compute speed and adaptive chunk size */
        if (elapsed > 0.1 && tested > 0) {
            ci->speed = (double)tested / elapsed;
            double raw_size = ci->speed * TARGET_SECS;
            if (raw_size > (double)MAX_CHUNK_BRUTE) raw_size = (double)MAX_CHUNK_BRUTE;
            long new_size = (long)raw_size;
            if (g_brute) {
                if (g_pdf_revision == 6) {
                    if (new_size < MIN_CHUNK_BRUTE_R6) new_size = MIN_CHUNK_BRUTE_R6;
                    if (new_size > MAX_CHUNK_BRUTE_R6) new_size = MAX_CHUNK_BRUTE_R6;
                } else {
                    if (new_size < MIN_CHUNK_BRUTE) new_size = MIN_CHUNK_BRUTE;
                    if (new_size > MAX_CHUNK_BRUTE) new_size = MAX_CHUNK_BRUTE;
                }
            } else {
                if (new_size < MIN_CHUNK_DICT) new_size = MIN_CHUNK_DICT;
                if (new_size > MAX_CHUNK_DICT) new_size = MAX_CHUNK_DICT;
            }
            ci->chunk_size = new_size;
        }

        /* Check if found */
        if (atomic_load(&g_found)) {
            atomic_thread_fence(memory_order_acquire);
            sock_printf(fd, "FOUND %s", g_password);
            return 1;
        }

        /* Compute deadline */
        int deadline = MIN_LEASE_SECS;
        if (elapsed > 0.1) {
            deadline = (int)(elapsed * LEASE_MULTIPLIER);
            if (deadline < MIN_LEASE_SECS) deadline = MIN_LEASE_SECS;
            if (deadline > MAX_LEASE_SECS) deadline = MAX_LEASE_SECS;
        }

        /* Assign work */
        int is_brute = 0, out_len = 0;
        long out_start = 0, out_end = 0, out_dict_start = 0, out_dict_count = 0;
        uint64_t lid = 0;
        int retries = 0;
        while (retries < 30) {
            lid = assign_work(ci, &is_brute, &out_len,
                              &out_start, &out_end,
                              &out_dict_start, &out_dict_count,
                              deadline);
            if (lid != 0) break;

            /* No work available — check if leases are still in-flight */
            int any_active = 0;
            pthread_mutex_lock(&g_lease_lock);
            int lcount = g_lease_count < MAX_LEASES ? g_lease_count : MAX_LEASES;
            for (int li = 0; li < lcount; li++) {
                int lslot = ((g_lease_count - 1 - li) % MAX_LEASES + MAX_LEASES) % MAX_LEASES;
                if (g_leases[lslot].active) { any_active = 1; break; }
            }
            pthread_mutex_unlock(&g_lease_lock);

            if (!any_active) break;  /* truly done */

            /* Active leases exist — wait for possible requeue */
            retries++;
            struct timespec wait_ts = {0, LEASE_RECHECK_NS};
            nanosleep(&wait_ts, NULL);
        }

        if (lid == 0) {
            sock_printf(fd, "DONE");
            return 1;
        }

        if (is_brute) {
            sock_printf(fd, "BRUTE %d %ld %ld %llu",
                       out_len, out_start, out_end,
                       (unsigned long long)lid);
        } else {
            sock_printf(fd, "DICT %ld %llu",
                       out_dict_count, (unsigned long long)lid);
            for (long i = out_dict_start;
                 i < out_dict_start + out_dict_count; i++)
                sock_printf(fd, "%s", g_words[i]);
        }
        return 0;
    }

    /* ── HEARTBEAT <lease_id> <tested> ──────────────────────────── */
    if (strncmp(line, "HEARTBEAT", 9) == 0) {
        unsigned long long lid = 0;
        long tested = 0;
        sscanf(line, "HEARTBEAT %llu %ld", &lid, &tested);

        pthread_mutex_lock(&g_lease_lock);
        int slot = find_lease((uint64_t)lid);
        if (slot >= 0 && g_leases[slot].active) {
            g_leases[slot].tested_so_far = tested;
            g_leases[slot].last_heartbeat = mono_time();
        }
        pthread_mutex_unlock(&g_lease_lock);

        if (atomic_load(&g_found)) {
            sock_printf(fd, "ABORT");
        } else {
            sock_printf(fd, "OK");
        }
        return 0;
    }

    /* ── COMPLETE <lease_id> <tested> ───────────────────────────── */
    if (strncmp(line, "COMPLETE", 8) == 0) {
        unsigned long long lid = 0;
        long tested = 0;
        sscanf(line, "COMPLETE %llu %ld", &lid, &tested);

        if (tested > 0) {
            atomic_fetch_add(&g_total_tested, tested);
            ci->tested += tested;
        }

        pthread_mutex_lock(&g_lease_lock);
        complete_lease((uint64_t)lid, tested);
        pthread_mutex_unlock(&g_lease_lock);

        ci->current_lease_id = 0;
        return 0;
    }

    /* ── PARTIAL <lease_id> <hwm> ───────────────────────────────── */
    if (strncmp(line, "PARTIAL", 7) == 0) {
        unsigned long long lid = 0;
        long hwm = 0;
        sscanf(line, "PARTIAL %llu %ld", &lid, &hwm);

        pthread_mutex_lock(&g_lease_lock);
        int slot = find_lease((uint64_t)lid);
        if (slot >= 0 && g_leases[slot].active) {
            LeaseEntry *le = &g_leases[slot];
            le->active = 0;

            pthread_mutex_lock(&g_work_lock);
            if (le->is_brute) {
                /* Re-queue the remaining range */
                long new_start = le->brute_start + hwm;
                long credited = hwm;
                if (credited > 0) {
                    atomic_fetch_add(&g_total_tested, credited);
                    ci->tested += credited;
                }
                if (new_start < le->brute_end) {
                    push_requeue_brute(le->brute_len, new_start, le->brute_end);
                }
            } else {
                /* Dict: re-queue entire chunk (can't split precisely) */
                long credited = hwm;
                if (credited > 0) {
                    atomic_fetch_add(&g_total_tested, credited);
                    ci->tested += credited;
                }
                push_requeue_dict(le->dict_start, le->dict_count);
            }
            pthread_mutex_unlock(&g_work_lock);
        }
        pthread_mutex_unlock(&g_lease_lock);

        ci->current_lease_id = 0;
        return 0;
    }

    /* ── FOUND <password> <lease_id> ────────────────────────────── */
    if (strncmp(line, "FOUND ", 6) == 0) {
        char pw[MAX_PASS_LEN + 1] = {0};
        unsigned long long lid = 0;
        sscanf(line, "FOUND %32s %llu", pw, &lid);

        if (g_srv_enc.valid && !pdf_verify_password(&g_srv_enc, pw)) {
            fprintf(stderr,
                "[server] ignoring unverified FOUND \"%s\" from client %d\n",
                pw, ci_idx);
            return 0;   /* keep searching; do not set g_found/g_password */
        }

        if (!atomic_exchange(&g_found, 1)) {
            strncpy(g_password, pw, MAX_PASS_LEN);
            atomic_thread_fence(memory_order_release);
            fprintf(stderr,
                "\n\n  *** PASSWORD FOUND by client %d: %s ***\n\n",
                ci_idx, g_password);
        }

        if (lid > 0) {
            pthread_mutex_lock(&g_lease_lock);
            complete_lease((uint64_t)lid, 0);
            pthread_mutex_unlock(&g_lease_lock);
        }

        sock_printf(fd, "OK");
        return 1;
    }

    /* Unknown message — ignored */
    return 0;
}

/* ================================================================
 * Client handler — orchestrates connection lifecycle
 * ================================================================ */

static void *client_handler(void *arg)
{
    int fd = *(int *)arg;
    free(arg);

    char line[MAX_LINE];
    int ci_idx = -1;

    /* Get client IP */
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    char ip_str[INET_ADDRSTRLEN] = "unknown";
    if (getpeername(fd, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
        inet_ntop(AF_INET, &peer_addr.sin_addr, ip_str, sizeof(ip_str));
    }

    /* ── Read first line: HELLO (protocol) or GET (HTTP bootstrap) ── */
    if (sock_readline(fd, line, sizeof(line)) < 0) goto done;

    /* HTTP request? Serve files and close. */
    if (strncmp(line, "GET ", 4) == 0) {
        char req_path[256] = "/";
        sscanf(line, "GET %255s", req_path);
        fprintf(stderr, "[%s] HTTP %s\n", ip_str, req_path);
        handle_http_request(fd, line);
        close(fd);
        return NULL;
    }

    /* ── Parse HELLO handshake ─────────────────────────────────── */
    int ncores = 0, proto_ver = 0;
    char uuid[UUID_LEN + 1] = {0};
    if (sscanf(line, "HELLO %d %36s %d", &ncores, uuid, &proto_ver) != 3 ||
        ncores < 1) {
        fprintf(stderr, "[%s] bad handshake: %s\n", ip_str, line);
        sock_printf(fd, "ERROR bad handshake");
        goto done;
    }

    if (proto_ver != PROTO_VERSION && proto_ver != 3) {
        fprintf(stderr, "[%s] protocol version mismatch: got %d, want %d (or 3)\n",
                ip_str, proto_ver, PROTO_VERSION);
        sock_printf(fd, "ERROR protocol version mismatch");
        goto done;
    }

    /* ── Find or allocate client slot ─────────────────────────── */
    pthread_mutex_lock(&g_clients_lock);
    ci_idx = find_client_by_uuid(uuid);
    if (ci_idx >= 0) {
        if (g_clients[ci_idx].active) {
            /* Duplicate UUID, reject */
            pthread_mutex_unlock(&g_clients_lock);
            fprintf(stderr, "[%s] duplicate UUID %s, rejecting\n", ip_str, uuid);
            sock_printf(fd, "ERROR duplicate UUID");
            ci_idx = -1;
            goto done;
        }
        /* Reconnecting client — reuse slot */
        fprintf(stderr, "[%s] client %d reconnected (uuid %s)\n",
                ip_str, ci_idx, uuid);
    } else {
        ci_idx = alloc_client_slot();
        if (ci_idx < 0) {
            pthread_mutex_unlock(&g_clients_lock);
            fprintf(stderr, "[%s] max clients reached, rejecting\n", ip_str);
            sock_printf(fd, "ERROR max clients");
            goto done;
        }
        strncpy(g_clients[ci_idx].uuid, uuid, UUID_LEN);
        g_clients[ci_idx].uuid[UUID_LEN] = '\0';
        g_clients[ci_idx].tested = 0;
        g_clients[ci_idx].speed = 0;
        g_clients[ci_idx].chunk_size = 0;
        fprintf(stderr, "[%s] new client %d (uuid %s, %d cores)\n",
                ip_str, ci_idx, uuid, ncores);
    }

    ClientInfo *ci = &g_clients[ci_idx];
    ci->fd        = fd;
    ci->cores     = ncores;
    ci->active    = 1;
    ci->slot_free = 0;
    strncpy(ci->ip_str, ip_str, INET_ADDRSTRLEN);
    ci->ip_str[INET_ADDRSTRLEN - 1] = '\0';
    ci->last_seen = mono_time();
    ci->current_lease_id = 0;
    pthread_mutex_unlock(&g_clients_lock);

    /* ── Send session config and PDF, wait for READY ──────────── */
    if (send_session_config(fd, ci_idx) < 0) goto done;

    /* ── Work loop ─────────────────────────────────────────────── */
    while (!g_shutdown && sock_readline(fd, line, sizeof(line)) >= 0) {
        ci->last_seen = mono_time();
        if (handle_protocol_message(fd, ci, ci_idx, line))
            break;
    }

done:
    if (ci_idx >= 0) {
        fprintf(stderr, "[client %d] disconnected (tested %ld passwords)\n",
                ci_idx, g_clients[ci_idx].tested);

        pthread_mutex_lock(&g_clients_lock);
        g_clients[ci_idx].active = 0;
        /* Do NOT set slot_free — they might reconnect */
        g_clients[ci_idx].fd = -1;
        pthread_mutex_unlock(&g_clients_lock);
    }

    close(fd);
    return NULL;
}

/* ================================================================
 * Reaper thread — expire stale leases
 * ================================================================ */
static void *reaper_thread(void *arg)
{
    (void)arg;
    while (!g_shutdown && !atomic_load(&g_found)) {
        struct timespec ts = {REAPER_INTERVAL, 0};
        nanosleep(&ts, NULL);

        double now = mono_time();

        pthread_mutex_lock(&g_lease_lock);
        int count = g_lease_count < MAX_LEASES ? g_lease_count : MAX_LEASES;
        for (int i = 0; i < count; i++) {
            int slot = ((g_lease_count - 1 - i) % MAX_LEASES + MAX_LEASES) % MAX_LEASES;
            LeaseEntry *le = &g_leases[slot];
            if (!le->active) continue;

            int expired = 0;

            /* Check deadline */
            if (now > le->deadline) {
                expired = 1;
            }

            /* Check client last_seen */
            if (!expired && le->client_idx >= 0 && le->client_idx < g_nclient_ids) {
                pthread_mutex_lock(&g_clients_lock);
                double last_seen = g_clients[le->client_idx].last_seen;
                pthread_mutex_unlock(&g_clients_lock);
                if (now - last_seen > HEARTBEAT_TIMEOUT) {
                    expired = 1;
                }
            }

            if (expired) {
                fprintf(stderr, "[reaper] expiring lease %llu (client %d)\n",
                        (unsigned long long)le->lease_id, le->client_idx);
                expire_lease(le->lease_id);
            }
        }
        pthread_mutex_unlock(&g_lease_lock);
    }
    return NULL;
}

/* ================================================================
 * Checkpoint
 * ================================================================ */
static void save_checkpoint(void)
{
    if (!g_pdf_path) return;

    /* Build checkpoint filename from PDF basename */
    const char *base = strrchr(g_pdf_path, '/');
    base = base ? base + 1 : g_pdf_path;

    char ckpt_path[512], tmp_path[520];
    snprintf(ckpt_path, sizeof(ckpt_path), "%s.server.ckpt", base);
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", ckpt_path);

    FILE *f = fopen(tmp_path, "w");
    if (!f) { perror("save_checkpoint"); return; }

    fprintf(f, "PDFCRACKER_CHECKPOINT v2\n");
    fprintf(f, "pdf_sha256 %s\n", g_pdf_sha256);
    fprintf(f, "wordlist_sha256 %s\n", g_wordlist_sha256[0] ? g_wordlist_sha256 : "none");
    fprintf(f, "mode %s\n", g_brute ? "brute" : "dict");
    fprintf(f, "charset %s\n", g_charset ? g_charset : "none");
    fprintf(f, "max_len %d\n", g_max_len);
    fprintf(f, "attack_mode %d\n", g_attack_mode);
    fprintf(f, "password_mode %d\n", g_password_mode);
    if (g_auto_phase > 0)
        fprintf(f, "auto_phase %d\n", g_auto_phase);
    if (g_mask_pattern[0])
        fprintf(f, "mask_pattern %s\n", g_mask_pattern);
    if (g_hybrid_suffix_len > 0)
        fprintf(f, "hybrid_suffix_len %d\n", g_hybrid_suffix_len);
    if (g_freq_mode)
        fprintf(f, "freq_mode 1\n");
    if (g_pdf_revision > 0)
        fprintf(f, "revision %d\n", g_pdf_revision);

    /* Lock order: g_lease_lock first, then g_work_lock (matches reaper) */
    pthread_mutex_lock(&g_lease_lock);
    pthread_mutex_lock(&g_work_lock);
    fprintf(f, "brute_cursor %d %ld\n", g_brute_len, g_brute_idx);
    fprintf(f, "dict_cursor %ld\n", g_dict_idx);
    pthread_mutex_unlock(&g_work_lock);

    fprintf(f, "total_tested %ld\n", atomic_load(&g_total_tested));
    fprintf(f, "keyspace %ld\n", g_keyspace);

    /* Save active leases (g_lease_lock already held) */
    int count = g_lease_count < MAX_LEASES ? g_lease_count : MAX_LEASES;
    for (int i = 0; i < count; i++) {
        int slot = ((g_lease_count - 1 - i) % MAX_LEASES + MAX_LEASES) % MAX_LEASES;
        LeaseEntry *le = &g_leases[slot];
        if (!le->active) continue;
        if (le->is_brute) {
            fprintf(f, "lease %llu brute %d %ld %ld\n",
                    (unsigned long long)le->lease_id,
                    le->brute_len, le->brute_start, le->brute_end);
        } else {
            fprintf(f, "lease %llu dict %ld %ld\n",
                    (unsigned long long)le->lease_id,
                    le->dict_start, le->dict_count);
        }
    }
    pthread_mutex_unlock(&g_lease_lock);

    fprintf(f, "END\n");
    fclose(f);

    rename(tmp_path, ckpt_path);
}

static int restore_checkpoint(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    char line[MAX_LINE];

    /* Header — accept v1 or v2 */
    if (!fgets(line, sizeof(line), f) ||
        (strncmp(line, "PDFCRACKER_CHECKPOINT v1", 23) != 0 &&
         strncmp(line, "PDFCRACKER_CHECKPOINT v2", 23) != 0)) {
        fprintf(stderr, "Bad checkpoint header\n");
        fclose(f); return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        size_t len = strlen(line);
        while (len && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if (strcmp(line, "END") == 0) break;

        char key[64] = {0}, val[256] = {0};
        if (sscanf(line, "%63s %255[^\n]", key, val) < 1) continue;

        if (strcmp(key, "pdf_sha256") == 0) {
            if (strcmp(val, g_pdf_sha256) != 0) {
                fprintf(stderr, "PDF hash mismatch in checkpoint\n"
                        "  checkpoint: %s\n  current:    %s\n",
                        val, g_pdf_sha256);
                fclose(f); return 0;
            }
        } else if (strcmp(key, "wordlist_sha256") == 0) {
            if (strcmp(val, "none") != 0 && g_wordlist_sha256[0] &&
                strcmp(val, g_wordlist_sha256) != 0) {
                fprintf(stderr, "Wordlist hash mismatch in checkpoint\n"
                        "  checkpoint: %s\n  current:    %s\n",
                        val, g_wordlist_sha256);
                fclose(f); return 0;
            }
        } else if (strcmp(key, "brute_cursor") == 0) {
            sscanf(val, "%d %ld", &g_brute_len, &g_brute_idx);
        } else if (strcmp(key, "dict_cursor") == 0) {
            sscanf(val, "%ld", &g_dict_idx);
        } else if (strcmp(key, "total_tested") == 0) {
            long t = 0;
            sscanf(val, "%ld", &t);
            atomic_store(&g_total_tested, t);
        } else if (strcmp(key, "keyspace") == 0) {
            sscanf(val, "%ld", &g_keyspace);
        } else if (strcmp(key, "attack_mode") == 0) {
            sscanf(val, "%d", &g_attack_mode);
        } else if (strcmp(key, "password_mode") == 0) {
            sscanf(val, "%d", &g_password_mode);
        } else if (strcmp(key, "auto_phase") == 0) {
            sscanf(val, "%d", &g_auto_phase);
        } else if (strcmp(key, "mask_pattern") == 0) {
            strncpy(g_mask_pattern, val, sizeof(g_mask_pattern) - 1);
        } else if (strcmp(key, "hybrid_suffix_len") == 0) {
            sscanf(val, "%d", &g_hybrid_suffix_len);
        } else if (strcmp(key, "freq_mode") == 0) {
            sscanf(val, "%d", &g_freq_mode);
        } else if (strcmp(key, "revision") == 0) {
            int rev = 0;
            sscanf(val, "%d", &rev);
            if (rev > 0 && g_pdf_revision == 0) g_pdf_revision = rev;
        } else if (strcmp(key, "lease") == 0) {
            /* Push all saved leases into requeue */
            unsigned long long lid = 0;
            char type[16] = {0};
            sscanf(val, "%llu %15s", &lid, type);
            (void)lid;  /* lease IDs from checkpoint are just re-queued */

            pthread_mutex_lock(&g_work_lock);
            if (strcmp(type, "brute") == 0) {
                int blen = 0;
                long bstart = 0, bend = 0;
                sscanf(val, "%*llu %*s %d %ld %ld", &blen, &bstart, &bend);
                push_requeue_brute(blen, bstart, bend);
            } else if (strcmp(type, "dict") == 0) {
                long dstart = 0, dcount = 0;
                sscanf(val, "%*llu %*s %ld %ld", &dstart, &dcount);
                push_requeue_dict(dstart, dcount);
            }
            pthread_mutex_unlock(&g_work_lock);
        }
        /* Ignore mode, charset, max_len — those come from command line */
    }

    fclose(f);
    fprintf(stderr, "Checkpoint restored from %s\n", path);
    fprintf(stderr, "  brute cursor: len=%d idx=%ld\n", g_brute_len, g_brute_idx);
    fprintf(stderr, "  dict cursor:  idx=%ld\n", g_dict_idx);
    fprintf(stderr, "  total tested: %ld\n", atomic_load(&g_total_tested));
    return 1;
}

/* ================================================================
 * Checkpoint thread
 * ================================================================ */
static void *checkpoint_thread(void *arg)
{
    (void)arg;
    while (!g_shutdown && !atomic_load(&g_found)) {
        struct timespec ts = {CHECKPOINT_INTERVAL, 0};
        nanosleep(&ts, NULL);
        save_checkpoint();
    }
    return NULL;
}

/* ================================================================
 * Shutdown
 * ================================================================ */
static void broadcast_abort(void)
{
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < g_nclient_ids; i++) {
        if (g_clients[i].active && g_clients[i].fd >= 0) {
            sock_printf(g_clients[i].fd, "ABORT");
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
}

static void sigint_handler(int sig)
{
    (void)sig;
    g_shutdown = 1;
    /* Interrupt accept() */
    if (g_listenfd >= 0) {
        shutdown(g_listenfd, SHUT_RDWR);
    }
}

/* ================================================================
 * Formatting helpers
 * ================================================================ */
static void fmt_num(long n, char *buf, size_t sz)
{
    if (n >= 1000000000L)
        snprintf(buf, sz, "%.1fG", (double)n / 1e9);
    else if (n >= 1000000L)
        snprintf(buf, sz, "%.1fM", (double)n / 1e6);
    else if (n >= 1000L)
        snprintf(buf, sz, "%.1fK", (double)n / 1e3);
    else
        snprintf(buf, sz, "%ld", n);
}

static void fmt_time(long secs, char *buf, size_t sz)
{
    if (secs < 0) {
        snprintf(buf, sz, "---");
    } else if (secs >= 3600) {
        snprintf(buf, sz, "%ldh%02ldm", secs / 3600, (secs % 3600) / 60);
    } else if (secs >= 60) {
        snprintf(buf, sz, "%ldm%02lds", secs / 60, secs % 60);
    } else {
        snprintf(buf, sz, "%lds", secs);
    }
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

    while (!g_shutdown && !atomic_load(&g_found)) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);

        long cur     = atomic_load(&g_total_tested);
        double now   = mono_time();
        long elapsed = (long)(now - g_start_time);

        /* Count active clients and sum their speeds */
        int nactive = 0;
        double total_speed = 0;
        pthread_mutex_lock(&g_clients_lock);
        for (int i = 0; i < g_nclient_ids; i++) {
            if (g_clients[i].active) {
                nactive++;
                total_speed += g_clients[i].speed;
            }
        }
        pthread_mutex_unlock(&g_clients_lock);
        long rate = (long)total_speed;

        /* Clear line */
        fputs("\r\033[K", stderr);

        char rate_s[32], tested_s[32], elapsed_s[32], eta_s[32];
        fmt_num(rate, rate_s, sizeof(rate_s));
        fmt_num(cur, tested_s, sizeof(tested_s));
        fmt_time(elapsed, elapsed_s, sizeof(elapsed_s));

        if (g_keyspace > 0) {
            double pct = (double)cur / (double)g_keyspace * 100.0;
            if (pct > 100.0) pct = 100.0;

            long eta = -1;
            if (rate > 0 && g_keyspace > cur)
                eta = (g_keyspace - cur) / rate;
            fmt_time(eta, eta_s, sizeof(eta_s));

            fputs("  ", stderr);
            print_bar(pct);
            fprintf(stderr, " %5.1f%%  [%d clients]  %s tested  %s/s  %s  ETA %s",
                    pct, nactive, tested_s, rate_s, elapsed_s, eta_s);
        } else {
            fprintf(stderr, "  [%d clients]  %s tested  %s/s  %s",
                    nactive, tested_s, rate_s, elapsed_s);
        }

        /* Per-client stats */
        fprintf(stderr, "\n");
        pthread_mutex_lock(&g_clients_lock);
        for (int i = 0; i < g_nclient_ids; i++) {
            ClientInfo *ci = &g_clients[i];
            if (ci->slot_free) continue;

            char sp[32], te[32];
            fmt_num((long)ci->speed, sp, sizeof(sp));
            fmt_num(ci->tested, te, sizeof(te));

            int ago = ci->active ? (int)(now - ci->last_seen) : -1;

            fprintf(stderr, "    #%-2d %-15s %2d cores  %6s/s  lease %-4llu  %8s tested",
                    i, ci->ip_str, ci->cores, sp,
                    (unsigned long long)ci->current_lease_id, te);
            if (ci->active) {
                fprintf(stderr, "  %ds ago", ago);
            } else {
                fprintf(stderr, "  [offline]");
            }
            fprintf(stderr, "\n");
        }
        pthread_mutex_unlock(&g_clients_lock);

        /* Move cursor up for overwrite on next iteration */
        int lines_to_clear = 1;  /* main line */
        pthread_mutex_lock(&g_clients_lock);
        for (int i = 0; i < g_nclient_ids; i++) {
            if (!g_clients[i].slot_free) lines_to_clear++;
        }
        pthread_mutex_unlock(&g_clients_lock);

        /* Move cursor up N lines */
        for (int i = 0; i < lines_to_clear; i++) {
            fputs("\033[A", stderr);
        }
        /* Move to beginning */
        fputc('\r', stderr);
        fflush(stderr);
    }
    return NULL;
}

/* ================================================================
 * Web Dashboard — dedicated HTTP server on --web-port
 * ================================================================ */

/* JSON-escape a string into buf (at most buf_sz-1 chars + NUL) */
static void web_json_escape(const char *in, char *buf, size_t buf_sz)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 6 < buf_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"')       { buf[j++] = '\\'; buf[j++] = '"'; }
        else if (c == '\\') { buf[j++] = '\\'; buf[j++] = '\\'; }
        else if (c < 0x20)  { j += (size_t)snprintf(buf + j, buf_sz - j, "\\u%04x", c); }
        else                { buf[j++] = (char)c; }
    }
    buf[j] = '\0';
}

static void web_serve_api_status(int fd)
{
    double now = mono_time();
    long tested = atomic_load(&g_total_tested);
    int found = atomic_load(&g_found);
    double elapsed = now - g_start_time;

    /* Snapshot password under lock to avoid data race */
    char pw_copy[MAX_PASS_LEN + 1] = {0};
    if (found) {
        pthread_mutex_lock(&g_work_lock);
        memcpy(pw_copy, g_password, sizeof(pw_copy));
        pthread_mutex_unlock(&g_work_lock);
    }

    /* JSON-escape strings that may contain special chars */
    char pw_escaped[MAX_PASS_LEN * 2 + 1];
    char cs_escaped[512];
    web_json_escape(pw_copy, pw_escaped, sizeof(pw_escaped));
    web_json_escape(g_charset ? g_charset : "", cs_escaped, sizeof(cs_escaped));

    double total_speed = 0;
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < g_nclient_ids; i++) {
        if (g_clients[i].active)
            total_speed += g_clients[i].speed;
    }

    /* Build JSON */
    char body[16384];
    int off = 0;
    off += snprintf(body + off, sizeof(body) - (size_t)off,
        "{\"mode\":\"%s\","
        "\"charset\":\"%s\","
        "\"max_length\":%d,"
        "\"total_keyspace\":%ld,"
        "\"total_tested\":%ld,"
        "\"elapsed_secs\":%.1f,"
        "\"aggregate_rate\":%.0f,"
        "\"found\":%s,"
        "\"password\":%s%s%s,"
        "\"clients\":[",
        g_brute ? "brute" : "dict",
        cs_escaped,
        g_max_len,
        g_keyspace,
        tested,
        elapsed,
        total_speed,
        found ? "true" : "false",
        found ? "\"" : "null",
        found ? pw_escaped : "",
        found ? "\"" : "");

    int first = 1;
    for (int i = 0; i < g_nclient_ids; i++) {
        ClientInfo *ci = &g_clients[i];
        if (ci->slot_free) continue;
        int ago = ci->active ? (int)(now - ci->last_seen) : -1;
        const char *status = ci->active ? "working" : "offline";
        if (!first) {
            off += snprintf(body + off, sizeof(body) - (size_t)off, ",");
        }
        first = 0;
        off += snprintf(body + off, sizeof(body) - (size_t)off,
            "{\"id\":\"%s\","
            "\"ip\":\"%s\","
            "\"cores\":%d,"
            "\"speed\":%.0f,"
            "\"tested\":%ld,"
            "\"status\":\"%s\","
            "\"last_heartbeat_ago\":%d}",
            ci->uuid, ci->ip_str, ci->cores, ci->speed,
            ci->tested, status, ago);
    }
    pthread_mutex_unlock(&g_clients_lock);

    off += snprintf(body + off, sizeof(body) - (size_t)off, "]}");

    dprintf(fd, "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %d\r\n"
                "\r\n%s", off, body);
}

static void web_serve_dashboard(int fd)
{
    static const char html[] =
        "<!DOCTYPE html>\n"
        "<html><head><meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>pdfcracker Dashboard</title>\n"
        "<style>\n"
        "  * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "  body { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;\n"
        "         background: #1a1a2e; color: #eee; padding: 20px; min-height: 100vh; }\n"
        "  h1 { font-size: 1.5em; margin-bottom: 18px; color: #7fbaff;\n"
        "       border-bottom: 1px solid #16213e; padding-bottom: 10px; }\n"
        "  .card { background: #16213e; border: 1px solid #0f3460;\n"
        "          border-radius: 8px; padding: 16px; margin-bottom: 16px; }\n"
        "  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));\n"
        "           gap: 12px; }\n"
        "  .stat-label { font-size: 0.7em; color: #8899aa; text-transform: uppercase;\n"
        "                letter-spacing: 0.05em; }\n"
        "  .stat-value { font-size: 1.4em; font-weight: 700; color: #f0f0f0; margin-top: 2px; }\n"
        "  .bar-bg { background: #0f3460; border-radius: 6px; height: 24px;\n"
        "            margin: 14px 0; overflow: hidden; position: relative; }\n"
        "  .bar-fg { background: linear-gradient(90deg, #e94560, #ff6b6b);\n"
        "            height: 100%; border-radius: 6px; transition: width 0.6s ease; }\n"
        "  .bar-text { position: absolute; top: 0; left: 0; right: 0; height: 100%;\n"
        "              display: flex; align-items: center; justify-content: center;\n"
        "              font-size: 0.8em; font-weight: 600; color: #fff; }\n"
        "  table { width: 100%; border-collapse: collapse; font-size: 0.85em; }\n"
        "  th { text-align: left; color: #8899aa; font-weight: 500; padding: 8px 10px;\n"
        "       border-bottom: 1px solid #0f3460; font-size: 0.75em;\n"
        "       text-transform: uppercase; letter-spacing: 0.05em; }\n"
        "  td { padding: 8px 10px; border-bottom: 1px solid #16213e; }\n"
        "  tr:hover td { background: #1a2744; }\n"
        "  .online { color: #3fb950; font-weight: 600; }\n"
        "  .offline { color: #f85149; font-weight: 600; }\n"
        "  .found-banner { background: #238636; color: #fff; padding: 14px 20px;\n"
        "                  border-radius: 8px; font-size: 1.3em; font-weight: 700;\n"
        "                  display: none; text-align: center; margin-bottom: 16px;\n"
        "                  letter-spacing: 0.02em; }\n"
        "  .mode-info { font-size: 0.85em; color: #8899aa; margin-bottom: 10px; }\n"
        "  .uuid { font-size: 0.8em; color: #6680aa; font-family: monospace; }\n"
        "  @media (max-width: 600px) {\n"
        "    body { padding: 10px; }\n"
        "    .stats { grid-template-columns: repeat(2, 1fr); gap: 8px; }\n"
        "    .stat-value { font-size: 1.1em; }\n"
        "    table { font-size: 0.75em; }\n"
        "    th, td { padding: 6px 4px; }\n"
        "  }\n"
        "</style>\n"
        "</head><body>\n"
        "<h1>pdfcracker Dashboard</h1>\n"
        "<div id='found' class='found-banner'></div>\n"
        "<div class='card'>\n"
        "  <div id='mode-info' class='mode-info'></div>\n"
        "  <div class='bar-bg'>\n"
        "    <div id='bar' class='bar-fg' style='width:0%'></div>\n"
        "    <div id='bar-text' class='bar-text'>0%</div>\n"
        "  </div>\n"
        "  <div class='stats'>\n"
        "    <div><div class='stat-label'>Progress</div><div class='stat-value' id='pct'>--</div></div>\n"
        "    <div><div class='stat-label'>Tested</div><div class='stat-value' id='tested'>--</div></div>\n"
        "    <div><div class='stat-label'>Speed</div><div class='stat-value' id='speed'>--</div></div>\n"
        "    <div><div class='stat-label'>ETA</div><div class='stat-value' id='eta'>--</div></div>\n"
        "    <div><div class='stat-label'>Elapsed</div><div class='stat-value' id='elapsed'>--</div></div>\n"
        "    <div><div class='stat-label'>Keyspace</div><div class='stat-value' id='keyspace'>--</div></div>\n"
        "  </div>\n"
        "</div>\n"
        "<div class='card'>\n"
        "  <table><thead><tr>\n"
        "    <th>ID</th><th>IP</th><th>Cores</th><th>Speed</th>\n"
        "    <th>Tested</th><th>Status</th><th>Last Heartbeat</th>\n"
        "  </tr></thead><tbody id='clients'></tbody></table>\n"
        "</div>\n"
        "<script>\n"
        "function fmtNum(n) {\n"
        "  if (n == null) return '---';\n"
        "  if (n >= 1e12) return (n/1e12).toFixed(1)+'T';\n"
        "  if (n >= 1e9) return (n/1e9).toFixed(1)+'G';\n"
        "  if (n >= 1e6) return (n/1e6).toFixed(1)+'M';\n"
        "  if (n >= 1e3) return (n/1e3).toFixed(1)+'K';\n"
        "  return n.toLocaleString();\n"
        "}\n"
        "function fmtSpeed(n) {\n"
        "  if (n == null || n <= 0) return '0/s';\n"
        "  if (n >= 1e6) return (n/1e6).toFixed(1)+'M/s';\n"
        "  if (n >= 1e3) return (n/1e3).toFixed(1)+'K/s';\n"
        "  return Math.round(n)+'/s';\n"
        "}\n"
        "function fmtTime(s) {\n"
        "  if (s == null || s < 0) return '---';\n"
        "  s = Math.floor(s);\n"
        "  var h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;\n"
        "  if (h > 0) return h+'h '+String(m).padStart(2,'0')+'m '+String(sec).padStart(2,'0')+'s';\n"
        "  if (m > 0) return m+'m '+String(sec).padStart(2,'0')+'s';\n"
        "  return sec+'s';\n"
        "}\n"
        "function shortUuid(u) {\n"
        "  if (!u || u.length < 8) return u || '---';\n"
        "  return u.substring(0, 8);\n"
        "}\n"
        "async function refresh() {\n"
        "  try {\n"
        "    var r = await fetch('/api/status');\n"
        "    var d = await r.json();\n"
        "    var pct = d.total_keyspace > 0 ? (d.total_tested / d.total_keyspace * 100) : 0;\n"
        "    if (pct > 100) pct = 100;\n"
        "    document.getElementById('pct').textContent = pct.toFixed(2)+'%';\n"
        "    document.getElementById('bar').style.width = Math.min(pct,100)+'%';\n"
        "    document.getElementById('bar-text').textContent = pct.toFixed(1)+'%';\n"
        "    document.getElementById('tested').textContent = fmtNum(d.total_tested);\n"
        "    document.getElementById('speed').textContent = fmtSpeed(d.aggregate_rate);\n"
        "    var eta = d.aggregate_rate > 0 && d.total_keyspace > d.total_tested\n"
        "      ? (d.total_keyspace - d.total_tested) / d.aggregate_rate : -1;\n"
        "    document.getElementById('eta').textContent = fmtTime(eta);\n"
        "    document.getElementById('elapsed').textContent = fmtTime(d.elapsed_secs);\n"
        "    document.getElementById('keyspace').textContent = fmtNum(d.total_keyspace);\n"
        "    var info = 'Mode: ' + d.mode;\n"
        "    if (d.mode === 'brute') info += ' | Charset: ' + d.charset + ' | Max length: ' + d.max_length;\n"
        "    document.getElementById('mode-info').textContent = info;\n"
        "    if (d.found) {\n"
        "      var el = document.getElementById('found');\n"
        "      el.textContent = 'PASSWORD FOUND: ' + d.password;\n"
        "      el.style.display = 'block';\n"
        "    }\n"
        "    var tb = document.getElementById('clients');\n"
        "    tb.innerHTML = '';\n"
        "    d.clients.forEach(function(c) {\n"
        "      var tr = document.createElement('tr');\n"
        "      var st = c.status === 'working'\n"
        "        ? '<span class=online>working</span>'\n"
        "        : '<span class=offline>offline</span>';\n"
        "      var hb = c.last_heartbeat_ago >= 0 ? c.last_heartbeat_ago+'s ago' : '---';\n"
        "      tr.innerHTML = '<td><span class=uuid>' + shortUuid(c.id) + '</span></td>'\n"
        "        + '<td>' + c.ip + '</td>'\n"
        "        + '<td>' + c.cores + '</td>'\n"
        "        + '<td>' + fmtSpeed(c.speed) + '</td>'\n"
        "        + '<td>' + fmtNum(c.tested) + '</td>'\n"
        "        + '<td>' + st + '</td>'\n"
        "        + '<td>' + hb + '</td>';\n"
        "      tb.appendChild(tr);\n"
        "    });\n"
        "  } catch(e) {}\n"
        "}\n"
        "refresh();\n"
        "setInterval(refresh, 2000);\n"
        "</script>\n"
        "</body></html>\n";

    int body_len = (int)sizeof(html) - 1;
    dprintf(fd, "HTTP/1.0 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Content-Length: %d\r\n"
                "\r\n", body_len);
    write(fd, html, body_len);
}

static void *web_server_thread(void *arg)
{
    (void)arg;

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("web socket"); return NULL; }

    int yes = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)g_web_port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("web bind"); close(sfd); return NULL;
    }
    if (listen(sfd, 8) < 0) {
        perror("web listen"); close(sfd); return NULL;
    }

    fprintf(stderr, "Web dashboard: http://0.0.0.0:%d\n", g_web_port);

    while (!g_shutdown) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR || g_shutdown) break;
            continue;
        }

        /* Read timeout to avoid blocking on bad clients */
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* Read until \r\n\r\n */
        char buf[4096];
        ssize_t total = 0;
        int header_done = 0;
        while (total < (ssize_t)sizeof(buf) - 1) {
            ssize_t r = read(cfd, buf + total, 1);
            if (r <= 0) break;
            total += r;
            if (total >= 4 &&
                buf[total-4] == '\r' && buf[total-3] == '\n' &&
                buf[total-2] == '\r' && buf[total-1] == '\n') {
                header_done = 1;
                break;
            }
        }
        buf[total] = '\0';

        if (header_done || total > 0) {
            /* Extract path from "GET /path HTTP/1.x" */
            char path[256] = "";
            if (strncmp(buf, "GET ", 4) == 0) {
                char *p = buf + 4;
                char *end = strchr(p, ' ');
                if (!end) end = strchr(p, '\r');
                if (!end) end = p + strlen(p);
                size_t len = (size_t)(end - p);
                if (len >= sizeof(path)) len = sizeof(path) - 1;
                memcpy(path, p, len);
                path[len] = '\0';
            }

            if (strcmp(path, "/") == 0) {
                web_serve_dashboard(cfd);
            } else if (strcmp(path, "/api/status") == 0) {
                web_serve_api_status(cfd);
            } else {
                dprintf(cfd, "HTTP/1.0 404 Not Found\r\n"
                             "Content-Type: text/plain\r\n"
                             "Access-Control-Allow-Origin: *\r\n"
                             "Content-Length: 9\r\n"
                             "\r\nNot Found");
            }
        }
        close(cfd);
    }

    close(sfd);
    return NULL;
}

/* ================================================================
 * Usage
 * ================================================================ */
static void usage(const char *p)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s -f <pdf> -d <wordlist> [-p <port>]                dictionary\n"
        "  %s -f <pdf> -b [-l <maxlen>] [-c <charset>] [-p <port>]  brute-force\n"
        "  %s -f <pdf> ... -R <ckpt_file>                       restore\n"
        "\nOptions:\n"
        "  --web-port N        Start web dashboard on port N (default: disabled)\n"
        "  --auth-token SECRET Require ?token=SECRET on HTTP endpoints\n"
        "\nStarts cracking locally and listens for remote workers.\n"
        "Other Macs can join with:\n"
        "  bash /tmp/join.sh user@<this-ip> [port]\n",
        p, p, p);
    exit(1);
}

/* ================================================================
 * main
 * ================================================================ */
int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    /* Determine server binary directory (for HTTP file serving) */
    {
        char *dir = dirname(strdup(argv[0]));
        if (dir[0] == '/') {
            strncpy(g_server_dir, dir, PATH_MAX - 1);
        } else {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                snprintf(g_server_dir, sizeof(g_server_dir), "%s/%s", cwd, dir);
            }
        }
    }

    const char *pdf_path      = NULL;
    const char *dict_path     = NULL;
    const char *charset       = DEFAULT_CHARSET;
    const char *restore_path  = NULL;
    int         brute         = 0;
    int         max_len       = 4;
    int         port          = DEFAULT_PORT;
    int         password_mode = PW_MODE_BOTH;

    const char *mask_str       = NULL;
    int         hybrid_suffix  = 0;
    int         freq_mode_flag = 0;
    int         auto_mode_flag = 0;

    /* Manual long option parsing for --web-port and --auth-token */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--web-port") == 0 && i + 1 < argc) {
            g_web_port = atoi(argv[i + 1]);
            for (int j = i; j + 2 < argc; j++) argv[j] = argv[j + 2];
            argc -= 2;
            i--;
        } else if (strcmp(argv[i], "--auth-token") == 0 && i + 1 < argc) {
            strncpy(g_auth_token, argv[i + 1], sizeof(g_auth_token) - 1);
            g_auth_token[sizeof(g_auth_token) - 1] = '\0';
            for (int j = i; j + 2 < argc; j++) argv[j] = argv[j + 2];
            argc -= 2;
            i--;
        }
    }

    int opt;
    while ((opt = getopt(argc, argv, "f:d:bl:c:p:R:OUm:H:FA")) != -1) {
        switch (opt) {
            case 'f': pdf_path     = optarg;       break;
            case 'd': dict_path    = optarg;       break;
            case 'b': brute        = 1;            break;
            case 'l': max_len      = atoi(optarg); break;
            case 'c': charset      = optarg;       break;
            case 'p': port         = atoi(optarg); break;
            case 'R': restore_path = optarg;       break;
            case 'O': password_mode = PW_MODE_OWNER; break;
            case 'U': password_mode = PW_MODE_USER;  break;
            case 'm': mask_str     = optarg;       break;
            case 'H': hybrid_suffix = atoi(optarg); break;
            case 'F': freq_mode_flag = 1;          break;
            case 'A': auto_mode_flag = 1;          break;
            default:  usage(argv[0]);
        }
    }

    if (!pdf_path)            { fprintf(stderr, "-f required\n");       usage(argv[0]); }
    if (!brute && !dict_path) { fprintf(stderr, "-d or -b required\n"); usage(argv[0]); }

    if (!g_auth_token[0])
        fprintf(stderr, "WARNING: No --auth-token set; HTTP endpoints are unauthenticated\n");

    /* ── Load PDF ──────────────────────────────────────────────── */
    g_pdf_path = pdf_path;
    if (!load_pdf(pdf_path)) return 1;
    fprintf(stderr, "PDF loaded: %s (%ld bytes)\n", pdf_path, g_pdf_size);
    compute_pdf_hash();

    /* ── Detect PDF encryption revision ────────────────────────── */
    {
        PDFEncryptParams enc = pdf_parse_encrypt_file(pdf_path);
        if (enc.valid) {
            g_pdf_revision = enc.revision;
            fprintf(stderr, "Encrypt: R%d (%d-bit key)\n",
                    enc.revision, enc.key_length);
        }
    }

    /* ── Setup mode ────────────────────────────────────────────── */
    g_brute   = brute;
    g_max_len = max_len;
    g_charset = strdup(charset);
    g_cs_len  = (int)strlen(charset);
    g_password_mode = password_mode;
    g_freq_mode = freq_mode_flag;
    if (mask_str) {
        strncpy(g_mask_pattern, mask_str, sizeof(g_mask_pattern) - 1);
        g_attack_mode = ATTACK_MASK;
    } else if (auto_mode_flag) {
        g_attack_mode = ATTACK_AUTO;
    } else if (hybrid_suffix > 0) {
        g_hybrid_suffix_len = hybrid_suffix;
        g_attack_mode = ATTACK_HYBRID;
    } else if (brute) {
        g_attack_mode = ATTACK_BRUTE;
    } else {
        g_attack_mode = ATTACK_DICT;
    }

    if (brute) {
        g_keyspace = total_keyspace(max_len, g_cs_len);
        fprintf(stderr, "Mode   : brute-force (len 1..%d, charset \"%s\")\n",
                max_len, charset);

        char ks_str[32];
        fmt_num(g_keyspace, ks_str, sizeof(ks_str));
        fprintf(stderr, "Keyspace: %s passwords (%ld)\n", ks_str, g_keyspace);
    } else {
        g_dict_path = dict_path ? strdup(dict_path) : NULL;
        if (!load_wordlist(dict_path)) return 1;
        g_keyspace = g_nwords;
        fprintf(stderr, "Mode   : dictionary (%ld words from %s)\n",
                g_nwords, dict_path);
        compute_wordlist_hash();
    }

    /* ── Restore checkpoint if requested ──────────────────────── */
    if (restore_path) {
        if (!restore_checkpoint(restore_path)) {
            fprintf(stderr, "Failed to restore checkpoint\n");
            return 1;
        }
    }

    /* ── Record start time ─────────────────────────────────────── */
    g_start_time = mono_time();

    /* ── Register signal handler ──────────────────────────────── */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* ── Launch background threads ────────────────────────────── */
    pthread_t prog_th, reaper_th, ckpt_th;
    pthread_create(&prog_th,   NULL, progress_thread,   NULL);
    pthread_create(&reaper_th, NULL, reaper_thread,     NULL);
    pthread_create(&ckpt_th,   NULL, checkpoint_thread, NULL);

    /* ── Create listening socket ──────────────────────────────── */
    g_listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listenfd < 0) { perror("socket"); return 1; }

    int yes = 1;
    setsockopt(g_listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(g_listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(g_listenfd, 16) < 0) { perror("listen"); return 1; }

    fprintf(stderr, "\nListening on port %d\n", port);
    fprintf(stderr, "Other Macs can join:  curl http://<this-ip>:%d/join.sh | bash\n", port);

    /* ── Launch web dashboard if requested ─────────────────────── */
    if (g_web_port > 0) {
        pthread_t web_th;
        pthread_create(&web_th, NULL, web_server_thread, NULL);
        pthread_detach(web_th);
    }

    /* ── Register Bonjour/mDNS service ────────────────────────── */
    DNSServiceErrorType mdns_err = DNSServiceRegister(
        &g_mdns_ref, 0, 0, NULL, "_pdfcracker._tcp",
        NULL, NULL, htons((uint16_t)port), 0, NULL, NULL, NULL);
    if (mdns_err == kDNSServiceErr_NoError) {
        fprintf(stderr, "Bonjour: registered _pdfcracker._tcp on port %d\n\n", port);
    } else {
        fprintf(stderr, "Bonjour: registration failed (error %d), continuing without mDNS\n\n",
                mdns_err);
    }

    /* ── Spawn local client (cracks on this machine too) ──────── */
    pid_t local_client_pid = -1;
    {
        /* Find client binary next to server binary */
        char client_path[PATH_MAX];
        char *dir = dirname(strdup(argv[0]));
        snprintf(client_path, sizeof(client_path), "%s/client", dir);

        /* Check client binary exists */
        if (access(client_path, X_OK) == 0) {
            local_client_pid = fork();
            if (local_client_pid == 0) {
                /* Child: exec client */
                char port_str[16];
                snprintf(port_str, sizeof(port_str), "%d", port);
                execl(client_path, "client", "-s", "127.0.0.1", "-p", port_str, NULL);
                _exit(1);  /* exec failed */
            } else if (local_client_pid > 0) {
                fprintf(stderr, "Local worker started (PID %d)\n\n", local_client_pid);
            } else {
                perror("fork");
            }
        } else {
            fprintf(stderr, "Warning: client binary not found at %s — running as coordinator only\n", client_path);
        }
    }

    /* ── Accept loop ──────────────────────────────────────────── */
    while (!g_shutdown && !atomic_load(&g_found)) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int fd = accept(g_listenfd, (struct sockaddr *)&cli_addr, &cli_len);
        if (fd < 0) {
            if (errno == EINTR || g_shutdown) break;
            perror("accept");
            continue;
        }

        /* Disable Nagle */
        int flag = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        /* Pass fd to handler thread */
        int *fdp = malloc(sizeof(int));
        if (!fdp) { close(fd); continue; }
        *fdp = fd;

        pthread_t th;
        pthread_create(&th, NULL, client_handler, fdp);
        pthread_detach(th);
    }

    /* ── Shutdown ─────────────────────────────────────────────── */
    fprintf(stderr, "\nShutting down...\n");
    g_shutdown = 1;
    broadcast_abort();
    save_checkpoint();

    /* Deregister Bonjour */
    if (g_mdns_ref) {
        DNSServiceRefDeallocate(g_mdns_ref);
        g_mdns_ref = NULL;
    }

    /* Stop local client */
    if (local_client_pid > 0) {
        kill(local_client_pid, SIGTERM);
        waitpid(local_client_pid, NULL, 0);
    }

    /* Give threads a moment to finish */
    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);

    /* Signal found to stop progress/reaper threads */
    atomic_store(&g_found, 1);

    fputs("\n\n", stderr);
    atomic_thread_fence(memory_order_acquire);
    if (g_password[0]) {
        printf("Password found: %s\n", g_password);
        printf("Total tested:   %ld\n", atomic_load(&g_total_tested));
    } else {
        printf("Password not found (tested %ld).\n", atomic_load(&g_total_tested));
        printf("Checkpoint saved. Restart with -R to resume.\n");
    }

    close(g_listenfd);
    return g_password[0] ? 0 : 1;
}
