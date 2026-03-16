/*
 * protocol.h — Shared constants and socket helpers for distributed pdfcracker
 *
 * Protocol is text-line-based over TCP, with one binary transfer (the PDF).
 *
 * Session flow:
 *   C→S: HELLO <ncores>
 *   S→C: CONFIG BRUTE <maxlen>      or   CONFIG DICT
 *         CHARSET <charset>               PDF <nbytes>
 *         PDF <nbytes>                    <raw bytes>
 *         <raw bytes>
 *   C→S: READY
 *
 *   [work loop]
 *   C→S: GETWORK <tested_in_prev_chunk>
 *   S→C: BRUTE <length> <start> <end>
 *     or DICT <count>            ← followed by <count> word lines
 *            <word1>
 *            …
 *     or FOUND <password>
 *     or DONE
 *
 *   C→S: FOUND <password>         ← password discovered
 *     or EXHAUSTED                ← chunk done, not found
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define DEFAULT_PORT      9999
#define CHUNK_BRUTE       500000L
#define CHUNK_DICT        5000
#define MAX_PASS_LEN      32
#define MAX_LINE          512
#define MAX_CLIENTS       64
#define DEFAULT_CHARSET   \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

/* ── Read exactly n bytes ─────────────────────────────────────── */
static inline ssize_t read_exact(int fd, void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, (char *)buf + done, n - done);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return (ssize_t)done;
}

/* ── Write exactly n bytes ────────────────────────────────────── */
static inline ssize_t write_exact(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, (const char *)buf + done, n - done);
        if (w <= 0) return -1;
        done += (size_t)w;
    }
    return (ssize_t)done;
}

/* ── Read one text line (up to \n, stripped) ───────────────────── */
static inline int sock_readline(int fd, char *buf, int maxlen)
{
    int i = 0;
    char c;
    while (i < maxlen - 1) {
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

/* ── Send a formatted text line (appends \n) ──────────────────── */
static inline int sock_printf(int fd, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static inline int sock_printf(int fd, const char *fmt, ...)
{
    char buf[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    buf[n++] = '\n';
    buf[n]   = '\0';
    return (write_exact(fd, buf, (size_t)n) > 0) ? n : -1;
}

/* ── Brute-force keyspace math ────────────────────────────────── */
static inline long keyspace_for_length(int len, int cs_len)
{
    long n = 1;
    for (int i = 0; i < len; i++) {
        if (n > (long)2e18 / cs_len) return (long)2e18;
        n *= cs_len;
    }
    return n;
}

static inline long total_keyspace(int max_len, int cs_len)
{
    long total = 0;
    for (int l = 1; l <= max_len; l++)
        total += keyspace_for_length(l, cs_len);
    return total;
}

static inline void index_to_password(long idx, int length,
                                     const char *charset, int cs_len,
                                     char *out)
{
    for (int i = length - 1; i >= 0; i--) {
        out[i] = charset[idx % cs_len];
        idx /= cs_len;
    }
    out[length] = '\0';
}

#endif /* PROTOCOL_H */
