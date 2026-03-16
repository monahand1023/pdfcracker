# Distributed Architecture Overhaul: Implementation Plan (v2)

## Overview

Transform the current fire-and-forget work distribution into a BOINC-style lease-based
system where workers can join/leave freely and no work is ever lost.

Changes touch 3 existing files (`protocol.h`, `server.c`, `client.c`).

### Design Decisions (from review)

1. **No heartbeat thread** — main thread sends heartbeats between chunks. Eliminates
   the socket read-race entirely (one reader, one writer, same thread).
2. **No HAVEPDF/PDFCACHED** — always send the PDF. Not worth the complexity for a
   sub-second transfer on a hours-long job.
3. **PARTIAL sends high-water mark** — `g_next_idx` value, not tested count, so the
   server can split the chunk precisely.
4. **Protocol version in HELLO** — forward compatibility.
5. **Max lease deadline capped at 300s** — prevents slow first-chunk from creating
   15-minute leases.
6. **Wordlist hash in checkpoint** — detects wordlist changes between restarts.
7. **Client slot recycling** — reuse slots from disconnected non-reconnecting clients.
8. **Monotonic clock** for lease deadlines — NTP-safe.
9. **Server SHUTDOWN broadcast** — sends ABORT to all clients before exiting.
10. **Validate word length** on wordlist load — reject lines > MAX_PASS_LEN.

---

## 1. Data Structures

### protocol.h — New Constants

```c
#define PROTO_VERSION       2          /* protocol version */
#define MIN_CHUNK_BRUTE     10000L
#define MAX_CHUNK_BRUTE     5000000L
#define MIN_CHUNK_DICT      500L
#define MAX_CHUNK_DICT      50000L
#define DEFAULT_CHUNK_BRUTE 500000L
#define DEFAULT_CHUNK_DICT  5000L
#define TARGET_SECS         30.0       /* target seconds per chunk */
#define MIN_LEASE_SECS      120
#define MAX_LEASE_SECS      300        /* cap lease deadline */
#define LEASE_MULTIPLIER    3          /* deadline = clamp(elapsed*3, MIN, MAX) */
#define HEARTBEAT_TIMEOUT   60         /* server marks client dead after 60s silence */
#define REAPER_INTERVAL     5
#define CHECKPOINT_INTERVAL 30
#define RECONNECT_BASE_SEC  3
#define RECONNECT_MAX_SEC   60
#define RECONNECT_MAX_TRIES 20
#define UUID_LEN            36
#define SHA256_HEX_LEN      64
#define MAX_LINE            1024       /* bumped from 512 */
```

### protocol.h — New Helpers

```c
/* SHA-256 hex string (uses CommonCrypto) */
static inline void sha256_hex(const void *data, size_t len, char out[SHA256_HEX_LEN+1]);

/* Monotonic time in seconds (NTP-safe) */
static inline double mono_time(void);
```

### server.c — LeaseEntry

```c
typedef struct {
    uint64_t  lease_id;
    int       is_brute;
    int       brute_len;
    long      brute_start, brute_end;
    long      dict_start, dict_count;
    double    deadline;        /* monotonic time */
    int       client_idx;
    long      tested_so_far;
    double    last_heartbeat;  /* monotonic time */
    int       active;          /* 1=assigned, 0=completed/expired */
} LeaseEntry;
```

### server.c — RequeueNode

```c
typedef struct RequeueNode {
    int       is_brute;
    int       brute_len;
    long      brute_start, brute_end;
    long      dict_start, dict_count;
    struct RequeueNode *next;
} RequeueNode;
```

### server.c — Enhanced ClientInfo

```c
typedef struct {
    int       fd;
    int       id;
    int       cores;
    int       active;          /* 1=connected, 0=disconnected */
    int       slot_free;       /* 1=slot can be reused by new client */
    long      tested;          /* cumulative across reconnections */
    char      uuid[UUID_LEN + 1];
    char      ip_str[INET_ADDRSTRLEN];
    double    speed;           /* passwords/sec */
    long      chunk_size;      /* adaptive next chunk size */
    uint64_t  current_lease_id;
    double    last_seen;       /* monotonic time of last message */
} ClientInfo;
```

---

## 2. Protocol (v2)

```
Handshake:
  C→S: HELLO <ncores> <uuid> <proto_version>
  S→C: CONFIG BRUTE <maxlen>
       CHARSET <charset>
       PDF <nbytes>
       <raw bytes>
    or CONFIG DICT
       PDF <nbytes>
       <raw bytes>
  C→S: READY

Work loop:
  C→S: GETWORK <tested> <elapsed_secs>
  S→C: BRUTE <len> <start> <end> <lease_id>
    or DICT <count> <lease_id>
       <word1>
       <word2>
       ...
    or FOUND <password>
    or DONE
    or ABORT                        (password found while client was idle)

  C→S: HEARTBEAT <lease_id> <tested_so_far>
  S→C: OK
    or ABORT                        (stop work, password found)

  C→S: COMPLETE <lease_id> <tested>
  C→S: PARTIAL <lease_id> <high_water_mark>   (graceful shutdown / disconnect)
  C→S: FOUND <password> <lease_id>
```

### Key protocol rules:
- **Single-threaded I/O on client**: main thread is sole reader AND writer. No socket
  sharing between threads. Heartbeats sent by main thread between chunks.
- **Server sends no unsolicited messages** during a lease. All server→client messages
  are responses to client requests.
- **ABORT can appear as response to GETWORK or HEARTBEAT** — tells client to stop.

### Heartbeat timing (no separate thread):
The client sends HEARTBEAT between chunk completions when chunks are long. For short
chunks (~30s target), the GETWORK message itself serves as a heartbeat (server updates
`last_seen` on any message). The HEARTBEAT_TIMEOUT (60s) is set well above the target
chunk time (30s) to accommodate this.

For very long chunks (e.g., slow client, first chunk), the client can optionally send
HEARTBEAT mid-chunk by having a worker thread set a flag, and the main thread polls
a non-blocking read for ABORT periodically. But for v1, we simply rely on the lease
deadline and reaper — if a client goes silent for 60s, the lease expires. This is
simpler and sufficient.

---

## 3. Thread Model

### Server Threads

| Thread | Purpose | Lifetime |
|--------|---------|----------|
| **main** | Accept loop, spawns client handlers | Process |
| **client_handler** (per client) | Handshake + work loop | Per-connection |
| **reaper_thread** (1) | Expire stale leases every 5s | Process |
| **checkpoint_thread** (1) | Save state every 30s | Process |
| **progress_thread** (1) | Display stats every 1s | Process |

### Client Threads

| Thread | Purpose | Lifetime |
|--------|---------|----------|
| **main** | reconnect_loop → run_session (handshake + work dispatch + heartbeats) | Process |
| **brute/dict workers** (N) | CPU cracking | Per-chunk |
| **gpu_worker** (0 or 1) | GPU cracking (R2-R4 only) | Per-chunk |

### Synchronization (server)

- `g_lease_lock` — protects lease array
- `g_work_lock` — protects cursor + requeue list
- `g_clients_lock` — protects client array

### Synchronization (client)

- None needed for socket — main thread is sole reader/writer
- Existing atomics for worker coordination (`g_chunk_found`, `g_chunk_tested`, `g_next_idx`)

---

## 4. Key Functions

### server.c — New

```c
/* PDF/wordlist hashing */
static void compute_pdf_hash(void);
static void compute_wordlist_hash(void);

/* Requeue management (caller holds g_work_lock) */
static void push_requeue_brute(int len, long start, long end);
static void push_requeue_dict(long start, long count);
static int  pop_requeue(int *is_brute, int *brute_len,
                        long *start, long *end, long *dict_count);

/* Lease management (caller holds g_lease_lock) */
static uint64_t create_lease(int client_idx, int is_brute,
                             int brute_len, long start, long end,
                             long dict_start, long dict_count,
                             int deadline_secs);
static void complete_lease(uint64_t lease_id, long final_tested);
static void expire_lease(uint64_t lease_id);

/* Work assignment — checks requeue first, then cursor */
static uint64_t assign_work(ClientInfo *ci, int *is_brute,
                            int *out_len, long *out_start, long *out_end,
                            long *out_dict_start, long *out_dict_count);

/* Background threads */
static void *reaper_thread(void *arg);
static void *checkpoint_thread(void *arg);

/* Checkpoint I/O */
static void save_checkpoint(void);
static int  restore_checkpoint(const char *path);

/* Client management */
static int  find_client_by_uuid(const char *uuid);
static int  alloc_client_slot(void);  /* reuses free slots */

/* Shutdown */
static void broadcast_abort(void);
static void sigint_handler(int sig);

/* Formatting */
static void fmt_num(long n, char *buf, size_t sz);
static void fmt_time(long secs, char *buf, size_t sz);
```

### client.c — New

```c
static void ensure_uuid(void);
static int  run_session(const char *host, int port);  /* 0=done, 1=retry, 2=shutdown */
static int  reconnect_loop(const char *host, int port);
static void sigint_handler(int sig);
```

---

## 5. Implementation Phases

### Phase A: Protocol Foundation (protocol.h)
1. Bump MAX_LINE to 1024
2. Add new constants (chunk sizing, lease, reconnect, UUID, SHA256)
3. Add `_Static_assert(sizeof(long) >= 8, "64-bit long required")`
4. Add `sha256_hex()` using CC_SHA256
5. Add `mono_time()` using clock_gettime(CLOCK_MONOTONIC)
6. Update protocol comment block

### Phase B: Server — Lease Infrastructure (server.c)
1. Add LeaseEntry, RequeueNode structs and globals
2. Enhanced ClientInfo with uuid, ip_str, speed, chunk_size, slot_free
3. `alloc_client_slot()` — scans for slot_free=1, else appends
4. Implement requeue push/pop
5. Implement create_lease/complete_lease/expire_lease
   - `complete_lease()` checks requeue list for the same chunk and removes it
     (handles the race where reaper expired a lease that was actually completing)
6. Implement `assign_work()`:
   - Lock g_work_lock, try pop_requeue first
   - If empty, generate new chunk from cursor (next_brute_chunk/next_dict_chunk)
   - Chunk size from ci->chunk_size (adaptive) or DEFAULT
   - Lock g_lease_lock, create_lease
   - Return lease_id
7. Modify next_brute_chunk/next_dict_chunk to accept chunk_size parameter

### Phase C: Server — Reaper Thread
1. Implement reaper_thread: every REAPER_INTERVAL seconds
   - Scan active leases, check mono_time() > deadline
   - Also check client last_seen: if > HEARTBEAT_TIMEOUT, expire lease
   - Call expire_lease() which pushes to requeue
2. Launch from main()

### Phase D: Server — Updated Client Handler
1. Parse `HELLO <ncores> <uuid> <proto_version>`
   - find_client_by_uuid() for reconnecting clients (reuse slot)
   - Reject incompatible proto_version
2. Always send PDF (no HAVEPDF/PDFCACHED)
3. Work loop handles:
   - `GETWORK <tested> <elapsed>` — compute speed, adaptive chunk size,
     call assign_work(), send response with lease_id
   - `HEARTBEAT <lease_id> <tested>` — update last_seen + tested_so_far,
     respond OK or ABORT
   - `COMPLETE <lease_id> <tested>` — call complete_lease(), credit tested
   - `PARTIAL <lease_id> <hwm>` — credit tested portion, expire_lease()
     with adjusted start (brute_start + hwm) for precise re-queue
   - `FOUND <password> <lease_id>` — set g_found, store password

### Phase E: Server — Checkpoint
1. compute_pdf_hash() and compute_wordlist_hash() at startup
2. save_checkpoint() — text format:
   ```
   PDFCRACKER_CHECKPOINT v1
   pdf_sha256 <hex>
   wordlist_sha256 <hex>
   mode brute|dict
   charset <chars>
   max_len <n>
   brute_cursor <len> <idx>
   dict_cursor <idx>
   total_tested <n>
   keyspace <n>
   lease <lease_id> <type> <brute_len> <start> <end> <dict_start> <dict_count>
   ...
   END
   ```
3. restore_checkpoint() — verify pdf + wordlist hashes, restore cursors,
   push saved leases into requeue
4. checkpoint_thread — every CHECKPOINT_INTERVAL seconds
5. SIGINT handler — broadcast_abort() to all clients, save_checkpoint(), exit
6. Add `-R <ckpt>` flag

### Phase F: Server — Enhanced Progress
1. Add fmt_num(), fmt_time()
2. Rewrite progress_thread with per-client table:
   ```
   [3 clients] 45.2% complete  1.2M/s aggregate  ETA 2h15m
     #0  192.168.1.5   8 cores  450K/s  lease 47  12.3M tested  2s ago
     #1  192.168.1.8   4 cores  210K/s  lease 48   5.1M tested  1s ago
     #2  192.168.1.12 16 cores  890K/s  lease 49  28.7M tested  3s ago
   ```

### Phase G: Client — UUID + Reconnect
1. ensure_uuid() — generate from /dev/urandom or load from ~/.pdfcracker_id
2. Extract main() body into run_session()
   - Returns 0 (done/found), 1 (disconnected, retry), 2 (shutdown)
3. reconnect_loop() with exponential backoff (3, 6, 12, 24, 48, 60, 60...)
4. New main() = parse args + ensure_uuid + reconnect_loop
5. Send `HELLO <ncores> <uuid> <PROTO_VERSION>` in handshake

### Phase H: Client — Lease-Aware Work Loop
1. Parse lease_id from BRUTE/DICT responses
2. Track wall-clock time per chunk
3. Send `COMPLETE <lease_id> <tested>` on chunk finish
4. Send `GETWORK <tested> <elapsed_secs>` for next chunk
5. Between chunks: if chunk took > 30s, send HEARTBEAT before GETWORK
   (keeps server's last_seen fresh for long chunks)

### Phase I: Client — Graceful Shutdown
1. SIGINT handler sets g_shutdown_requested + g_chunk_found (stops workers)
2. After workers stop, send `PARTIAL <lease_id> <g_next_idx>` (high-water mark)
3. run_session() returns 2, reconnect_loop exits

---

## 6. Edge Cases and Mitigations

| Scenario | Mitigation |
|----------|------------|
| Client dies mid-chunk | Reaper expires lease after deadline, chunk re-queued |
| Reaper expires lease while COMPLETE in transit | complete_lease() removes chunk from requeue list if present |
| Two clients find password simultaneously | atomic_exchange on g_found, only first password stored, both get OK |
| Server restarts | Clients reconnect via UUID, re-receive PDF, get new work. Checkpoint re-queues in-flight chunks |
| Wordlist changes between restarts | Checkpoint stores wordlist SHA-256, restore refuses if mismatch |
| Client slot exhaustion | alloc_client_slot() recycles slots where slot_free=1 |
| First chunk very slow (GPU compilation) | Lease deadline capped at MAX_LEASE_SECS=300s. Speed measured from second chunk onwards |
| Requeue list grows unbounded (no clients) | Reaper only expires leases of connected clients. If client disconnects, lease is expired once and chunk re-queued once |
| sock_printf truncates long lines | Validate word length on wordlist load, reject > MAX_PASS_LEN |
| NTP clock jump | All deadlines use monotonic clock |
| Server shutdown | broadcast_abort() sends ABORT to all clients, save checkpoint, exit |

---

## 7. Testing Plan

1. **Basic lease flow**: Start server + 1 client, verify chunks get lease_ids, COMPLETE works
2. **Lease expiry**: Start client, kill it mid-chunk (kill -9), verify reaper re-queues, second client gets the work
3. **Reconnect**: Start client, kill server, restart server with -R, verify client reconnects and work continues
4. **Adaptive sizing**: Connect slow client (limit to 1 thread), then fast client (all cores), verify chunk sizes differ
5. **Graceful shutdown**: Ctrl+C client mid-chunk, verify PARTIAL sent, chunk re-queued
6. **Multi-client**: 3+ clients, verify no duplicate work, all chunks completed
7. **Found broadcast**: One client finds password, verify all others get ABORT and stop
8. **Server checkpoint**: Kill server (kill -9), restore with -R, verify no work lost
