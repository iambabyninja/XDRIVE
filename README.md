# XDRIVE PROPOSAL

XDRIVE - A transport layer that uses cloud storage services as a communication channel.

-----

## Table of Contents

- [Context and Goals](#context-and-goals)
- [Threat Model](#threat-model)
- [Data Model](#data-model)
  - [File Key](#file-key)
  - [Wire Format](#wire-format)
  - [Discovery File](#discovery-file)
- [DriveService Interface](#driveservice-interface)
  - [FileRef Translation per Backend](#fileref-translation-per-backend)
- [Circuit Breaker](#circuit-breaker-per-session)
- [Writer](#writer)
  - [Lifecycle](#lifecycle)
  - [Dynamic Chunking](#dynamic-chunking)
  - [Write()](#write-bounded-buffer)
  - [Writer Goroutine Algorithm](#writer-goroutine-algorithm)
  - [Graceful Close (FIN)](#graceful-close-fin)
- [Reader](#reader)
  - [Lifecycle](#lifecycle-1)
  - [Algorithm Selection](#algorithm-selection)
  - [Sequential Reader](#sequential-reader-strong-consistency)
  - [Out-of-Order Reader](#out-of-order-reader-eventual-consistency)
  - [Parallel Probe](#parallel-probe-fail-fast-sequential-reader-only)
  - [Read()](#read-leftover-buffer-management)
- [Async Delete Worker](#async-delete-worker)
- [Server Discovery](#server-discovery)
  - [Client Session Establishment](#client-session-establishment)
  - [Discovery Loop + Admission Control](#discovery-loop--admission-control)
  - [Startup GC](#startup-gc)
  - [Periodic GC](#periodic-gc)
- [Session Management](#session-management)
- [Thundering Herd Mitigation](#thundering-herd-mitigation)
- [Memory Management](#memory-management)
- [PRNG](#prng)
- [Full Exchange Diagram](#full-exchange-diagram)
- [Configuration Parameters](#configuration-parameters)
- [Backend Priority](#backend-priority)
- [Implementation Notes](#implementation-notes)
  - [§1 - Context Isolation](#1---context-isolation)
  - [§2 - Two Separate PRNGs](#2---two-separate-prngs)
  - [§3 - Clock Skew in Discovery](#3---clock-skew-in-discovery)
  - [§4 - Per-Connection Read Buffer](#4---per-connection-read-buffer)
  - [§5 - Write() on Buffer Full](#5---write-on-buffer-full)
  - [§6 - Wire Format Validation](#6---wire-format-validation)
  - [§7 - Probe: Gap vs Stall](#7---probe-gap-vs-stall)
  - [§8 - Google Drive: Hybrid Download](#8---google-drive-hybrid-download)
  - [§9 - S3 DeleteObjects](#9---s3-deleteobjects)
  - [§10 - Memory Requirements](#10---memory-requirements)
- [Intentionally Excluded](#intentionally-excluded)

-----

## Context and Goals

XDRIVE allows two nodes to communicate through files stored in a cloud storage service (Google Drive, S3, WebDAV, FTP, Local FS). This provides three properties that classical transports cannot achieve:

- No public IP: the server can sit behind NAT or on a home network.
- No direct TCP connection: the censor sees only HTTPS traffic to the cloud storage domain.

All user traffic is multiplexed into a single XDRIVE connection per session. Multiplexing is handled by Xray itself - XDRIVE is a simple bidirectional pipe (`io.ReadWriteCloser`). Writer and Reader are independent goroutines with independent file namespaces (`c2s` / `s2c`), providing full-duplex operation without mutual blocking.

-----

## Threat Model

XDRIVE protects against IP-based censorship (IP whitelisting). The following threats are out of scope and must be explicitly documented:

**Compromised storage account.** If the censor gains access to the account (subpoena, breach), session metadata (timings, file sizes, packet counts) is exposed. Payload remains protected by TLS inside the files.

**Timing analysis.** The regular Upload/Download pattern is visible as a cloud-sync client signature. Jitter reduces precision but does not eliminate correlation.

**Attacker with write access to storage.** Per-file HMAC protects against content substitution. Deletion of legitimate files by an attacker produces ErrNotExist and triggers reconnect - this is a DoS, not a data compromise.

-----

## Data Model

### File Key

```
{sessionID}/{direction}/{seq}

sessionID   UUIDv4, unique per session
direction   c2s (client -> server) | s2c (server -> client)
seq         uint64, monotonic counter starting at zero
```

`seq = uint64_max` is the FIN marker. Invariant: no data packet may have `seq == uint64_max`.

```
550e8400-e29b-41d4-a716-446655440000/c2s/0
550e8400-e29b-41d4-a716-446655440000/c2s/1
550e8400-e29b-41d4-a716-446655440000/c2s/18446744073709551615  <- FIN
```

### Wire Format

Data packet (`seq < uint64_max`):

```
+----------------------------------------------------+
|  2 bytes  : uint16 big-endian, payload length (L) |
|  L bytes  : Xray mux frames (TLS-encrypted)        |
|  16 bytes : HMAC-SHA256(fileKey, data[:2+L])[:16]  |
|  N bytes  : random padding (per-goroutine PRNG)    |
+----------------------------------------------------+

fileKey = HMAC-SHA256(sharedSecret, sessionID + direction + seq_big_endian)[:32]
```

FIN packet (`seq == uint64_max`):

```
+----------------------------------------------------------+
|  8 bytes  : uint64 big-endian, lastDataSeq              |
|  16 bytes : HMAC-SHA256(fileKey, lastDataSeq_bytes)[:16]|
+----------------------------------------------------------+
```

`lastDataSeq` lets the OOO Reader know how many packets to wait for before graceful close.

Receiver - mandatory validation sequence (see §6):

1. `if len(data) < 2` -> partial read error, retry
2. `payloadLen = uint16(data[0:2])`
3. `if payloadLen > maxChunkSize` -> malformed, close session
4. `if len(data) < 2 + int(payloadLen) + 16` -> partial read error, retry
5. Verify HMAC: if mismatch -> reject, close session

### Discovery File

```
_new/{quantized_min}_{hmac16}
```

sessionID is removed from the filename - it lives inside the encrypted payload. A passive observer sees only the timestamp (rounded to the minute) and the HMAC. Without knowing sharedSecret, the observer cannot locate data files at `{sessionID}/c2s/*`.

```
hmac16 = lowercase_hex(HMAC-SHA256(sharedSecret, quantized_min_decimal)[:8])
```

Filename format:

```
regex: ^_new/[0-9]+_[0-9a-f]{16}$
```

Discovery file payload:

```
+----------------------------------------------------+
|  36 bytes : sessionID (UUID RFC 4122, plaintext)  |
|  ...      : first data packet (wire format)        |
+----------------------------------------------------+
```

The server reads the payload, extracts sessionID, then validates the wire format of the first packet.

The timestamp is quantized to the minute to eliminate a millisecond-precision timing side-channel. To determine freshness, the server uses `Last-Modified` from cloud metadata, not the client-side timestamp.

**The discovery file payload is the first data packet (c2s/0).** This merges session establishment and the first data transfer into a single atomic operation.

-----

## DriveService Interface

```go
type FileRef struct {
    Session   string // sessionID
    Direction string // "c2s" | "s2c"
    Seq       uint64 // uint64_max = FIN
}

type FileInfo struct {
    Ref        FileRef
    ServerTime time.Time // from cloud Last-Modified metadata
    Data       []byte
}

// ConsistencyMode describes storage guarantees for list read-after-write operations.
// Google Drive: EventualConsistency for files.list(),
// but Strong for files.get(fileId) - see §8.
type ConsistencyMode int

const (
    StrongConsistency   ConsistencyMode = iota
    EventualConsistency
)

type DriveService interface {
    Login(ctx context.Context) error
    Consistency() ConsistencyMode

    // Hot path
    Upload(ctx context.Context, ref FileRef, data []byte) error
    Download(ctx context.Context, ref FileRef) ([]byte, error) // os.ErrNotExist if missing
    Delete(ctx context.Context, ref FileRef) error
    BatchDelete(ctx context.Context, refs []FileRef) error

    // Cold path
    // pageSize limits one page of results (DDoS protection against garbage discovery files)
    ListNew(ctx context.Context, within time.Duration, pageSize int) ([]FileInfo, error)
    CleanupSession(ctx context.Context, sessionID string) error
}
```

`ListNew` accepts `pageSize`: the driver requests at most `pageSize` files per HTTP request (S3: `MaxKeys`, GDrive: `pageSize`). The Discovery Loop calls `ListNew(pageSize=maxNewSessionsPerCycle*2)`.

### FileRef Translation per Backend

|Backend     |Upload / Download / Delete                      |CleanupSession                          |
|------------|------------------------------------------------|----------------------------------------|
|S3          |key = `{session}/{direction}/{seq}`             |ListPrefix -> BatchDeleteObjects x retry|
|WebDAV      |path = `/{folder}/{session}/{direction}/{seq}`  |DELETE session folder                   |
|Google Drive|fileId from cache + search inside folder        |DELETE session folder                   |
|Local FS    |`filepath.Join(folder, session, direction, seq)`|`os.RemoveAll`                          |

**S3 CleanupSession** is a composite non-transactional operation. It is called only after two-sided close (both FINs received or idleTimeout elapsed). Repeat `ListPrefix` after each `BatchDeleteObjects` until `count == 0`, maximum 5 iterations with a 5s pause. S3 Object Expiration Rules serve as a safety net. **This cleanup is best-effort, not guaranteed**: some S3-compatible implementations (notably MinIO under concurrent load) may return already-deleted keys in a subsequent ListPrefix due to internal replication lag. The 5-iteration limit prevents infinite loops; any residual objects will be collected by Object Expiration or the next Startup/Periodic GC.

-----

## Circuit Breaker (per-session)

CB is per-session, not global. A global CB allows one degrading session to block all others.

```
Closed:    all calls pass through normally
           5 errors in sliding window 10s (429 / 5xx) -> Open
           429 with Retry-After header -> use Retry-After as cooldown directly

Open:      all calls immediately return ErrCircuitOpen
           after cooldownPeriod -> Half-Open

Half-Open: allows up to 3 probe calls
           all 3 succeed -> Closed
           any failure -> Open
```

|Parameter         |Default|
|------------------|-------|
|`failureWindow`   |10s    |
|`failureThreshold`|5      |
|`cooldownPeriod`  |30s    |
|`halfOpenProbes`  |3      |

-----

## Writer

### Lifecycle

Writer is a dedicated goroutine on `XdriveConnection`. It uses `writerCtx` derived from `Server.bgCtx`, not from the Xray session context. It exits on `conn.Close()` or `Server.Close()`.

### Dynamic Chunking

```
nextSize = clamp(
    throughputBytesPerSec / targetRPS,
    minChunkSize,   // 32 KB
    maxChunkSize    // 4 MB
)
```

`throughputBytesPerSec` is a sliding average of flush volumes over the last 3 seconds.

### Write() (bounded buffer)

```go
func (c *XdriveConnection) Write(p []byte) (int, error) {
    c.writeMu.Lock()
    defer c.writeMu.Unlock()

    if c.closed {
        return 0, io.ErrClosedPipe
    }
    if len(c.writeBuf)+len(p) > c.maxWriteBufSize {
        return 0, ErrWriteBufferFull
    }
    c.writeBuf = append(c.writeBuf, p...)
    return len(p), nil
}
```

`maxWriteBufSize = 2 x maxChunkSize` (default 8 MB). `ErrWriteBufferFull` closes the specific virtual stream; other streams continue unaffected.

### Writer Goroutine Algorithm

`writeBuf` is not cleared until Upload is confirmed successful. This prevents seq desync: if the client times out while the server has already written the file (WebDAV, FTP), the next flush will not overwrite the same seq with different data.

```
sessionSeed ← int64(binary.BigEndian.Uint64([]byte(sessionID[:8])))
secretSeed  ← int64(binary.BigEndian.Uint64(HMAC-SHA256(sharedSecret, []byte("prng"))[:8]))
writerRng   ← rand.New(rand.NewSource(
    time.Now().UnixNano() ^ int64(os.Getpid()) ^ sessionSeed ^ secretSeed))

// Client: writeSeq starts at 1 (c2s/0 was sent inside the discovery file).
// Server: writeSeq starts at 0 (s2c/0 is the first regular upload).
writeSeq    ← 1  // client side; server side initializes to 0
inflight    ← []byte(nil)   // data for the current in-flight Upload
inflightSeq ← uint64(0)

loop:
    // If there is an unconfirmed Upload - complete it first
    if inflight != nil:
        err ← service.Upload(writerCtx, FileRef{session, myDirection, inflightSeq}, inflight)
        if err != nil:
            sleep(retryDelay)  // exponential backoff
            continue
        writeSeq++
        updateThroughput(len(inflight))
        inflight = nil
        sleep(nextInterval)
        continue

    nextSize     ← computeNextSize()
    flushTimer   ← time.NewTimer(maxFlushDelay)  // 500ms
    nextInterval ← baseInterval + writerRng.Int63n(2*jitter) - jitter

    wait until len(writeBuf) >= nextSize OR flushTimer fires

    flushTimer.Stop()

    writeMu.Lock()
    if writeBuf is empty:
        writeMu.Unlock()
        sleep(nextInterval)
        continue

    inflight = make([]byte, len(writeBuf))
    copy(inflight, writeBuf)
    writeBuf = writeBuf[:0]   // cleared immediately after copy into inflight
    writeMu.Unlock()

    inflightSeq = writeSeq
    buf         ← chunkPool.Get()
    frame       ← wrapWithHMAC(buf, inflight, writeSeq, writerRng)
    err         ← service.Upload(writerCtx, FileRef{session, myDirection, writeSeq}, frame)
    chunkPool.Put(buf)

    if err != nil:
        // Do NOT increment writeSeq. inflight is kept for retry.
        sleep(retryDelay)
        continue

    writeSeq++
    updateThroughput(len(inflight))
    inflight = nil
    sleep(nextInterval)
```

`writeBuf` is cleared immediately after copying into `inflight`, so `Write()` can continue accepting data while the Upload is in progress. `inflight` holds the data until confirmation.

### Graceful Close (FIN)

FIN payload encodes `writeSeq` - the total number of confirmed data uploads at the time FIN is sent. This is the value of `writeSeq` after all data uploads are confirmed and before the FIN upload itself. FIN does not increment `writeSeq`.

```
// writeSeq at this point = number of confirmed data packets
finPayload = uint64_big_endian(writeSeq)
finHmac    = HMAC-SHA256(fileKey(uint64_max), finPayload)[:16]
service.Upload(bgCtx, FileRef{session, myDirection, uint64_max}, finPayload + finHmac)
// writeSeq is NOT incremented after FIN upload
```

Zero-data case: client `writeSeq=1` after discovery (c2s/0 sent), but then no further data was written before close. `finPayload=1`, OOO Reader closes when `readSeq >= 1`, i.e. after receiving exactly c2s/0 via `injectFirstPacket`. If the server sends no data at all: `writeSeq=0`, `finPayload=0`, OOO Reader closes immediately at `readSeq=0 >= 0`.

-----

## Reader

### Lifecycle

Reader is a dedicated goroutine on `XdriveConnection`. It uses `readerCtx` derived from `Server.bgCtx`.

### Algorithm Selection

```go
switch service.Consistency() {
case StrongConsistency:
    go c.runSequentialReader()
case EventualConsistency:
    go c.runOutOfOrderReader()
}
```

OneDrive returns `StrongConsistency`. Empirical verification is required: direct `GET /items/{id}/content` must be immediately consistent after `PUT` before using OneDrive with Sequential Reader in production.

### Sequential Reader (Strong Consistency)

```
readerRng   ← rand.New(rand.NewSource(^(time.Now().UnixNano() ^ sessionSeed ^ secretSeed)))
currentPoll ← pollMin

loop:
    data, err ← service.Download(readerCtx, FileRef{session, theirDirection, readSeq})

    if err == ErrNotExist:
        currentPoll = min(currentPoll x pollFactor, pollMax)
        sleep(currentPoll)
        continue

    if err != nil:
        return err

    // Validation (§6, mandatory sequence):
    if len(data) < 2: partial read, retry
    payloadLen ← uint16(data[0:2])
    if payloadLen > maxChunkSize: malformed, close session
    if len(data) < 2 + int(payloadLen) + 16: partial read, retry
    check HMAC: if fail -> close session

    if readSeq == uint64_max:  // FIN
        // Sequential Reader: if readSeq has reached FIN,
        // all preceding seq have already been processed by definition.
        // FIN payload carries writeSeq (packet count) for consistency with OOO Reader,
        // but Sequential Reader does not need it - ordering is guaranteed.
        initiate graceful close
        return

    currentPoll ← pollMin
    payload     ← data[2 : 2+payloadLen]
    enqueueDelete(FileRef{session, theirDirection, readSeq})
    readSeq++
    lastSuccessfulRead ← time.Now()
    send to readCh
```

### Out-of-Order Reader (Eventual Consistency)

`ooTimeout` is configured per-backend. GDrive default: 120s (consistency lag up to one hour in shared drives).

```
outOfOrderBuf   ← map[uint64]chunkData
expectedPktCount ← uint64_max  // unknown until FIN is received
finReceived      ← false
maxLookahead     ← 8
ooProbe          ← make(chan struct{}, maxLookahead+1)  // semaphore: max concurrent probeOOO

loop:
    // Probe window [readSeq .. readSeq+maxLookahead]
    for seq in window not in outOfOrderBuf:
        select {
        case ooProbe <- struct{}{}:
            go func(s uint64):
                defer func() { <-ooProbe }()
                probeOOO(s, context.WithTimeout(readerCtx, 3s))
            (seq)
        default:
        }

    // Probe FIN in parallel
    if !finReceived:
        select {
        case ooProbe <- struct{}{}:
            go func():
                defer func() { <-ooProbe }()
                probeOOO(uint64_max, context.WithTimeout(readerCtx, 3s))
        default:
        }

    if outOfOrderBuf[readSeq] exists:
        send to readCh
        delete(outOfOrderBuf[readSeq])
        readSeq++
        lastSuccessfulRead ← time.Now()
        continue

    // FIN handling: readSeq == expectedPktCount means all packets delivered
    // (readSeq is the count of delivered packets, expectedPktCount is the total sent)
    if finReceived && readSeq >= expectedPktCount:
        initiate graceful close
        return

    if time.Since(lastSuccessfulRead) > ooTimeout:
        close session -> reconnect

    sleep(pollMin)
```

When FIN is received via `probeOOO(uint64_max)`:

```
pktCount         ← uint64_big_endian(data[0:8])  // total packets sent by remote
expectedPktCount ← pktCount
finReceived      ← true
// Example: remote sent 5 packets (seq 0..4), pktCount=5.
// OOO Reader closes when readSeq >= 5, i.e. after all 5 are delivered.
// Zero-data case: pktCount=0, readSeq=0 >= 0 -> closes immediately.
```

### Parallel Probe (Fail-Fast, Sequential Reader Only)

Probe detects a **gap** (seq=N is missing while seq=N+1 already exists), not a stall (Writer has not yet written seq=N+1). See §7.

```
probeSem ← make(chan struct{}, 1)

on each miss of readSeq:
    select {
    case probeSem <- struct{}{}:
        go func():
            defer func() { <-probeSem }()
            probeCtx ← context.WithTimeout(readerCtx, probeTimeout)
            _, err ← service.Download(probeCtx, FileRef{session, theirDirection, readSeq+1})
            if err != ErrNotExist:
                signal gapDetected
    default:
        // previous probe still running
    }
```

On `gapDetected` and `time.Since(lastSuccessfulRead) > stallTimeout` -> close session -> reconnect.

`stallTimeout=5s` is intentionally aggressive for Sequential Reader (Strong Consistency backends). A gap on a strong-consistency backend means the file is genuinely lost, not just delayed - jitter is 30ms so a 5s window is more than sufficient. Probe is **not used in OOO Reader**: eventual consistency backends (GDrive) handle delays via `ooTimeout=120s`, and the 8-slot lookahead window already covers out-of-order arrival. Adding probe to OOO Reader would produce false positives on backends where multi-second list delays are normal.

### Read() (leftover buffer management)

`heldBuf` is replaced by a per-connection pre-allocated `readBuf` (§4). Pool is used only for the Writer.

```go
func (c *XdriveConnection) Read(b []byte) (int, error) {
    if len(c.readLeftover) > 0 {
        n := copy(b, c.readLeftover)
        c.readLeftover = c.readLeftover[n:]
        return n, nil
    }

    select {
    case chunk := <-c.readCh:
        n := copy(b, chunk.payload)
        if n < len(chunk.payload) {
            c.readLeftover = chunk.payload[n:]
        }
        return n, nil
    case <-c.readerCtx.Done():
        return 0, io.EOF
    }
}
```

`c.readBuf` is pre-allocated as `make([]byte, maxChunkSize+maxPadding+18)` at `XdriveConnection` creation. It lives for the entire duration of the connection. This eliminates use-after-free through `sync.Pool` when leftover data is held across Read() calls.

-----

## Async Delete Worker

A single goroutine at the `Server` level. Uses `Server.bgCtx`.

```
loop:
    sleep(deleteWorkerInterval)   // 1s

    batch ← dequeue(up to deleteBatchSize from globalDeleteQueue)
    if batch is empty: continue

    opCtx ← context.WithTimeout(bgCtx, 10s)
    err   ← service.BatchDelete(opCtx, batch)
    if err: return batch to queue with retry delay
```

-----

## Server Discovery

### Client Session Establishment

```
1. Generate sessionID = UUIDv4
2. quantized_min = strconv.FormatInt(time.Now().Unix()/60*60, 10)
3. hmac16 = lowercase_hex(HMAC-SHA256(sharedSecret, quantized_min)[:8])
4. Create session folder (for WebDAV / GDrive)
5. firstData = wrapWithHMAC(firstChunk)   // this IS c2s/0
6. discoveryPayload = sessionID_bytes(36) + firstData
7. Upload(_new/{quantized_min}_{hmac16}, discoveryPayload)
   // If Upload fails - restart with a new sessionID
8. writeSeq = 1
   // c2s/0 was delivered via discovery file, not as a separate storage object.
   // Writer must start at seq=1. Starting at 0 would either duplicate c2s/0 in
   // storage or collide with the server's injectFirstPacket on readSeq=0.
```

### Discovery Loop + Admission Control

```
newThisCycle  ← 0
newThisMinute ← 0
minuteReset   ← time.NewTicker(1m)

every 500ms:
    select { case <-minuteReset.C: newThisMinute = 0; default: }

    if currentRPS > maxRPS x admissionMaxRPSRatio:
        continue

    files ← service.ListNew(ctx, within=10m, pageSize=maxNewSessionsPerCycle*2)

    for each file:
        if newThisCycle >= maxNewSessionsPerCycle: break
        if newThisMinute >= maxNewSessionsPerMinute: break

        // Step 1: filename format
        if !matchRegex(file.Name, `^_new/[0-9]+_[0-9a-f]{16}$`):
            enqueueDelete(file)
            continue

        quantizedMin, hmac16 ← parse(file.Name)

        // Step 2: filename HMAC
        expected ← lowercase_hex(HMAC-SHA256(sharedSecret, quantizedMin)[:8])
        if hmac16 != expected:
            enqueueDelete(file)
            continue

        // Step 3: freshness
        if file.ServerTime.Before(now - staleThreshold):
            enqueueDelete(file)
            continue

        // Step 4: payload extraction
        if len(file.Data) < 36 + 2:
            // Payload is too short to contain a valid sessionID + wire format header.
            // On eventual-consistency backends (GDrive) ListNew may return a file
            // before it is fully written - this is a partial read at the discovery layer.
            // There is no retry here: enqueue for deletion and skip. The client will
            // not receive s2c/0 within deadTimeout=30s and will restart with a new sessionID.
            // This is correct behavior: a lost discovery file is cheaper than a stuck session.
            enqueueDelete(file)
            continue

        sessionID   ← string(file.Data[:36])
        firstPacket ← file.Data[36:]

        if !isValidUUID(sessionID):
            enqueueDelete(file)
            continue

        if sessionID already in sessions: skip

        conn ← newXdriveConnection(sessionID, isServer=true)
        conn.sessionClosed = false
        conn.injectFirstPacket(firstPacket)
        // injectFirstPacket sends the first packet into readCh and sets readSeq=1.
        // Without this, the Reader would attempt Download(c2s/0) which will never
        // appear in storage - it was consumed from the discovery file payload.
        sessions.Store(sessionID, sessionEntry{conn, time.Now()})
        addConn(conn)
        enqueueDelete(file)
        newThisCycle++
        newThisMinute++

    newThisCycle = 0
```

### Startup GC

```
ListNew(within=infinity, pageSize=1000), paginate until exhausted
everything where serverTime < now-2min -> BatchDelete(bgCtx)
```

### Periodic GC

A dedicated goroutine at the `Server` level, runs every `periodicGCInterval` (default 5 minutes):

```
loop:
    sleep(periodicGCInterval)

    opCtx ← context.WithTimeout(bgCtx, 60s)
    orphanFiles ← service.ListOrphanedSessions(opCtx, gcMaxAge)
    for batch in chunks(orphanFiles, deleteBatchSize):
        service.BatchDelete(bgCtx, batch)
```

Protects against garbage accumulation on long-running servers and for backends without an equivalent of S3 Expiration Rules (GDrive, OneDrive, WebDAV).

-----

## Session Management

```go
type sessionEntry struct {
    conn     *XdriveConnection
    lastSeen time.Time
}
```

A session is closed when:

- FIN is received (after confirming all seq up to `lastDataSeq` are processed)
- `lastSeen + idleTimeout` has elapsed
- `stallTimeout` or `deadTimeout` fires in the Reader
- `ErrWriteBufferFull` is returned from Write()

**Two-phase close.** Side A sends FIN -> side B receives FIN, sends its own FIN -> A receives FIN -> both call CleanupSession. If the acknowledgment FIN is not received within `finAckTimeout` (15s), CleanupSession is called unilaterally.

The signal path from Reader to Writer is explicit via `conn.remoteFinCh chan struct{}`:

```
Reader receives remote FIN:
    close(conn.remoteFinCh)   // signal Writer to drain and send own FIN
    initiate graceful close (wait for own FIN to be sent)

Writer loop - additional select arm:
    case <-conn.remoteFinCh:
        // flush any remaining writeBuf, then send FIN
        drain writeBuf -> Upload inflight if non-empty
        send FIN
        return
```

Without this signal, the Writer may not drain `writeBuf` before the session context is cancelled, causing data loss on the last flush.

```go
ctx := context.WithTimeout(context.Background(), 15*time.Second)
service.CleanupSession(ctx, sessionID)
```

`conn.sessionClosed = true` on first FIN processing. A duplicate FIN is idempotent.

-----

## Thundering Herd Mitigation

```
attempt N: sleep(min(1s x 2^N, 60s) x uniform(0.7, 1.3))
```

Server-side admission control in the Discovery Loop: when `currentRPS > maxRPS x 0.8`, no new sessions are accepted. The client does not receive `s2c/0` within `deadTimeout` and retries with backoff.

-----

## Memory Management

### Writer buffers (sync.Pool)

```go
var chunkPool = sync.Pool{
    New: func() interface{} {
        buf := make([]byte, 0, maxChunkSize+maxPadding+18)  // +18 = 2 len + 16 HMAC
        return &buf
    },
}
```

Before `Put()`: `*buf = (*buf)[:0]`. Lifecycle: Get() -> wrapWithHMAC() -> Upload() -> Put(). Short-lived buffers; Pool is effective here.

### Reader buffer (per-connection)

```go
// At XdriveConnection initialization:
conn.readBuf = make([]byte, maxChunkSize+maxPadding+18)
```

Pool is ineffective for the Reader: the buffer may outlive multiple GC cycles when `Read()` is slow. A pre-allocated per-connection buffer is predictable and independent of GC. Pool is used only for the Writer.

-----

## PRNG

```go
sessionSeed := int64(binary.BigEndian.Uint64([]byte(sessionID[:8])))
secretSeed  := int64(binary.BigEndian.Uint64(HMAC-SHA256(sharedSecret, []byte("prng"))[:8]))

writerRng = rand.New(rand.NewSource(
    time.Now().UnixNano() ^ int64(os.Getpid()) ^ sessionSeed ^ secretSeed))
readerRng = rand.New(rand.NewSource(
    ^(time.Now().UnixNano() ^ sessionSeed ^ secretSeed)))
```

`secretSeed` includes sharedSecret: an observer who knows sessionID and the startup time cannot reproduce the PRNG without knowing sharedSecret. Each RNG is used exclusively in its own goroutine - no contention, no data race (`rand.NewSource` is not goroutine-safe).

-----

## Full Exchange Diagram

```
[ Client ]                      [ Storage ]                [ Server ]
    |                                |                          |
    |  Upload(_new/min_hmac16,        |                          |
    |    sessionID+firstPkt) ------> |                          |
    |                                | <-- ListNew(pageSize) -- |  every 500ms
    |                                |     parse sessionID ---- |
    |                                |     validate wire fmt -- |
    |                                | <-- Delete(_new/...) --- |
    |                                |                          | -- addConn()
    |                                |                          |
    |  Writer:                       |                          |
    |  inflight <- data              |                          |
    |  Upload(sid/c2s/N) ----------> |                          |
    |  (retry with same data on err) |    Download(sid/c2s/N) - |  Sequential / OOO
    |                                |    validate HMAC ------- |
    |                                |    -> readCh             |
    |                                |                          |
    |  Download(sid/s2c/M) <-------- |    Upload(sid/s2c/M) --> |
    |  validate HMAC                 |                          |
    |  -> readCh                     |                          |
    |                                |                          |
    |  [graceful close, 2-phase]:    |                          |
    |  Upload(c2s/FIN, lastSeq) ---> |                          |
    |                                |    FIN+lastSeq -> OOO -- |  waits all seq
    |                                |    Upload(s2c/FIN) ----- |
    |  FIN ack <-------------------- |                          |
    |  CleanupSession                |    CleanupSession ------- |
    |                                |                          |
    |     [ Delete Worker - bgCtx, BatchDelete every 1s ]       |
    |  <-- BatchDelete([s2c/0..M]) - | <-- BatchDelete([c2s/..])
    |                                |                          |
    |  [ Periodic GC - every 5min ]  |                          |
    |                                | <-- ListOrphan + Delete- |
    |                                |                          |
    |  [Sequential Probe]:           |                          |
    |                                |    Download(c2s/N+1) --- |
    |                                |    gap -> close -------- |
```

-----

## Configuration Parameters

```json
{
  "xdriveSettings": {
    "remoteFolder":            "xdrive-proxy",
    "service":                 "s3",
    "secrets":                 ["token"],

    "targetRPS":               2,
    "minChunkSize":            32768,
    "maxChunkSize":            4194304,
    "maxWriteBufSize":         8388608,
    "maxFlushDelay":           "500ms",
    "maxPadding":              4096,

    "baseInterval":            "100ms",
    "jitter":                  "30ms",

    "pollMin":                 "100ms",
    "pollMax":                 "3000ms",
    "pollFactor":              1.5,

    "ooMaxLookahead":          8,
    "ooTimeout":               "30s",

    "stallTimeout":            "5s",
    "deadTimeout":             "30s",
    "idleTimeout":             "10s",
    "finAckTimeout":           "15s",
    "staleDiscovery":          "2m",
    "probeTimeout":            "3s",

    "deleteWorkerInterval":    "1s",
    "deleteBatchSize":         50,

    "cbFailureWindow":         "10s",
    "cbFailureThreshold":      5,
    "cbCooldownPeriod":        "30s",
    "cbHalfOpenProbes":        3,

    "reconnectBaseDelay":      "1s",
    "reconnectMaxDelay":       "60s",
    "reconnectJitter":         0.3,

    "admissionMaxRPSRatio":    0.8,
    "maxNewSessionsPerCycle":  10,
    "maxNewSessionsPerMinute": 60,

    "periodicGCInterval":      "5m",
    "gcMaxAge":                "1h",

    "minProbeHits":            3
  }
}
```

For Google Drive, `ooTimeout` should be set to `"120s"` due to eventual consistency lag of up to one hour in shared drives.

-----

## Backend Priority

| Backend       | Write        | List         | BatchDelete          | Notes                   |
|---------------|--------------|--------------|----------------------|-------------------------|
| Local FS      | Strong       | Strong       | sequential os.Remove | Development and testing |
| S3-compatible | Strong       | Strong*      | 1000 (non-atomic)    | Self-hosted, corporate  |
| OneDrive      | Strong**     | Undocumented | 20 (JSON batch)      | Western audience        |
| Google Drive  | Strong by ID | Eventual     | 100                  | Last fallback           |

`*` **S3 LIST** - each individual request is immediately consistent, but multi-page pagination is not an atomic snapshot. CleanupSession: repeat ListPrefix until count == 0, maximum 5 iterations.

**S3 DeleteObjects:** HTTP 200 does not mean full success. Inspect `<e>` elements in the response body. Use Quiet mode.

`**` **OneDrive** - direct `GET /items/{id}/content` is expected to be immediately consistent after `PUT`, but Microsoft does not document this. Empirical verification required before production use.

**Google Drive** - `files.get(fileId)` is immediately consistent; `files.list()` is eventual (2-30s, up to one hour in shared drives). Limits: 20,000 requests/100s, ~300 writes/100s **per GCP project** (write limit cannot be increased). If multiple XDRIVE server instances share one GCP project/OAuth client, the write quota is shared across all of them. At `targetRPS=2`, one session generates 2 client uploads/s + 2 server uploads/s = 4 writes/s total, which already exceeds the 3 writes/s project limit. **`targetRPS` for GDrive must be set to `1` maximum**, giving 1+1=2 writes/s across both sides. Suitable for at most 1 concurrent session per GCP project.

-----

## Implementation Notes

### §1 - Context Isolation

```
XdriveConnection.writerCtx  -> Upload on hot path (Writer goroutine)
XdriveConnection.readerCtx  -> Download on hot path (Reader goroutine)
Server.bgCtx                -> Delete Worker, CleanupSession, GC, Periodic GC
                               derived from context.Background()
                               cancelled on Server.Close()
```

Background operations never use the Xray session context - it can be cancelled at any moment.

### §2 - Two Separate PRNGs

`rand.NewSource` is not goroutine-safe. Writer and Reader are separate goroutines. A shared source without a mutex is a data race, detectable by `go test -race`.

```go
sessionSeed := int64(binary.BigEndian.Uint64([]byte(sessionID[:8])))
secretSeed  := int64(binary.BigEndian.Uint64(HMAC-SHA256(sharedSecret, []byte("prng"))[:8]))
writerRng    = rand.New(rand.NewSource(
    time.Now().UnixNano() ^ int64(os.Getpid()) ^ sessionSeed ^ secretSeed))
readerRng    = rand.New(rand.NewSource(
    ^(time.Now().UnixNano() ^ sessionSeed ^ secretSeed)))
```

### §3 - Clock Skew in Discovery

The authoritative freshness source is `ServerTime` (cloud Last-Modified). The client timestamp in the filename is quantized to the minute and serves only as a secondary hint. Zombie: `ServerTime < now-2m`. Clock skew: client timestamp old but server timestamp fresh - accept and log via `newError("XDRIVE discovery: clock skew on session ", sessionID).AtWarning().WriteToLog()` (Xray logging convention).

### §4 - Per-Connection Read Buffer

`sync.Pool` is cleared on every GC cycle. If the Reader holds a buffer in leftover longer than one cycle, `Put()` is wasted and the next `Get()` allocates again. With 50 sessions x 4 MB, that is 200 MB of fresh allocations per GC cycle.

Solution: `conn.readBuf = make([]byte, maxChunkSize+maxPadding+18)` at connection creation. Pre-allocated, predictable, independent of GC. Pool is used only for the Writer (short-lived buffers).

### §5 - Write() on Buffer Full

`ErrWriteBufferFull` when `len(writeBuf)+len(p) > maxWriteBufSize`. Closes the specific virtual stream without affecting others. A blocking Write() under backend degradation (CB Open for 30s) leads to OOM.

### §6 - Wire Format Validation

Mandatory sequence in every `Download()`:

```go
if len(data) < 2 {
    return nil, ErrPartialRead
}
payloadLen := int(binary.BigEndian.Uint16(data[0:2]))
if payloadLen > maxChunkSize {
    return nil, ErrMalformedPayload
}
if len(data) < 2+payloadLen+16 {
    return nil, ErrPartialRead
}
mac := data[2+payloadLen : 2+payloadLen+16]
if !hmac.Equal(mac, computeHMAC(fileKey, data[:2+payloadLen])) {
    return nil, ErrInvalidHMAC
}
return data[2 : 2+payloadLen], nil
```

`ErrPartialRead` - Reader retries. `ErrMalformedPayload` and `ErrInvalidHMAC` - Reader closes the session.

### §7 - Probe: Gap vs Stall

Probe checks `readSeq+1` and signals `gapDetected` only if `readSeq+1` already exists while `readSeq` does not. This is a gap (lost file), not a stall (Writer has not yet written seq+1). Under low traffic, the probe consistently returns ErrNotExist - this is normal and does not indicate a problem.

To prevent a single spurious probe hit from triggering reconnect during burst traffic, `gapDetected` is only raised after `minProbeHits` consecutive successful probes (default 1):

```go
if err != ErrNotExist {
    consecutiveProbeHits++
    if consecutiveProbeHits >= minProbeHits {
        signal gapDetected
    }
} else {
    consecutiveProbeHits = 0
}
```

`minProbeHits=1` is correct for strong-consistency backends. Writer is a single goroutine with one inflight at a time - `seq=N` is always confirmed before `seq=N+1` is uploaded. There is no valid scenario where `seq=N+1` exists in storage while `seq=N` is merely delayed: if `N+1` is visible and `N` is not, `N` is genuinely lost. Higher values only delay gap detection by `minProbeHits x pollMin` without adding correctness.

### §8 - Google Drive: Hybrid Download

`files.list()` is eventual consistent (2-30s). `files.get(fileId)` is immediately consistent. The GDrive driver caches seq -> fileId on Upload (own side) or on first `findByName` (other side). Subsequent access to the same seq goes through `getByFileId`. The cache is bound to `XdriveConnection` and is cleared on `CleanupSession`.

```go
type GoogleDriveService struct {
    fileIdCache sync.Map  // cacheKey(ref) -> fileId string
}

func (s *GoogleDriveService) Download(ctx context.Context, ref FileRef) ([]byte, error) {
    key := cacheKey(ref)
    if fileId, ok := s.fileIdCache.Load(key); ok {
        return s.getByFileId(ctx, fileId.(string))
    }
    fileId, err := s.findByName(ctx, ref)
    if err != nil {
        return nil, err
    }
    s.fileIdCache.Store(key, fileId)
    return s.getByFileId(ctx, fileId)
}
```

### §9 - S3 DeleteObjects

S3 returns HTTP 200 even on partial failures. Use Quiet mode. Inspect `<e>` elements in the response. On partial failure, return failed refs to the Delete Worker for retry. Deleting a non-existent key is treated as success (idempotent).

```go
func (s *S3Service) BatchDelete(ctx context.Context, refs []FileRef) error {
    result, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
        Bucket: s.bucket,
        Delete: &types.Delete{
            Objects: toObjectIdentifiers(refs),
            Quiet:   aws.Bool(true),
        },
    })
    if err != nil {
        return err
    }
    if len(result.Errors) > 0 {
        return fmt.Errorf("partial delete failure: %d keys failed", len(result.Errors))
    }
    return nil
}
```

### §10 - Memory Requirements

```
Per-session:
  writeBuf         = maxWriteBufSize        =  8 MB
  inflight         = maxChunkSize           =  4 MB
  readBuf          = maxChunkSize + 18      =  4 MB
  readCh (depth 1) = maxChunkSize x 1      =  4 MB
  total per session                        ~ 20 MB

Server total ~ maxConcurrentSessions x 20 MB + overhead

Examples:
  10  sessions ->   ~200 MB
  50  sessions ->  ~1.0 GB
  100 sessions ->  ~2.0 GB
  500 sessions -> ~10.0 GB
```

`maxConcurrentSessions` constrains both backend rate limits and memory consumption.