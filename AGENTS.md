# AGENTS.md — webTraffik AI Agent Reference

This file is the authoritative reference for AI agent sessions working on the webTraffik codebase. Read it in full before making any changes.

---

## Project Overview

webTraffik is a real-time network traffic sensor and visualization tool. It binds directly to a configurable list of common HTTP ports, TCP service ports (with protocol emulation), and UDP ports, logs every incoming connection, geolocates the source IP, and streams the events to a browser dashboard over WebSocket.

**Tech stack:**
- **Backend**: Go (single binary, no CGo required)
- **Frontend**: D3.js v7 with TopoJSON, served as an embedded static file
- **Persistence**: SQLite via `modernc.org/sqlite` (pure-Go driver)
- **Firewall**: nftables (Linux only), configured by `firewall.sh`
- **Process manager**: systemd, running as a dedicated low-privilege user

---

## Architecture

### Event flow (end-to-end)

```
Internet -> TCP SYN on capture port
  |
  v
http.ListenAndServe (one goroutine per port in capturePorts)
  |
  v
handleCapture(srcIP, dstPort)
  - geo.Lookup(srcIP) -> Location{Lat, Lon, City, CountryCode}
  - builds ConnectionEvent struct
  |
  +-> appLimiter.Record(srcIP, dstPort)
  |     - feeds rate limiter (dual-threshold auto-ban: flood check + volume-window check)
  |     - feeds scan tracker (port hit tracking, 5-port/10-minute threshold detection)
  |     - evicts stale port hits outside scan window
  |     - non-blocking, mutex-protected
  |
  +-> appHub.broadcast(ev)
  |     - appends to in-memory ring buffer (historySize = 1000, oldest evicted)
  |     - fans out to all open WebSocket subscriber channels (non-blocking select)
  |
  +-> appDB.insert(ev)
  |     - fire-and-forget INSERT into SQLite events table
  |     - errors logged, never fatal, never blocks the capture path
  |
  +-> appMetrics.Record(ev)
        - increments in-memory hourly-bucketed counters
        - tracks connections per port/protocol/service/country
        - tracks unique IPs per hour
        - dirty counters flushed to SQLite every 5 seconds
```

### The hub (`main.go`)

- `hub` struct: mutex-protected map of subscriber channels + a `[]ConnectionEvent` ring buffer
- `broadcast()`: appends to ring buffer (evicting oldest when full) under lock, then snapshots subscribers and releases the lock before fan-out. Sends to all subscriber channels with a non-blocking `select` (slow clients are dropped, not stalled). This lock-snapshot-release pattern avoids blocking subscribe/unsubscribe operations during fan-out.
- `snapshot()`: returns a copy of the ring buffer (used internally; WS handler reads from DB directly)
- On startup, `loadHistory(1000)` seeds the ring buffer from the DB so in-memory state survives restarts

### WebSocket `/ws` endpoint (`main.go`)

1. Accepts the WebSocket upgrade
2. Subscribes to the hub channel FIRST (256-deep channel absorbs bursts during replay)
3. Calls `appDB.loadHistory(historySize)` — reads up to 1000 events from SQLite, oldest-first
4. Sends each historical event with `Replay = true` while live events buffer in the channel
5. Drains buffered live events and continues streaming as they arrive
6. Exits cleanly when the client disconnects (`ctx.Done()`)

### Frontend (`static/index.html`)

- D3.js Natural Earth projection (svg `#map`)
- Animated arcs: great-circle paths via `d3.geoInterpolate`, 20-point sampling with `curveNatural` (optimized from 60-point CatmullRom), animated with `stroke-dashoffset`
- Persistent dots: remain after arc animation completes; store `[lon, lat]` as D3 datum for reprojection on resize (no DOM attributes)
- Tooltips: `#dot-tooltip` div, shown on `mouseover` of `.src-dot` elements via D3 event handlers, displays "City, CC", source IP, "Trace route" button, and "Ban"/"Unban" button
- Traceroute visualization: tooltip "Trace route" button or double-click on `.src-dot` triggers an SSE stream from `/api/traceroute?ip=...`; during a trace, live arc rendering is suppressed (`tracerouteActive` flag); hops are reversed (animation flows from source toward server) and drawn as sequential staggered arcs in a `traceGroup` SVG layer with progressive color scale (red→amber→cyan); map auto-zooms to fit all hop points; `#trace-indicator` overlay shows "Tracing route…" during SSE stream; Escape key cancels and zooms back to world view
- Two corner overlay panels positioned absolutely on the map:
  - `#panel-service` (top-left): Top Services — top 10 services with bar charts showing relative traffic
  - `#panel-banned` (top-right): Banned IPs — list of currently banned source IPs
  - `#panel-scanners` (top-right, below banned): Port Scanners — list of IPs detected hitting 5+ ports in 10 minutes
- Panel rendering decoupled from event processing: uses `requestIdleCallback` on a 2-second timer with dirty flags; only re-renders when data changes
- Log panel (`#log-panel`): scrolling list, capped at 200 entries, shows time/IP/city/CC/port; uses rAF-based rendering via `scheduleLogRender()` for low latency
- Arc lifecycle: gradient pooling (reuses SVG gradients by color pair instead of per-arc gradients), no glow filters on dots (only on self-dot), arc count capped at 150, dot count capped at 1000
- Arc animation lifespan: ~2.6 seconds (800ms draw + 1200ms hold + 600ms fade)

---

## Key Files and Responsibilities

| File | Owns |
|------|------|
| `main.go` | `ConnectionEvent` struct, `hub` (ring buffer + fan-out), HTTP capture listeners, dashboard server, `/ws` handler, `/api/self` endpoint, `capturePorts` var (HTTP-only ports), `/api/traceroute` SSE endpoint |
| `services.go` | TCP service port emulation (`tcpServices` with banners for FTP, SSH, Teltel, SMTP, etc.) and UDP port capture (`udpServicePorts`) |
| `SERVICES.md` | Detailed reference of all emulated TCP/UDP services and their protocol banners; must be kept in sync with `services.go` |
| `db.go` | SQLite open/close, schema creation, `insert()`, `loadHistory()`, metrics table schema, `upsertMetrics()`, `queryMetrics()`, `backfillMetrics()` |
| `metrics.go` | `metricsCache` struct, in-memory hourly-bucketed metrics aggregation, `Record()`, `RecordBan()`, `flushLoop()` (5-second interval), `/api/metrics` and `/metrics` (Prometheus) handlers |
| `internal/ratelimit/scanner.go` | Port scan detection tracker; `ScannerEntry` struct; `scanTracker` with per-IP port-hit tracking; 5-port/10-minute threshold; 1-hour display window; 2-minute GC loop; `ActiveScanners()` for `/api/scanners` endpoint |
| `internal/traceroute/traceroute.go` | `Hop` struct, `Run()` function (streams traceroute/tracepath hops incrementally), `GeoFunc` callback type, `buildCmd()` tool detection (prefers `traceroute`, falls back to `tracepath`), private/loopback IP filtering, hop de-duplication |
| `internal/ratelimit/ratelimit.go` | Auto-ban rate limiter; `Limiter` struct; dual-threshold detection (flood + volume-window); per-IP+port ban tracking; SQLite persistence; `IsBanned()` fast read-lock check; `ManualBan()`/`ManualUnban()` API handlers; 64-shard FNV32a hash design |
| `geo.go` | `GeoLocator` (GeoLite2 reader + rgeo fallback), `Lookup()`, `Location` struct |
| `geodb.go` | `ensureGeoDB()` — auto-download of `GeoLite2-City.mmdb` from GitHub mirror |
| `iputil.go` | `discoverPublicIP()` — queries external APIs to find the server's public IP |
| `static_embed.go` | `//go:embed static` directive; exposes `staticFiles fs.FS` |
| `static/index.html` | Entire browser UI: D3.js map, WebSocket client, arc animation, tooltips, corner panels, log, traceroute visualization |
| `firewall.sh` | nftables ruleset installer; auto-detects interface/subnet; substitutes tokens into `nftables.conf` |
| `nftables.conf` | Ruleset template; contains `__SUBNET__`, `__CAPTURE_PORTS_TCP__`, and `__CAPTURE_PORTS_UDP__` tokens |
| `install.sh` | Standalone deployer: creates user, data dir, copies binary, writes systemd unit, calls `firewall.sh` |
| `webtraffik.service` | systemd unit template (also written inline by `install.sh`) |
| `Makefile` | All build, cross-compile, deploy, firewall, and uninstall targets |

---

## Port List — CRITICAL SYNC REQUIREMENT

This is the most operationally important section. Mismatches between the port definitions in the app and the firewall will cause either missed traffic (ports open in the app but blocked by the firewall) or firewall holes (ports open in the firewall but not listened on by the app).

### Definition locations

**1. `main.go` — `capturePorts` variable (around line 113)**

```go
var capturePorts = []int{
    80, 8080, 8000, 8008, 8081, 8088, 8090, 8888,
    3000, 3001, 3128, 4000, 4200, 5000, 5001, 9000, 9090,
}
```

This is the authoritative list of **HTTP-only ports**. The app binds an `http.ListenAndServe` listener on every port in this slice.

**2. `services.go` — `tcpServices` slice (around line 21)**

```go
var tcpServices = []serviceEntry{
    {Port: 21, Name: "FTP", Banner: ftpBanner},
    {Port: 22, Name: "SSH", Banner: sshBanner},
    // ... etc.
}
```

This is the authoritative list of **TCP service ports** (non-HTTP). Each entry specifies a port, service name, and a `Banner()` function that returns the bytes sent immediately after accepting a connection. These use raw `net.Listener`, not `net/http`.

**3. `services.go` — `udpServicePorts` slice (around line 240)**

```go
var udpServicePorts = []int{53}
```

This is the authoritative list of **UDP ports**. These use `net.ListenPacket`.

**4. `firewall.sh` — `CAPTURE_PORTS_TCP` variable (around line 70)**

```bash
CAPTURE_PORTS_TCP="21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, \
993, 995, 1433, 1521, 1723, 3000, 3001, 3128, 3306, 3333, 3389, \
4000, 4200, 4444, 5000, 5001, 5432, 5555, \
5900, 6379, 6667, 8000, 8008, 8080, 8081, 8088, 8090, 8333, 8443, \
8545, 8546, 8888, 9000, 9090, 9100, 9200, 9735, 10009, \
11211, 18080, 18081, 18789, 25565, 27017, 30303"
```

This must include **all TCP ports** — both HTTP ports from `main.go` and service ports from `services.go` — as a comma-separated nftables set literal.

**5. `firewall.sh` — `CAPTURE_PORTS_UDP` variable (around line 75)**

```bash
CAPTURE_PORTS_UDP="53, 123, 161, 1434, 1900, 5060, 30303"
```

This must include **all UDP ports** from `services.go` as a comma-separated nftables set literal.

### Current port list

**TCP ports (main.go `capturePorts` — HTTP listeners):**
80, 8080, 8000, 8008, 8081, 8088, 8090, 8888, 3000, 3001, 3128, 4000, 4200, 5000, 5001, 9000, 9090

**TCP service ports (services.go `tcpServices` — raw TCP listeners with banners):**
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 445 (SMB), 1433 (MSSQL), 3306 (MySQL), 3333 (Stratum), 3389 (RDP), 5432 (PostgreSQL), 6379 (Redis), 8333 (Bitcoin P2P), 8443 (HTTPS-Alt), 8545 (Ethereum RPC), 8546 (Ethereum WS), 9200 (Elasticsearch), 9735 (Lightning), 10009 (Lightning gRPC), 11211 (Memcached), 18080 (Monero P2P), 18081 (Monero RPC), 27017 (MongoDB), 30303 (Ethereum P2P), 5900 (VNC)

**UDP ports (services.go `udpServicePorts` — UDP listeners):**
53 (DNS), 123 (NTP), 161 (SNMP), 1900 (SSDP), 5060 (SIP), 30303 (Ethereum P2P)

### Dashboard port

Port **8999** is the dashboard. It is **not** in `capturePorts` and is **not** in the firewall's capture-port rule. It is covered by the subnet-only management rule and is intentionally inaccessible from the internet.

### After changing ports

Any time ports are added or removed in `main.go`:
1. Update `CAPTURE_PORTS_TCP` in `firewall.sh` to match
2. Re-apply the firewall: `make remote-install IP=x.x.x.x` (full deploy) or `sudo bash firewall.sh` (firewall only)
3. Rebuild and restart the app so it binds the new port list

---

## Database

### Location

`WorkingDirectory + /events.db`

Under systemd the unit sets `WorkingDirectory=/var/lib/webtraffik`, so the path is `/var/lib/webtraffik/events.db`. In a local dev run it is `./events.db` in whatever directory the binary is launched from.

### Schema (`db.go:50-70`)

```sql
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    time     TEXT    NOT NULL,
    src_ip   TEXT    NOT NULL,
    dst_ip   TEXT    NOT NULL,
    dst_port TEXT    NOT NULL,
    src_lat  REAL    NOT NULL DEFAULT 0,
    src_lon  REAL    NOT NULL DEFAULT 0,
    dst_lat  REAL    NOT NULL DEFAULT 0,
    dst_lon  REAL    NOT NULL DEFAULT 0,
    src_city TEXT    NOT NULL DEFAULT '',
    dst_city TEXT    NOT NULL DEFAULT '',
    src_cc   TEXT    NOT NULL DEFAULT '',
    dst_cc   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_id_desc ON events(id DESC);
```

### Pragmas

- `PRAGMA journal_mode=WAL` — readers do not block the writer
- `PRAGMA synchronous=NORMAL` — fast writes; may lose up to ~1 second of events on a hard power failure, safe on normal OS/app crash

### Key behaviors

- `insert()` (`db.go:88`): queues a `ConnectionEvent` into a 4096-deep buffered channel. If the queue is full, the event is dropped (logged) — the capture path never blocks on DB writes.
- `writeLoop()` (`db.go:100`): dedicated goroutine that drains the insert queue and batches writes into SQLite. Groups pending events into a single transaction, flushing whenever the queue drains or a batch reaches 64 events. This provides high throughput under burst traffic.
- `flushBatch()` (`db.go:137`): writes a slice of events to SQLite in a single transaction. All errors are logged; failures do not crash the app.
- `loadHistory(limit int)` (`db.go:179`): subquery selects the `limit` most-recent rows by `id DESC`, then re-orders them `ASC` for oldest-first replay. Called twice: once at startup (to seed the ring buffer) and once per new WebSocket connection.
- `close()` (`db.go:210`): closes the insert queue channel (signaling `writeLoop` to flush and exit), waits for the writer goroutine to finish, then releases the database connection.

### Metrics table

The `metrics` table stores hourly-aggregated statistics:

```sql
CREATE TABLE IF NOT EXISTS metrics (
    name   TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '',
    bucket TEXT NOT NULL,
    value  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (name, labels, bucket)
);
CREATE INDEX IF NOT EXISTS idx_metrics_bucket ON metrics(bucket);
```

**Schema details:**
- `name` — metric name: `connections`, `unique_ips`, or `bans`
- `labels` — comma-separated key-value pairs (e.g., `port=80,protocol=http,service=HTTP,cc=US`) for `connections`; `type=auto` or `type=manual` for `bans`; empty for `unique_ips`
- `bucket` — ISO 8601 hour timestamp (`2026-03-22T14:00:00Z`); all metrics within the hour are aggregated into this bucket
- `value` — aggregated value (counter total for `connections` and `bans`, unique IP count for `unique_ips`)

**Key behaviors:**
- `upsertMetrics()` (`db.go`): uses `INSERT ... ON CONFLICT DO UPDATE` to add deltas to existing counters or insert new rows
- `queryMetrics()` (`db.go`): queries metrics within a time range and aggregates them by metric name/labels
- `backfillMetrics()` (`db.go`): on first run with an empty metrics table, aggregates all existing events into hourly buckets; re-run safe (idempotent)

---

## Metrics System

webTraffik maintains an in-memory hourly-bucketed metrics cache with SQLite persistence. This provides fast aggregation for dashboards and historical analysis without blocking the capture path.

### Architecture

**In-memory cache** (`metrics.go`):
- `metricsCache` struct: map of `(name, labels, hourBucket)` → counter value
- Tracks three metric types:
  - `connections` — labeled by `port`, `protocol`, `service`, `cc` (country code)
  - `unique_ips` — per-hour unique source IP count (approximate across hour boundaries)
  - `bans` — labeled by `type` (`auto` or `manual`)
- Dirty counters tracked separately; only modified counters are flushed to SQLite
- Per-hour IP sets stored in memory for `unique_ips` calculation; released after flush
- Mutex-protected for concurrent access from capture handlers and flush loop

**Flush loop** (`metrics.go:flushLoop()`):
- Runs every 5 seconds in a dedicated goroutine
- Snapshots dirty counters under lock
- Writes to SQLite via `upsertMetrics()` (non-blocking; never stalls capture path)
- Uses `value = value + delta` for counters, `MAX(value, new)` for `unique_ips` (prevents overcounting on restarts)
- Final flush on graceful shutdown (loss: 0 events); on hard crash, up to 5 seconds of data may be lost

**Backfill** (`metrics.go:backfillMetrics()`):
- On first run (empty metrics table), aggregates existing events from the `events` table into hourly buckets
- Idempotent: safe to re-run; uses `INSERT ... ON CONFLICT DO UPDATE` to merge with existing metrics
- Called automatically on startup if metrics table is empty

**Integration points:**
- `handleCapture()` (`main.go`) → calls `appMetrics.Record(ev)` for every connection event
- `autoBanHandler()` (`ratelimit.go`) → calls `appMetrics.RecordBan("auto")` when auto-banning an IP
- `ManualBan()` (`ratelimit.go`) → calls `appMetrics.RecordBan("manual")` for manual bans

### API Endpoints

Both endpoints are served on the dashboard port (8999) and are accessible only from the subnet.

**1. `/api/metrics?from=...&to=...` (JSON)**

Returns aggregated metrics for the specified time range:

```json
{
  "from": "2026-03-22T00:00:00Z",
  "to": "2026-03-22T23:59:59Z",
  "connections": 12543,
  "bans": 142,
  "unique_ips": 3891,
  "time_buckets": [
    {"bucket": "2026-03-22T00:00:00Z", "connections": 523, "bans": 5, "unique_ips": 187},
    {"bucket": "2026-03-22T01:00:00Z", "connections": 601, "bans": 8, "unique_ips": 203},
    ...
  ],
  "port_timeline": {
    "80": [{"bucket": "2026-03-22T00:00:00Z", "value": 123}, ...],
    "443": [...],
    ...
  },
  "country_timeline": {
    "US": [{"bucket": "2026-03-22T00:00:00Z", "value": 89}, ...],
    "CN": [...],
    ...
  }
}
```

**2. `/metrics?from=...&to=...` (Prometheus)**

Returns metrics in Prometheus exposition format (text/plain):

```
# HELP webtraffik_connections_total Total number of connections
# TYPE webtraffik_connections_total counter
webtraffik_connections_total{port="80",protocol="http",service="HTTP",cc="US"} 523

# HELP webtraffik_unique_ips Unique source IPs per hour
# TYPE webtraffik_unique_ips gauge
webtraffik_unique_ips 187

# HELP webtraffik_bans_total Total number of bans
# TYPE webtraffik_bans_total counter
webtraffik_bans_total{type="auto"} 12
```

Query parameters:
- `from` — ISO 8601 timestamp (default: 24 hours ago)
- `to` — ISO 8601 timestamp (default: now)

---

## Port Scan Detection

webTraffik includes an in-memory port scan detection system that identifies IPs hitting multiple distinct ports within a short time window.

### Detection logic

- **Threshold**: 5 distinct ports within 10 minutes
- **Display duration**: detected scanners remain visible for 1 hour after last activity
- **GC interval**: stale port hits and fully-expired entries are cleaned every 2 minutes
- **Non-blocking**: all operations use mutex-protected maps; never blocks the capture path

### Architecture

**scanner.go (`internal/ratelimit` package):**
- `ScannerEntry` struct (exported): `IP`, `PortCount`, `DetectedAt`, `ExpiresAt`, `LastSeenAt` — all JSON-tagged for API serialization
- `scanTracker`: unexported tracker with per-IP port-hit timestamps (`map[string]time.Time` per IP)
- `Record(srcIP, dstPort) bool`: records hit, evicts stale hits outside `ScanWindow`, returns true when IP crosses threshold
- `ActiveScanners() []ScannerEntry`: returns snapshot of detected scanners sorted by port count descending
- `gcLoop()`: background goroutine runs every 2 minutes to prune stale hits and remove expired entries

**ratelimit.go integration:**
- `Limiter.scanner` field initialized by `New()`
- `Limiter.Record()` calls `scanner.Record()` before rate-limit shard logic
- `Limiter.ActiveScanners()` delegates to `scanner.ActiveScanners()`

**Frontend integration (`static/index.html` & `static/index.js`):**
- New `#panel-scanners` div in `#right-panels` wrapper (top-right, stacked above `#panel-banned`)
- Amber/orange color scheme (`#ffb74d`) to distinguish from banned IPs (red)
- Displays scanner IP, port count, time ago ("2m 15s ago"), and countdown to expiry
- Polled every 10 seconds via `/api/scanners` endpoint
- Idle-callback rendering with dirty flags (same pattern as other panels)

### API Endpoint

**`GET /api/scanners`** — returns JSON array of `ScannerEntry`:

```json
[
  {
    "ip": "1.2.3.4",
    "port_count": 8,
    "detected_at": "2026-03-22T14:23:45Z",
    "expires_at": "2026-03-22T15:23:45Z",
    "last_seen_at": "2026-03-22T14:28:12Z"
  }
]
```

### Integration points

- `handleCapture()` (`main.go`) → `appLimiter.Record(srcIP, dstPort)` → `scanner.Record()`
- `/api/scanners` handler (`main.go`) → `appLimiter.ActiveScanners()`
- Frontend polls every 10 seconds, renders in top-right panel

---

## Auto-Ban System

webTraffik includes an automatic IP banning system that detects abusive connection patterns and temporarily blocks offending IPs on a per-port basis.

### Ban triggers

Two independent detection mechanisms can trigger an automatic ban:

1. **High-rate (flood) ban** — sustained connection flooding:
   - Threshold: `>2 connections/sec` sustained for `10 minutes`
   - Catches rapid port scanners and brute-force tools

2. **Volume-window ban** — slow persistent scanning:
   - Threshold: `30 or more connections` within any rolling `10-minute window`
   - Catches slow, methodical scanners (e.g., VNC brute-forcers) that stay under the per-second threshold but hammer a single port continuously

### Ban characteristics

- **Duration**: `1 hour` (`BanCooldown`)
- **Scope**: per-IP per-port (keyed as `ipPortKey{ip, port}`)
- **Persistence**: bans are written to the `banned_ips` SQLite table and survive restarts
- **Expiration**: bans auto-expire after cooldown via `scheduleUnban()` (scheduled goroutine)
- **Metrics**: auto-bans are tracked in the metrics system with label `type=auto`

### Architecture

**ratelimit.go (`internal/ratelimit` package):**
- `Limiter` struct: holds ban map (RWMutex-protected) + 64-shard rate tracker (per-shard mutex)
- `IsBanned(ip, port) bool`: fast read-lock check; called at connection accept time in all TCP/HTTP handlers
- `Record(srcIP, dstPort) bool`: tracks connection, evicts stale timestamps, checks both flood and volume thresholds, triggers ban if breached; returns `false` if IP is banned (caller drops connection)
- `ManualBan(ip, port)` / `ManualUnban(ip, port)`: API-driven ban/unban; manual bans use `type=manual` metric label
- `ban()`: creates `BanEntry`, persists to DB (fire-and-forget), schedules auto-expiration, triggers `onChange()` callback (updates frontend panel)
- `scheduleUnban()`: sleeps for `BanCooldown`, then removes ban from memory and DB
- `LoadBans()`: seeds in-memory ban set from SQLite on startup; skips expired bans, schedules remaining

**Database schema:**
```sql
CREATE TABLE IF NOT EXISTS banned_ips (
    ip         TEXT NOT NULL,
    port       TEXT NOT NULL,
    service    TEXT NOT NULL,
    banned_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (ip, port)
);
```

**Sharded rate tracker:**
- `64 shards` (`rateShards`), each with its own mutex + `map[ipPortKey]*rateState`
- FNV32a hash on `ip+port` → shard index
- Per-IP+port `rateState`: two timestamp slices (1-second window for flood, 10-minute window for volume)
- GC loop: sweeps every 5 minutes, evicts entries idle longer than 11 minutes (`volumeWindow + 1 minute`)

### Integration points

**Capture path:**
- `handleCapture()` (`main.go`) → `appLimiter.Record(srcIP, dstPort)` → ban check + rate tracking
- TCP service handlers (`services.go`) → `IsBanned()` check before sending banner; if banned, connection is closed immediately
- HTTP handlers (`main.go`) → `IsBanned()` check before responding; if banned, connection is closed immediately
- UDP handlers (`services.go`) → ban check is **skipped** (UDP is connectionless; banning is ineffective)

**API endpoints:**
- `GET /api/banned` — returns JSON array of `BanEntry` (current bans, sorted by `BannedAt` descending)
- `POST /api/ban` — manual ban via JSON body: `{"ip": "1.2.3.4", "port": "22"}`
- `POST /api/unban` — manual unban via JSON body: `{"ip": "1.2.3.4", "port": "22"}`

**Frontend:**
- `#panel-banned` (top-right) displays active bans
- Polled every 10 seconds via `/api/banned`
- Updates triggered by WebSocket events when `onChange()` callback fires

### Constants (ratelimit.go lines 12-28)

```go
const (
    // High-rate (flood) ban: >2 events/sec sustained for 10 minutes.
    rateThreshold     = 2
    rateSustainWindow = 10 * time.Minute

    // Volume-window ban: 30+ events within any rolling 10-minute window.
    volumeThreshold = 30
    volumeWindow    = 10 * time.Minute

    BanCooldown    = 1 * time.Hour
    rateShards     = 64
    rateGCInterval = 5 * time.Minute
    rateGCMaxAge   = volumeWindow + time.Minute  // 11 minutes
)
```

---

## Firewall

### Technology

nftables only (Linux). No iptables support. The `nft` binary must be present on the target host.

### Template (`nftables.conf`)

Three tokens are substituted by `firewall.sh`:
- `__SUBNET__` — the CIDR of the primary interface (e.g. `192.168.1.0/24`), auto-detected via `ip route`
- `__CAPTURE_PORTS_TCP__` — the comma-separated TCP port list from `CAPTURE_PORTS_TCP` in `firewall.sh`
- `__CAPTURE_PORTS_UDP__` — the comma-separated UDP port list from `CAPTURE_PORTS_UDP` in `firewall.sh`

The generated file is written to `/etc/nftables.d/webtraffik.conf`.

### Policy

```
inet filter input (policy drop):
  - loopback: accept
  - established/related: accept
  - icmp/icmpv6: accept
  - tcp dport { CAPTURE_PORTS_TCP }: accept  (internet-facing TCP)
  - udp dport { CAPTURE_PORTS_UDP }: accept  (internet-facing UDP)
  - ip saddr SUBNET: accept                  (management — covers SSH, :8999, everything else)
  - everything else: drop (implicit)

ip webtraffik_nat prerouting:
  - tcp dport { CAPTURE_PORTS_TCP }: redirect  (NAT to app process)
  - udp dport { CAPTURE_PORTS_UDP }: redirect  (NAT to app process)
```

The `inet filter` table is flushed and fully redefined by the template. This eliminates any race condition with distro-default accept-all chains.

### Applying the firewall

```bash
# During full install (automatic)
make remote-install IP=x.x.x.x

# Firewall only, on the server
sudo bash firewall.sh

# Firewall only, via Makefile (runs locally)
make firewall
```

### Port sync

`firewall.sh` `CAPTURE_PORTS_TCP` (line ~71) must match `main.go` `capturePorts` (line ~113). See the Port List section above.

---

## Traceroute

webTraffik includes an on-demand traceroute feature that traces the network path from the server to a source IP and visualizes the hops on the dashboard map.

### Backend

**traceroute.go (`internal/traceroute` package):**
- `Hop` struct (exported): `N`, `IP`, `Lat`, `Lon`, `City`, `CountryCode` — all JSON-tagged for SSE serialization
- `Run(ctx, target, maxHops, geo, ch)`: spawns `traceroute` (or `tracepath` fallback) as a subprocess via `exec.CommandContext`, pipes stdout, parses each line for public IPs, geolocates each hop via `GeoFunc` callback, de-duplicates IPs, and sends `Hop` structs on `ch`. Channel is closed when the process exits or context is cancelled. Max hops default: 20.
- `buildCmd()`: tries `traceroute` first (with `-n -m N -w 1 -q 1` flags for fast numeric output), falls back to `tracepath` (with `-n -m N`). Returns empty if neither is available.
- Private/loopback/link-local IPs are silently skipped (not useful for geolocation).

**`/api/traceroute` SSE endpoint (`main.go`):**
- `GET /api/traceroute?ip=<public-ip>` — Server-Sent Events stream
- Validates target is a parseable public IP (rejects private, loopback, link-local, unspecified)
- 60-second context timeout
- Each hop streamed as `data: {json}\n\n`; terminal `event: done\ndata: {}\n\n` sentinel when trace completes
- Geo callback wraps `appGeo.Lookup()` for consistent geolocation with the main capture path

### Frontend

- **Trigger**: tooltip "Trace route" button, double-click on `.src-dot`, or click on log row
- **SSE client**: `startTraceroute(srcIP)` opens an `EventSource` to `/api/traceroute?ip=...`
- **Hop collection**: hops with valid geo coordinates are collected; on `done` event, hops are reversed and `selfPos` is appended so the animation flows from the source IP inward toward the server
- **Animation** (`animateTraceHops()`): sequential arc draw via `setTimeout` chain (one arc every `TRACE_STAGGER_MS`); progressive color scale (red→amber→cyan via `d3.interpolateRgbBasis`); numbered dot labels at each hop; map auto-zooms to fit all hop points (`zoomToHops()`)
- **State flags**: `tracerouteActive` suppresses live arc rendering during trace; `traceDrawing` suppresses `reprojectTraceHops()` during the draw phase to avoid destroying active transitions
- **Cancellation**: Escape key calls `cancelTrace()` — closes EventSource, clears all `traceTimers`, removes trace geometry, snaps back to world view
- **Timing constants**: `TRACE_ARC_DRAW_MS = 1800`, `TRACE_STAGGER_MS = 2000`, `TRACE_HOLD_MS = 2500`, `TRACE_FADE_MS = 800`

### System requirements

Requires `traceroute` or `tracepath` to be installed on the server. If neither is available, the endpoint returns an empty stream (immediate `done` sentinel, no hops). On most Linux distributions, install via `apt install traceroute` or `yum install traceroute`.

---

## Git Workflow

- Always branch off `main` before making changes
- Branch naming conventions:
  - `feature/*` — new functionality
  - `bugfix/*` — bug fixes
  - `refactor/*` — restructuring with no behavior change
  - `docs/*` — documentation-only changes
- Run `make build` after code changes to verify the binary compiles
- Merge back to `main` with `--no-ff` to preserve branch history

---

## Build and Deploy

```bash
# Local build (current OS/arch)
make build

# Cross-compile all platforms into dist/
make dist

# Deploy to remote server (detects arch, cross-compiles, installs, configures firewall)
make remote-install IP=x.x.x.x

# Re-apply firewall only (on the local/target machine)
make firewall

# Full removal
make uninstall
```

`make remote-install` is the standard deploy command. It handles everything: cross-compile, `scp` the binary + `install.sh` + `firewall.sh` + `nftables.conf`, run `install.sh` as root over SSH, and clean up temp files.

---

## Common Tasks for Agents

### 1. Adding a new HTTP capture port

Edit **two files** and redeploy:

**`main.go`** — add to `capturePorts` (line ~113):
```go
var capturePorts = []int{
    // ... existing ports ...
    NNNN, // description
}
```

**`firewall.sh`** — update `CAPTURE_PORTS_TCP` (line ~70) to include the same port:
```bash
CAPTURE_PORTS_TCP="..., NNNN"
```

Then rebuild and redeploy:
```bash
make remote-install IP=x.x.x.x
```

Do not change one file without the other.

### 2. Changing the dashboard port

The dashboard port is hardcoded as `:8999` in two places:

- `main.go:345` — `http.ListenAndServe(":8999", mux)`
- `main.go:212` — the log message `"Dashboard available at http://localhost:8999"`
- `install.sh:133` — the post-install hint line (cosmetic only)

The nftables firewall does **not** enumerate the dashboard port explicitly — it is covered by the subnet-only catch-all rule, so no firewall change is required when changing the dashboard port. After changing the port, rebuild and redeploy with `make remote-install IP=x.x.x.x`.

### 3. Adding a new field to ConnectionEvent

This touches three layers:

**`main.go` — struct definition (line ~20)**

Add the new field to `ConnectionEvent`:
```go
type ConnectionEvent struct {
    // ... existing fields ...
    NewField string `json:"new_field"`
}
```

Also populate it in `handleCapture()` where the struct is built (line ~241).

**`db.go` — schema, insert, and scan**

1. `createSchema()` (line ~58): add the column to the `CREATE TABLE` statement. If modifying an existing deployed database, also write a migration or drop and recreate the DB.
2. `insert()` (line ~88): add the new field to both the column list and the `VALUES` placeholder list, and append `ev.NewField` to the `Exec` arguments.
3. `loadHistory()` (line ~179): add the column to the `SELECT` list and add `&ev.NewField` to the `rows.Scan()` call. The order of columns in `SELECT` and `Scan` must match exactly.

**`static/index.html` — frontend**

Reference the new field as `ev.new_field` (matching the JSON tag) wherever the event is consumed: arc rendering, log entries, tooltip content, etc.

### 4. Adding a new TCP service port (non-HTTP)

Edit **four files** and redeploy:

**`services.go`** — add to `tcpServices` slice (around line 21):
```go
var tcpServices = []serviceEntry{
    // ... existing services ...
    {Port: NNNN, Name: "ServiceName", Banner: yourBannerFunc},
}
```

You must also define a `Banner()` function that returns the protocol-specific bytes to send immediately after accepting a connection. See existing banner functions (e.g., `ftpBanner()`, `sshBanner()`) for examples.

**`firewall.sh`** — update `CAPTURE_PORTS_TCP` (line ~70) to include the new port:
```bash
CAPTURE_PORTS_TCP="..., NNNN"
```

**`SERVICES.md`** — add a detailed entry for the new service documenting:
- Port number and service name
- Protocol description
- Banner content and format
- Why the banner is convincing to scanners

**`static/index.html`** — add an entry to the `PORT_SERVICE_NAMES` map (around line 992):
```js
'NNNN': 'ServiceName',
```

Then rebuild and redeploy:
```bash
make remote-install IP=x.x.x.x
```

Do not change one file without the other.

### 5. Adding a new UDP service port

Edit **four files** and redeploy:

**`services.go`** — add to `udpServicePorts` slice (around line 240):
```go
var udpServicePorts = []int{
    // ... existing ports ...
    NNNN, // description
}
```

**`firewall.sh`** — update `CAPTURE_PORTS_UDP` (line ~75) to include the new port:
```bash
CAPTURE_PORTS_UDP="..., NNNN"
```

**`SERVICES.md`** — add an entry to the UDP Capture Ports section documenting:
- Port number and service name
- Protocol description
- Why this port is targeted by scanners

**`static/index.html`** — add an entry to the `PORT_SERVICE_NAMES` map (around line 992):
```js
'NNNN': 'ServiceName',
```

Then rebuild and redeploy:
```bash
make remote-install IP=x.x.x.x
```

Do not change one file without the other.

### 6. Adding a new metric

Edit **`metrics.go`** to add a new metric type:

**In `metricsCache.Record()` or create a new record method:**
```go
func (mc *metricsCache) RecordNewMetric(labels map[string]string, value float64) {
    bucket := time.Now().UTC().Truncate(time.Hour).Format(time.RFC3339)
    labelStr := formatLabels(labels)
    key := cacheKey{name: "new_metric_name", labels: labelStr, bucket: bucket}
    
    mc.mu.Lock()
    mc.counters[key] += value
    mc.dirty[key] = true
    mc.mu.Unlock()
}
```

**In the `/api/metrics` handler:**
Add aggregation logic to include the new metric in the JSON response:
```go
// Query the new metric
newMetricData := appMetrics.queryMetrics("new_metric_name", from, to)
// Add to response struct
```

**In the `/metrics` Prometheus handler:**
Add exposition format output for the new metric:
```go
fmt.Fprintf(&buf, "# HELP webtraffik_new_metric_name Description\n")
fmt.Fprintf(&buf, "# TYPE webtraffik_new_metric_name counter\n")
// Add data lines
```

**Call the new record method** from the appropriate location:
- For connection-related metrics: add to `handleCapture()` in `main.go`
- For ban-related metrics: add to ban handlers in `ratelimit.go`
- For custom events: call from wherever the event occurs

The metrics system will automatically:
- Flush dirty counters to SQLite every 5 seconds
- Persist metrics across restarts
- Aggregate into hourly buckets
- Include in backfill operations

---

## Notes for Agents

- The `modernc.org/sqlite` driver requires no CGo. Do not substitute it with a CGo-based driver — it will break cross-compilation.
- `geo.go` uses an `atomic.Pointer[rgeo.Rgeo]` for the fallback geocoder. This is intentionally lock-free; do not add a mutex around `rgeo` access.
- The `hub.broadcast()` method snapshots subscribers under lock, then releases the lock before fan-out. Subscriber channel sends are non-blocking (`select/default`). This pattern keeps subscribe/unsubscribe operations fast even during high-traffic fan-out. Do not add blocking operations to the snapshot-and-send logic.
- `insert()` queues events into a buffered channel and never blocks. A dedicated `writeLoop()` goroutine drains the channel and batches writes into SQLite for high throughput. The `database/sql` pool handles concurrent reads safely.
- Static files are embedded at compile time via `static_embed.go`. Changes to `static/index.html` require a rebuild to take effect.
- The `tcpServices` slice in `services.go` owns all non-HTTP TCP emulation. Each entry has a `Banner()` func that returns the bytes sent immediately after accepting the connection. The `udpServicePorts` slice owns all UDP capture ports. Neither uses `net/http` — they use raw `net.Listener` / `net.ListenPacket`.
- When adding or removing services in `services.go`, update `SERVICES.md` to reflect the change. This file is the human-readable reference for all emulated services.
- When adding or removing services in `services.go`, also update the `PORT_SERVICE_NAMES` map in `static/index.html` to add or remove the corresponding port→name entry. This keeps the frontend log and panel labels in sync with the backend.
- The metrics system (`metrics.go`) maintains in-memory hourly-bucketed counters that are flushed to SQLite every 5 seconds. The flush loop is non-blocking — it snapshots dirty counters under lock, then writes to the database without holding the lock. Metrics survive restarts via SQLite persistence, and `backfillMetrics()` is called automatically on first run to aggregate existing events. Never add blocking operations to `Record()` methods — they are called from the capture path and must be fast.
- The port scan detection system (`internal/ratelimit/scanner.go`) tracks per-IP port hits in memory with a 10-minute sliding window. Detection is threshold-based (5 ports) with no auto-ban integration — it is purely observational. All operations are mutex-protected and non-blocking. The `gcLoop()` runs every 2 minutes to prune stale data. Never add blocking operations to `Record()` — it is called from the capture path via `Limiter.Record()`.
- The auto-ban rate limiter (`internal/ratelimit/ratelimit.go`) uses a dual-threshold design: flood detection (>2 connections/sec sustained for 10 minutes) and volume-window detection (30+ connections within any rolling 10-minute window). Bans are per-IP+port, not global. The sharded rate tracker (64 shards, FNV32a hash) avoids lock contention between different IPs. All operations are non-blocking and mutex-protected. Never add blocking operations to `Record()` — it is called from the capture path for every connection. The `IsBanned()` check uses a fast read-lock and is called at connection accept time in all TCP/HTTP handlers.
- The `internal/traceroute` package spawns an external `traceroute` or `tracepath` process and parses its stdout line-by-line. It requires one of these tools to be installed on the server (no Go-native ICMP implementation). The `/api/traceroute` SSE endpoint has a 60-second context timeout and validates that the target IP is public. The frontend suppresses live arc rendering while a traceroute animation is active (`tracerouteActive` flag). Only one traceroute can be active at a time — starting a new one cancels the previous via `cancelTrace()`.
