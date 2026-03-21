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
  +-> appHub.broadcast(ev)
  |     - appends to in-memory ring buffer (historySize = 1000, oldest evicted)
  |     - fans out to all open WebSocket subscriber channels (non-blocking select)
  |
  +-> appDB.insert(ev)
        - fire-and-forget INSERT into SQLite events table
        - errors logged, never fatal, never blocks the capture path
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
- Tooltips: `#dot-tooltip` div, shown on `mouseover` of `.src-dot` elements via D3 event handlers, displays "City, CC" or just IP if geo unavailable
- Four corner overlay panels positioned absolutely on the map (no separate sidebars):
  - `#panel-port` (top-left): Traffic by Port — top 10 ports sorted by hit count, color swatch + port number + count
  - `#panel-service` (top-right): Top Services — top 10 services with bar charts showing relative traffic
  - `#panel-country` (bottom-left): Traffic by Country — top 10 countries by connection count
  - `#panel-ip` (bottom-right): Traffic by IP — top 10 source IPs by connection count
- Sidebar rendering decoupled from event processing: uses `requestIdleCallback` on a 2-second timer with dirty flags; only re-renders when data changes
- Log panel (`#log-panel`): scrolling list, capped at 200 entries, shows time/IP/city/CC/port; uses rAF-based rendering via `scheduleLogRender()` for low latency
- Arc lifecycle: gradient pooling (reuses SVG gradients by color pair instead of per-arc gradients), no glow filters on dots (only on self-dot), arc count capped at 150, dot count capped at 1000
- Arc animation lifespan: ~2.6 seconds (800ms draw + 1200ms hold + 600ms fade)

---

## Key Files and Responsibilities

| File | Owns |
|------|------|
| `main.go` | `ConnectionEvent` struct, `hub` (ring buffer + fan-out), HTTP capture listeners, dashboard server, `/ws` handler, `/api/self` endpoint, `capturePorts` var (HTTP-only ports) |
| `services.go` | TCP service port emulation (`tcpServices` with banners for FTP, SSH, Telnet, SMTP, etc.) and UDP port capture (`udpServicePorts`) |
| `SERVICES.md` | Detailed reference of all emulated TCP/UDP services and their protocol banners; must be kept in sync with `services.go` |
| `db.go` | SQLite open/close, schema creation, `insert()`, `loadHistory()` |
| `geo.go` | `GeoLocator` (GeoLite2 reader + rgeo fallback), `Lookup()`, `Location` struct |
| `geodb.go` | `ensureGeoDB()` — auto-download of `GeoLite2-City.mmdb` from GitHub mirror |
| `iputil.go` | `discoverPublicIP()` — queries external APIs to find the server's public IP |
| `static_embed.go` | `//go:embed static` directive; exposes `staticFiles fs.FS` |
| `static/index.html` | Entire browser UI: D3.js map, WebSocket client, arc animation, tooltips, corner panels, log |
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
CAPTURE_PORTS_TCP="80, 8080, 8000, 8008, 8081, 8088, 8090, 8888, \
3000, 3001, 3128, 4000, 4200, 5000, 5001, 9000, 9090, \
21, 22, 23, 25, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 27017"
```

This must include **all TCP ports** — both HTTP ports from `main.go` and service ports from `services.go` — as a comma-separated nftables set literal.

**5. `firewall.sh` — `CAPTURE_PORTS_UDP` variable (around line 75)**

```bash
CAPTURE_PORTS_UDP="53"
```

This must include **all UDP ports** from `services.go` as a comma-separated nftables set literal.

### Current port list

**TCP ports (main.go `capturePorts` — HTTP listeners):**
80, 8080, 8000, 8008, 8081, 8088, 8090, 8888, 3000, 3001, 3128, 4000, 4200, 5000, 5001, 9000, 9090

**TCP service ports (services.go `tcpServices` — raw TCP listeners with banners):**
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 445 (SMB), 1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB), 5900 (VNC), 8443 (HTTPS-Alt), 9200 (Elasticsearch), 11211 (Memcached)

**UDP ports (services.go `udpServicePorts` — UDP listeners):**
53 (DNS), 123 (NTP), 161 (SNMP), 1900 (SSDP), 5060 (SIP)

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
