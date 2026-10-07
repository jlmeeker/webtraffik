# AGENTS.md — webTraffik

Orientation for AI agents (and humans) working in this repo. It records what the
code cannot tell you: invariants, gotchas and the workflow. For *how things
work*, read the code — packages are small and commented. User docs live in
`README.md`; protocol notes in `SERVICES.md`; the port list in `docs/PORTS.md`
(generated).

## What it is

A network sensor + honeypot. Listeners (and optionally an eBPF/XDP program)
observe connection attempts, the app enriches them (geo, ASN), stores them in
SQLite and streams them to a browser map over WebSocket.

Go (single binary, **no CGo** — `modernc.org/sqlite` — keep it that way; it keeps
cross-compilation trivial). eBPF via `github.com/cilium/ebpf`. Frontend in `web/`.

## Layout

| Path | Owns |
|------|------|
| `cmd/webtraffik` | `main`, flags/config (`flags.go`, `config.go`), `ports` subcommand |
| `internal/app` | capture pipeline: `Submit()` → bounded queue → workers → hub/DB/metrics/export; ordered shutdown; `Status()` |
| `internal/server` | dashboard HTTP: auth, origin checks, API, `/ws`, traceroute SSE |
| `internal/services` | **port registry** (`registry.go`) and every listener: HTTP/TLS honeypot, SSH, Telnet, FTP/SMTP/POP3/Redis, banner services, UDP; payload classifier (`classify.go`); JA3/JA4 (`tlscap.go`) |
| `internal/ebpf` | XDP program + manager (bans, telemetry, event stream); compiled objects are committed |
| `internal/ratelimit` | auto-ban (flood + volume windows), port-scan detector, ban persistence, eBPF ban sync |
| `internal/db` | SQLite: versioned migrations (`migrate.go`), event/ban/metrics storage, retention |
| `internal/geo` | GeoLite2 City + ASN readers, validated atomic refresh |
| `internal/hub`, `event`, `metrics`, `traceroute`, `iputil` | fan-out ring buffer, `ConnectionEvent`, hourly metrics, traceroute runner, public-IP discovery |
| `web/` | frontend source (built output is committed and embedded) |
| `firewall.sh`, `nftables.conf`, `install.sh`, `webtraffik.service` | deployment |

## Invariants — do not break these

1. **The capture path never blocks.** Listeners call `Capture` (= `App.Submit`),
   which enqueues or drops (counted). Never add blocking work, locks held across
   I/O, or a goroutine-per-event to `Submit`, `Hub.Broadcast`, `Metrics.Record`,
   `Limiter.Record` or `DB.Insert`.
2. **One port registry.** Ports are defined only in `internal/services/registry.go`
   (+ `banners.go` for banner-only services). `firewall.sh` reads them from the
   binary (`webtraffik ports`); the UI reads `/api/services`; `docs/PORTS.md` is
   generated (`make docs`, enforced by a test). Never hand-copy a port list.
3. **Ordered shutdown** (`App.Run`): listeners stop → bg loops → XDP detach →
   queue closed/drained → metrics final flush → DB writer drained → geo closed.
   `Submit` is safe after close (it no-ops).
4. **Schema changes are migrations.** Append to `migrations` in `internal/db/migrate.go`;
   never edit an applied one. Tests cover the legacy → current upgrade.
5. **eBPF**: `ban_map` keys/events are 16-byte v4-mapped addresses (IPv4 + IPv6);
   `expires_at` is `bpf_ktime_get_ns()` (since boot), **not** Unix time. Go
   structs (`banKey`, `ipKey`, `RawEvent`) must match `capture.bpf.c` byte for
   byte. After editing the C file run `make ebpf-gen` and **commit the regenerated
   `.o`/`.go`** (CI diffs them). The program must keep passing `TestProgramLoads`
   (kernel verifier) and works unprivileged with `CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON`
   — `CAP_SYS_ADMIN` is not needed (verified). Events fire per SYN/UDP/ICMP, not
   per packet; multicast/broadcast destinations (mDNS, SSDP, DHCP, IPv6 ND…) are
   ignored entirely (`TestXDPIgnoresMulticastAndBroadcast` runs real packets via
   `BPF_PROG_TEST_RUN`). `Manager` methods are no-ops when inactive; don't nil-check.
6. **Security defaults.** The dashboard may be exposed: keep the Basic-auth path,
   the Origin check on POST/WebSocket, JSON-only POST bodies, input validation in
   `parseBanRequest`, the traceroute concurrency cap and public-IP check, and the
   CSP (no CDN — assets are self-hosted). Credentials never go into `detail`
   (they live in `meta`).
7. **Honeypot hygiene.** Emulators must bound everything they read (line length,
   line count, deadline) — they parse hostile input. Add a test with hostile input
   for any new parser (see `TestRESPParserBounds`, `TestParseClientHelloGarbage`).

## Adding things

- **Service**: see "Maintenance" in `SERVICES.md` (registry entry + name + handler,
  `make docs`, test).
- **Config option**: field in `Config` (+ yaml tag = flag name), default in
  `defaultConfig()`, flag in `parseConfig`, wire in `buildOptions`, document in
  `config.yaml.example` and the README.
- **Event field**: `event.ConnectionEvent` → migration + `eventColumns`/`scanEvent`/
  insert in `internal/db` → UI.
- **API endpoint**: `Server.Handler()`; keep responses backward compatible (the UI
  tolerates unknown fields, not missing ones).
- **Classifier tag**: `payloadSignatures`/`uaSignatures` in `classify.go` + a case in
  `TestClassify`.

## Workflow

```
make check          # gofmt, vet, go test -race (what CI runs)
make ebpf-check     # regenerate BPF objects, fail on diff (needs clang)
make docs           # regenerate docs/PORTS.md
go build ./cmd/webtraffik && ./webtraffik -capture-mode=go-only -dashboard-listen=127.0.0.1:8999
```

- Tests that need geo data build a fake MaxMind DB with `internal/testutil`
  (`WriteCityDB`) — no network. `internal/server/server_test.go` is the end-to-end
  harness (real app + HTTP + WebSocket, no ports bound).
- Frontend: `make web-check` (tsc, eslint, vitest); Playwright e2e in `web/tests/e2e`.
  After touching `web/src`, run `make web` and commit the regenerated `web/dist`
  (CI fails on drift). Traceroute filtering constants live in `web/src/traceroute/filter.ts`.
- Branches: `feature/*`, `bugfix/*`, `refactor/*`, `docs/*`; merge to `main`.
- Sandboxes often cannot reach GitHub release mirrors: the GeoLite download will
  fail there; use `testutil` or drop `GeoLite2-City.mmdb` in the data dir.

## Deployment gotchas

- `make remote-install IP=…` ships binary + `install.sh` + `firewall.sh` +
  `nftables.conf` + unit + config example. Fresh installs generate a dashboard
  password (printed once; stored in `/etc/webtraffik/dashboard.pass`).
- If you pass `-disable-ports` (e.g. real SSH on 22), export the same list to
  `firewall.sh` via `DISABLE_PORTS`, or the firewall opens ports nobody serves.
- The firewall template flushes `table inet filter`; management traffic is allowed
  only from the detected local subnet. The dashboard port is deliberately not in
  the public capture sets.
- `systemctl reload webtraffik` only re-reads `mgmt-allow-file`; everything else
  needs a restart.
