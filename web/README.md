# webTraffik frontend (`web/`)

The browser dashboard: a Vite + TypeScript (strict) multi-page app with D3 v7
and topojson-client **bundled** — nothing is fetched from a CDN at runtime.
The world map (`sane-topojson` 110m: land, borders, lakes, rivers) ships as a
hashed local asset.

## Pages

| URL             | Entry           | What it does |
|-----------------|-----------------|--------------|
| `/`             | `index.html` → `src/pages/live.ts`    | Live map: WebSocket stream, arcs + dots, tooltips (ban/unban/trace), traceroute animation, Top Services / Capture Mode / Port Scanners / Banned / Last Seen panels, magnifier inset, log, pause/resume, replay-window slider, sound toggle, theme toggle |
| `/history.html` | `history.html` → `src/pages/history.ts` | Filters (country, IP, port, service, from/to + presets) over `/api/history` + `/api/metrics`; KPI tiles, D3 charts, eBPF stats, result table |
| `/recent.html`  | `recent.html` → `src/pages/recent.ts`   | Ring-buffer snapshot from `/api/recent` with hex dumps of `client_data`, service/limit filters, expand-all |

## Build / embed

```
make web          # cd web && npm ci && npm run build  → web/dist
make web-check    # typecheck + lint + unit tests
```

`web/dist` is **committed** and embedded by `web/embed.go` (`web.FS`), which
`cmd/webtraffik/static_embed.go` serves at `/`. Plain `go build` therefore
needs no Node. After changing anything in `web/src`, run `make web` and commit
the regenerated `web/dist`. (`.gitignore` at the repo root ignores `dist/`;
`web/.gitignore` re-includes ours.)

## Develop

```
cd web
npm ci
npm run dev            # Vite dev server on :5173, proxies /api and /ws to :8999
npm run typecheck      # tsc --noEmit
npm run lint           # eslint
npm run test           # vitest (pure logic)
npm run test:e2e       # playwright smoke test against the built dist (run `npm run build` first)
```

Playwright uses the Chromium at `/opt/pw-browsers/chromium` when present
(override with `PW_CHROMIUM=/path/to/chrome`); set
`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` to avoid downloads. The e2e suite serves
`dist/` with `vite preview` and mocks every `/api/*` route and the `/ws`
socket (`tests/e2e/mocks.ts`), so no backend is required.
`SHOTS_DIR=/tmp/shots npx playwright test screenshots` captures review
screenshots of every page in both themes and viewports.

## Source layout

```
src/
  lib/
    types.ts        API contract types (unknown fields tolerated)
    api.ts          fetch wrapper (credentials: same-origin), SSE traceroute client
    ws.ts           LiveStream: auto-reconnect with exponential backoff + jitter
    store.ts        pure reducers for the live state (window eviction, port slots, last-seen)
    services.ts     ServiceRegistry: port→name from /api/services (+ small fallback)
    palette.ts      categorical colour slots (fixed order, fold past 8 into "other")
    theme.ts        dark/light (prefers-color-scheme + toggle), CSS token access
    chrome.ts       shared header wiring (theme toggle, nav, /api/self)
    utils/          format, geo (haversine), dom, prefs
  map/
    view.ts         MapView: Natural Earth projection, projection-based zoom, layers
    geometry.ts     pure arc geometry, fit transform, width/radius curves
    arcs.ts         ArcLayer: arcs, dots, pulses, flood batching, TTL, caps (150 arcs / 1000 dots)
    magnifier.ts    Mercator inset for short/clipped arcs
    tooltip.ts      dot hover card (Trace route / Ban / Unban)
    audio.ts        Web Audio event tones
    world.ts        bundled topojson loader
  traceroute/
    filter.ts       hop pipeline (country-centroid filter, RTT plausibility, path build)
    animate.ts      SSE → staggered arc animation, zoom-to-fit, Escape cancel
  panels/           Top Services, Last Seen, Port Scanners, Banned, Capture Mode, idle scheduler
  log.ts            rAF-batched live log (200 rows), shared row builder
  charts/           D3 charts for history (columns, lines, horizontal bars, tiles, meter)
  history/aggregate.ts  pure metric aggregation
  recent/filter.ts  pure recent-events filter
  styles/           theme tokens + per-page CSS
tests/unit          vitest
tests/e2e           playwright (smoke + screenshots)
```

## Traceroute correction constants

`src/traceroute/filter.ts` ports the shipped `index.js` pipeline exactly:

* `GEO_ACCURACY_THRESHOLD = 500` km — hops with `accuracy_km >= 500` are
  country-level centroids and are dropped. (AGENTS.md documents 200 km; the
  shipped UI raised it to 500 km so ISP backbone routers at 150–400 km are kept.)
* `RTT_KM_PER_MS = 500` (100 km/ms × 5 routing overhead) and
  `MIN_HOP_DELTA_MS = 3` — `filterImplausibleHops()` drops hops that are
  same-location (ΔRTT ≤ 3 ms) or whose haversine distance exceeds
  `ΔRTT × 500 km`. (AGENTS.md documents 300 km/ms with a *clamp*; that variant
  is available as `correctImplausibleGeo()` with `RTT_KM_PER_MS_STRICT = 300`
  but is not in the default pipeline, matching the previous UI.)

Pipeline: drop target IP → country filter → plausibility filter → reverse
(source → us) → prepend the source's known geo → append our own position.

## Design notes

* Colour tokens live in `src/styles/theme.css`; dark is default, light is
  selected via `prefers-color-scheme` or `data-theme`. The eight categorical
  series colours are the validated colour-blind-safe order (do not reorder or
  generate a 9th; `--series-other` is the fold).
* `prefers-reduced-motion` disables pulses, arc/dot transitions and the
  staggered traceroute draw (static path instead).
* Mobile (≤ 860 px): the panel stacks become drawers toggled by the two buttons
  over the map; the magnifier is hidden.
* Keyboard: log rows and Last Seen entries are buttons (Enter/Space → trace),
  Banned rows have an Unban button, Space pauses/resumes, Escape cancels a
  trace. Map dots themselves are hover/double-click targets only (there can be
  1000 of them); the same actions are reachable from the log.
* Performance caps preserved from the previous UI: 150 arcs, 1000 dots, 80
  pulses, flood batching above 10 events/s, idle-callback panel renders every
  2 s with dirty flags, rAF-batched log.
* Pause buffers up to 5000 events; on resume they are applied as replay
  (dots/log/stats, no arcs).
