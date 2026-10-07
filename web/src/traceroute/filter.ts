// Pure traceroute hop post-processing. Ported from the legacy index.js so the
// behaviour (and its tuning) is preserved exactly; see README for rationale.

import type { GeoPoint, Hop } from '../lib/types';
import { haversineKm } from '../lib/utils/geo';

/**
 * Accuracy radius (km) at/above which a hop counts as a country-level
 * centroid (MaxMind returns ~1000 km for country-only resolutions, 1–50 km
 * for city-level, 150–400 km for many ISP backbone routers).
 * The AGENTS.md design note quotes 200 km; the shipped UI raised it to 500 km
 * to keep backbone routers while still dropping true country centroids.
 */
export const GEO_ACCURACY_THRESHOLD = 500;

/**
 * Maximum plausible one-way distance (km) per ms of RTT delta.
 * Light in fibre ≈ 100 km per ms of *round-trip* time; multiplied by a
 * routing-overhead margin. The documented value is 3× (300 km/ms); the
 * shipped UI uses 5× (500 km/ms) because US backbone hops reach ~400 km/ms.
 */
export const RTT_KM_PER_MS = 100 * 5;

/** Documented (stricter) alternative used by correctImplausibleGeo(). */
export const RTT_KM_PER_MS_STRICT = 100 * 3;

/**
 * Consecutive hops closer than this many ms of RTT are the same location
 * (two routers in one datacenter) — not worth an arc.
 */
export const MIN_HOP_DELTA_MS = 3;

export interface FilterOptions {
  accuracyThresholdKm?: number;
  kmPerMs?: number;
  minHopDeltaMs?: number;
}

/** Drop hops whose geolocation is only country-level (large accuracy radius). */
export function filterCountryLevelHops(hops: readonly Hop[], threshold: number = GEO_ACCURACY_THRESHOLD): Hop[] {
  return hops.filter((h) => !h.accuracy_km || h.accuracy_km < threshold);
}

/**
 * Keep only hops that form a geographically plausible path.
 * Rules, each applied against the last *kept* hop:
 *   1. deltaRTT <= minHopDeltaMs → drop (same location, different router)
 *   2. great-circle distance > deltaRTT × kmPerMs → drop (GeoIP is wrong)
 * Hops lacking RTT are kept (we cannot judge them).
 * Call after filterCountryLevelHops().
 */
export function filterImplausibleHops(hops: readonly Hop[], opts: FilterOptions = {}): Hop[] {
  const kmPerMs = opts.kmPerMs ?? RTT_KM_PER_MS;
  const minDelta = opts.minHopDeltaMs ?? MIN_HOP_DELTA_MS;
  if (hops.length === 0) return [];
  const kept: Hop[] = [hops[0]!];
  for (let i = 1; i < hops.length; i++) {
    const prev = kept[kept.length - 1]!;
    const curr = hops[i]!;
    if (!prev.rtt || !curr.rtt) {
      kept.push(curr);
      continue;
    }
    const deltaRTT = curr.rtt - prev.rtt;
    if (deltaRTT <= minDelta) continue;
    const maxKm = deltaRTT * kmPerMs;
    const actualKm = haversineKm(prev.lat, prev.lon, curr.lat, curr.lon);
    if (actualKm > maxKm) continue;
    kept.push(curr);
  }
  return kept;
}

/**
 * Alternative "clamp" strategy (as documented in AGENTS.md): instead of
 * dropping an implausible hop, overwrite its lat/lon with the previous hop's
 * so route directionality is preserved without inventing coordinates.
 * Returns a new array with copied hop objects (input is not mutated).
 */
export function correctImplausibleGeo(hops: readonly Hop[], kmPerMs: number = RTT_KM_PER_MS_STRICT): Hop[] {
  const out: Hop[] = hops.map((h) => ({ ...h }));
  for (let i = 1; i < out.length; i++) {
    const prev = out[i - 1]!;
    const curr = out[i]!;
    if (prev.rtt === undefined || curr.rtt === undefined || !prev.rtt || !curr.rtt) continue;
    const deltaRTT = curr.rtt - prev.rtt;
    const budgetKm = Math.max(0, deltaRTT) * kmPerMs;
    const dist = haversineKm(prev.lat, prev.lon, curr.lat, curr.lon);
    if (dist > budgetKm) {
      curr.lat = prev.lat;
      curr.lon = prev.lon;
    }
  }
  return out;
}

/** Documented accuracy cut-off used by the strict trace mode (km). */
export const GEO_ACCURACY_THRESHOLD_STRICT = 200;

/**
 * 'default' = shipped behaviour (500 km, 500 km/ms, drop implausible hops).
 * 'strict'  = documented variant (200 km, 300 km/ms, clamp implausible hops
 *             onto the previous hop instead of dropping them).
 */
export type TraceMode = 'default' | 'strict';

export function isTraceMode(v: unknown): v is TraceMode {
  return v === 'default' || v === 'strict';
}

/** Collapse consecutive hops that sit at identical coordinates (post-clamp). */
function collapseCoLocated(hops: readonly Hop[]): Hop[] {
  const out: Hop[] = [];
  for (const h of hops) {
    const last = out[out.length - 1];
    if (last && last.lat === h.lat && last.lon === h.lon) continue;
    out.push(h);
  }
  return out;
}

export interface TracePathOptions extends FilterOptions {
  /** Pipeline variant; explicit accuracyThresholdKm / kmPerMs still win. */
  mode?: TraceMode;
  /** Known geolocation of the traced IP (prepended as first point). */
  srcGeo?: GeoPoint | null;
  /** Our own server position (appended as last point). */
  self?: (GeoPoint & { ip?: string }) | null;
}

/** Points consumed by the animator: ordered from the remote source to us. */
export interface TracePoint {
  ip: string;
  lat: number;
  lon: number;
  city: string;
  cc: string;
}

/**
 * Full pipeline used by the live page:
 *  raw SSE hops → drop target IP → country filter → plausibility filter →
 *  reverse (source → us) → prepend srcGeo → append self.
 */
export function buildTracePath(rawHops: readonly Hop[], targetIP: string, opts: TracePathOptions = {}): TracePoint[] {
  const withGeo = rawHops.filter((h) => h && (h.lat || h.lon));
  // traceroute reports the destination as a hop with rtt≈0 — srcGeo covers it.
  const intermediate = withGeo.filter((h) => h.ip !== targetIP);
  const strict = opts.mode === 'strict';
  const cityHops = filterCountryLevelHops(intermediate, opts.accuracyThresholdKm ?? (strict ? GEO_ACCURACY_THRESHOLD_STRICT : GEO_ACCURACY_THRESHOLD));
  // Strict clamps implausible geo onto the previous hop (keeping the route's
  // shape); the co-located duplicates this creates are then collapsed so no
  // zero-length arcs are drawn.
  const plausible = strict
    ? collapseCoLocated(correctImplausibleGeo(cityHops, opts.kmPerMs ?? RTT_KM_PER_MS_STRICT))
    : filterImplausibleHops(cityHops, opts);
  // traceroute runs FROM us TO them; reverse so the path flows inward.
  const path: TracePoint[] = [...plausible].reverse().map((h) => ({
    ip: h.ip,
    lat: h.lat,
    lon: h.lon,
    city: h.city ?? '',
    cc: h.cc ?? '',
  }));

  const src = opts.srcGeo;
  if (src && (src.lat || src.lon)) {
    const first = path[0];
    if (!first || first.lat !== src.lat || first.lon !== src.lon) {
      path.unshift({ ip: targetIP, lat: src.lat, lon: src.lon, city: src.city ?? '', cc: src.cc ?? '' });
    }
  }
  const self = opts.self;
  if (self && (self.lat || self.lon)) {
    path.push({ ip: self.ip ?? '', lat: self.lat, lon: self.lon, city: self.city ?? '', cc: self.cc ?? '' });
  }
  return path;
}
