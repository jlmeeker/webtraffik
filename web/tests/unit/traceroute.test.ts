import { describe, expect, it } from 'vitest';
import {
  buildTracePath,
  correctImplausibleGeo,
  filterCountryLevelHops,
  filterImplausibleHops,
  GEO_ACCURACY_THRESHOLD,
  GEO_ACCURACY_THRESHOLD_STRICT,
  isTraceMode,
  MIN_HOP_DELTA_MS,
  RTT_KM_PER_MS,
  RTT_KM_PER_MS_STRICT,
} from '../../src/traceroute/filter';
import type { Hop } from '../../src/lib/types';

const hop = (ip: string, lat: number, lon: number, rtt?: number, accuracy_km?: number): Hop => ({
  ip,
  lat,
  lon,
  ...(rtt !== undefined ? { rtt } : {}),
  ...(accuracy_km !== undefined ? { accuracy_km } : {}),
});

describe('filterCountryLevelHops', () => {
  it('drops hops at/above the accuracy threshold and keeps the rest', () => {
    const hops = [hop('a', 1, 1, 1, 10), hop('b', 2, 2, 2, GEO_ACCURACY_THRESHOLD), hop('c', 3, 3, 3, 1000), hop('d', 4, 4, 4)];
    expect(filterCountryLevelHops(hops).map((h) => h.ip)).toEqual(['a', 'd']);
  });
  it('honours a custom threshold', () => {
    expect(filterCountryLevelHops([hop('a', 0, 0, 1, 150)], 200)).toHaveLength(1);
    expect(filterCountryLevelHops([hop('a', 0, 0, 1, 250)], 200)).toHaveLength(0);
  });
});

describe('filterImplausibleHops', () => {
  it('returns [] for empty input and keeps a lone hop', () => {
    expect(filterImplausibleHops([])).toEqual([]);
    expect(filterImplausibleHops([hop('a', 0, 0, 1)])).toHaveLength(1);
  });
  it('drops same-location routers (delta <= MIN_HOP_DELTA_MS)', () => {
    const hops = [hop('a', 51.5, -0.1, 1), hop('b', 51.5, -0.1, 1 + MIN_HOP_DELTA_MS), hop('c', 48.8, 2.3, 10)];
    expect(filterImplausibleHops(hops).map((h) => h.ip)).toEqual(['a', 'c']);
  });
  it('drops hops whose distance exceeds the RTT budget', () => {
    // London → New York (~5570 km) in a 5 ms delta: budget = 5 * RTT_KM_PER_MS = 2500 km → implausible
    const hops = [hop('lon', 51.5, -0.1, 1), hop('nyc', 40.7, -74, 6), hop('par', 48.8, 2.3, 10)];
    expect(filterImplausibleHops(hops).map((h) => h.ip)).toEqual(['lon', 'par']);
    expect(5 * RTT_KM_PER_MS).toBeLessThan(5500);
  });
  it('keeps plausible long hops and compares against the last kept hop', () => {
    // London → New York in 40 ms delta: budget 20 000 km → plausible
    const hops = [hop('lon', 51.5, -0.1, 1), hop('nyc', 40.7, -74, 41)];
    expect(filterImplausibleHops(hops)).toHaveLength(2);
  });
  it('keeps hops lacking RTT', () => {
    const hops = [hop('a', 0, 0), hop('b', 60, 100, 2)];
    expect(filterImplausibleHops(hops)).toHaveLength(2);
  });
});

describe('correctImplausibleGeo (clamp strategy)', () => {
  it('clamps an implausible hop to the previous hop position without mutating input', () => {
    const hops = [hop('lon', 51.5, -0.1, 1), hop('nyc', 40.7, -74, 3)];
    const out = correctImplausibleGeo(hops);
    expect(out[1]!.lat).toBe(51.5);
    expect(out[1]!.lon).toBe(-0.1);
    expect(hops[1]!.lat).toBe(40.7);
  });
  it('leaves plausible hops untouched', () => {
    const hops = [hop('lon', 51.5, -0.1, 1), hop('par', 48.8, 2.3, 10)];
    const out = correctImplausibleGeo(hops);
    expect(out[1]).toMatchObject({ lat: 48.8, lon: 2.3 });
  });
});

describe('buildTracePath', () => {
  const self = { ip: '9.9.9.9', lat: 51.5, lon: -0.1, city: 'London', cc: 'GB' };
  it('reverses hops, drops the target IP, prepends srcGeo and appends self', () => {
    const raw = [hop('r1', 51.4, -0.2, 1, 10), hop('r2', 48.8, 2.3, 12, 10), hop('1.2.3.4', 48.9, 2.4, 20, 10)];
    const path = buildTracePath(raw, '1.2.3.4', { srcGeo: { lat: 45, lon: 5, city: 'Lyon', cc: 'FR' }, self });
    expect(path.map((p) => p.ip)).toEqual(['1.2.3.4', 'r2', 'r1', '9.9.9.9']);
    expect(path[0]).toMatchObject({ lat: 45, lon: 5, city: 'Lyon' });
    expect(path.at(-1)).toMatchObject({ ip: '9.9.9.9', city: 'London' });
  });
  it('does not duplicate the source when the first hop already sits there', () => {
    const raw = [hop('r1', 45, 5, 5, 10)];
    const path = buildTracePath(raw, 'x', { srcGeo: { lat: 45, lon: 5 } });
    expect(path).toHaveLength(1);
  });
  it('skips hops without coordinates and country-level centroids', () => {
    const raw = [hop('r1', 0, 0, 1), hop('r2', 37.75, -97.82, 5, 1000), hop('r3', 48.8, 2.3, 9, 20)];
    const path = buildTracePath(raw, 'x');
    expect(path.map((p) => p.ip)).toEqual(['r3']);
  });
});

describe('buildTracePath modes', () => {
  it("'default' mode is identical to omitting the mode", () => {
    const raw = [hop('r1', 51.4, -0.2, 1, 10), hop('r2', 40.7, -74, 6, 300), hop('r3', 48.8, 2.3, 12, 450), hop('r4', 37, -97, 14, 800)];
    expect(buildTracePath(raw, 'x', { mode: 'default' })).toEqual(buildTracePath(raw, 'x'));
  });

  it('strict uses the 200 km accuracy cut-off (default keeps up to 500)', () => {
    const raw = [hop('r1', 51.4, -0.2, 1, 150), hop('r2', 48.8, 2.3, 20, 300)];
    expect(GEO_ACCURACY_THRESHOLD_STRICT).toBe(200);
    expect(buildTracePath(raw, 'x').map((p) => p.ip)).toEqual(['r2', 'r1']);
    expect(buildTracePath(raw, 'x', { mode: 'strict' }).map((p) => p.ip)).toEqual(['r1']);
  });

  it('strict clamps an implausible hop instead of dropping it', () => {
    // London -> New York in 8 ms: default budget 4000 km (drop), strict budget 2400 km (clamp).
    const raw = [hop('lon', 51.5, -0.1, 1, 10), hop('nyc', 40.7, -74, 9, 10), hop('par', 48.8, 2.3, 60, 10)];
    const def = buildTracePath(raw, 'x');
    expect(def.map((p) => p.ip)).toEqual(['par', 'lon']);
    const strict = buildTracePath(raw, 'x', { mode: 'strict' });
    // nyc is clamped onto lon, then collapsed with it (same coordinates); path stays ordered.
    expect(strict.map((p) => p.ip)).toEqual(['par', 'lon']);
    expect(strict.every((p) => !(p.lat === 40.7 && p.lon === -74))).toBe(true);
  });

  it('strict keeps hops that default would drop as too close in RTT, minus co-located duplicates', () => {
    const raw = [hop('a', 51.5, -0.1, 1, 10), hop('b', 48.8, 2.3, 30, 10), hop('c', 52.5, 13.4, 45, 10)];
    expect(buildTracePath(raw, 'x', { mode: 'strict' }).map((p) => p.ip)).toEqual(['c', 'b', 'a']);
  });

  it('strict mode uses 300 km/ms (stricter than the default 500)', () => {
    expect(RTT_KM_PER_MS_STRICT).toBeLessThan(RTT_KM_PER_MS);
    // London -> Prague is ~1030 km over 3.3 ms: strict budget 990 km (clamped), default 1650 km (kept).
    const raw = [hop('lon', 51.5, -0.1, 10, 10), hop('prg', 50.08, 14.43, 13.3, 10)];
    expect(buildTracePath(raw, 'x').map((p) => p.ip)).toEqual(['prg', 'lon']);
    expect(buildTracePath(raw, 'x', { mode: 'strict' }).map((p) => p.ip)).toEqual(['lon']);
  });

  it('explicit thresholds override the mode', () => {
    const raw = [hop('r1', 51.4, -0.2, 1, 150), hop('r2', 48.8, 2.3, 20, 300)];
    expect(buildTracePath(raw, 'x', { mode: 'strict', accuracyThresholdKm: 500 }).map((p) => p.ip)).toEqual(['r2', 'r1']);
  });

  it('isTraceMode validates stored values', () => {
    expect(isTraceMode('strict')).toBe(true);
    expect(isTraceMode('default')).toBe(true);
    expect(isTraceMode('loose')).toBe(false);
    expect(isTraceMode(null)).toBe(false);
  });
});
