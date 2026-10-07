import { describe, expect, it } from 'vitest';
import {
  buildTracePath,
  correctImplausibleGeo,
  filterCountryLevelHops,
  filterImplausibleHops,
  GEO_ACCURACY_THRESHOLD,
  MIN_HOP_DELTA_MS,
  RTT_KM_PER_MS,
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
