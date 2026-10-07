import { describe, expect, it } from 'vitest';
import { geoDistKm, haversineKm, hasGeo, MAX_GEO_DIST_KM } from '../../src/lib/utils/geo';
import { ensureInt, fmtNum, fmtUptime, formatTimeAgo, formatTimeRemaining, hexPreview, localDateTimeStr, localDateTimeToUTC, placeLabel } from '../../src/lib/utils/format';
import { backoffDelay } from '../../src/lib/ws';
import { toneFor } from '../../src/map/audio';

describe('haversine', () => {
  it('is zero for identical points', () => {
    expect(haversineKm(10, 20, 10, 20)).toBe(0);
  });
  it('matches known distances (London–New York ≈ 5570 km)', () => {
    const d = haversineKm(51.5074, -0.1278, 40.7128, -74.006);
    expect(d).toBeGreaterThan(5500);
    expect(d).toBeLessThan(5600);
  });
  it('is symmetric and geoDistKm takes [lon, lat]', () => {
    expect(haversineKm(1, 2, 3, 4)).toBeCloseTo(haversineKm(3, 4, 1, 2), 9);
    expect(geoDistKm([2, 1], [4, 3])).toBeCloseTo(haversineKm(1, 2, 3, 4), 9);
  });
  it('antipodes are half the circumference', () => {
    expect(haversineKm(0, 0, 0, 180)).toBeCloseTo(MAX_GEO_DIST_KM, -1);
  });
  it('hasGeo rejects 0,0 and non-finite', () => {
    expect(hasGeo(0, 0)).toBe(false);
    expect(hasGeo(NaN, 1)).toBe(false);
    expect(hasGeo(1.5, 0)).toBe(true);
  });
});

describe('formatters', () => {
  it('fmtNum', () => {
    expect(fmtNum(999)).toBe('999');
    expect(fmtNum(1234)).toBe('1.2K');
    expect(fmtNum(2_500_000)).toBe('2.5M');
    expect(fmtNum(3e9)).toBe('3.0B');
    expect(fmtNum(null)).toBe('—');
  });
  it('formatTimeAgo / formatTimeRemaining', () => {
    const now = Date.UTC(2026, 0, 1, 12, 0, 0);
    expect(formatTimeAgo(new Date(now - 5000).toISOString(), now)).toBe('5s ago');
    expect(formatTimeAgo(new Date(now - 135_000).toISOString(), now)).toBe('2m 15s ago');
    expect(formatTimeAgo(new Date(now - 3_720_000).toISOString(), now)).toBe('1h 2m ago');
    expect(formatTimeAgo(new Date(now + 1000).toISOString(), now)).toBe('just now');
    expect(formatTimeRemaining(new Date(now + 59_000).toISOString(), now)).toBe('59s');
    expect(formatTimeRemaining(new Date(now + 3_660_000).toISOString(), now)).toBe('1h 1m');
    expect(formatTimeRemaining(new Date(now - 1).toISOString(), now)).toBe('expiring');
    expect(formatTimeAgo('garbage', now)).toBe('');
  });
  it('fmtUptime', () => {
    expect(fmtUptime(45)).toBe('45s');
    expect(fmtUptime(182)).toBe('3m 2s');
    expect(fmtUptime(7260)).toBe('2h 1m');
  });
  it('hexPreview renders hex + ascii columns', () => {
    const out = hexPreview('474554202f20485454502f312e310d0a');
    expect(out).toBe('0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..');
    expect(hexPreview('')).toBe('');
    expect(hexPreview('41'.repeat(17)).split('\n')).toHaveLength(2);
  });
  it('local datetime round-trips', () => {
    const d = new Date(2026, 4, 6, 7, 8, 9);
    expect(localDateTimeStr(d)).toBe('2026-05-06T07:08:09');
    expect(localDateTimeToUTC('2026-05-06T07:08:09')).toBe(d.toISOString());
    expect(localDateTimeToUTC('')).toBe('');
    expect(localDateTimeToUTC('nope')).toBe('');
  });
  it('placeLabel and ensureInt', () => {
    expect(placeLabel('Paris', 'FR')).toBe('Paris, FR');
    expect(placeLabel('', 'FR', 'x')).toBe('FR');
    expect(placeLabel(undefined, undefined, '1.2.3.4')).toBe('1.2.3.4');
    expect(ensureInt('12', 1, 24, 1)).toBe(12);
    expect(ensureInt('99', 1, 24, 1)).toBe(24);
    expect(ensureInt('abc', 1, 24, 7)).toBe(7);
  });
});

describe('backoffDelay', () => {
  it('grows exponentially with jitter and is clamped', () => {
    const r = () => 0.5; // zero jitter
    expect(backoffDelay(1, 1000, 30000, r)).toBe(1000);
    expect(backoffDelay(2, 1000, 30000, r)).toBe(2000);
    expect(backoffDelay(4, 1000, 30000, r)).toBe(8000);
    expect(backoffDelay(10, 1000, 30000, r)).toBe(30000);
    for (let i = 0; i < 50; i++) {
      const d = backoffDelay(3, 1000, 30000);
      expect(d).toBeGreaterThanOrEqual(3200);
      expect(d).toBeLessThanOrEqual(4800);
    }
  });
});

describe('toneFor', () => {
  it('nearby = short high tone, antipodal = long low tone', () => {
    const near = toneFor([0, 0], [0.1, 0.1]);
    const far = toneFor([0, 0], [180, 0]);
    expect(near.freq).toBeGreaterThan(far.freq);
    expect(near.duration).toBeLessThan(far.duration);
    expect(far.duration).toBeCloseTo(0.5, 2);
  });
});
