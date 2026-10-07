import { describe, expect, it } from 'vitest';
import { banKey, createLiveState, evictExpired, recordEvent, resetLiveState, Signal, topPorts, updateLastSeen } from '../../src/lib/store';
import { FALLBACK_SERIES, SERIES_SLOTS, SlotAssigner } from '../../src/lib/palette';
import type { ConnectionEvent } from '../../src/lib/types';
import { filterRecent } from '../../src/recent/filter';

const ev = (i: number, port: string, time: number, extra: Partial<ConnectionEvent> = {}): ConnectionEvent => ({
  time: new Date(time).toISOString(),
  src_ip: `10.0.0.${i}`,
  dst_ip: '1.1.1.1',
  dst_port: port,
  src_lat: 1,
  src_lon: 2,
  dst_lat: 3,
  dst_lon: 4,
  src_cc: 'US',
  ...extra,
});

describe('live state reducers', () => {
  it('records events, assigns stable port slots and counts', () => {
    const s = createLiveState(1);
    const now = Date.UTC(2026, 0, 1, 12);
    recordEvent(s, ev(1, '22', now), now);
    recordEvent(s, ev(2, '80', now), now);
    recordEvent(s, ev(3, '22', now), now);
    expect(s.events).toHaveLength(3);
    expect(s.portStats.get('22')).toEqual({ count: 2, slot: 0 });
    expect(s.portStats.get('80')).toEqual({ count: 1, slot: 1 });
    expect(topPorts(s, 5).map(([p]) => p)).toEqual(['22', '80']);
  });

  it('evicts events outside the window and never reuses slots', () => {
    const s = createLiveState(1);
    const now = Date.UTC(2026, 0, 1, 12);
    // Recorded while still fresh; it ages out by the time the third event lands.
    expect(recordEvent(s, ev(1, '22', now - 70 * 60e3), now - 70 * 60e3)).toEqual([]);
    expect(recordEvent(s, ev(2, '80', now - 30 * 60e3), now - 30 * 60e3)).toEqual([]);
    const evicted = recordEvent(s, ev(3, '443', now), now);
    expect(evicted.map((e) => e.src_ip)).toEqual(['10.0.0.1']);
    expect(s.portStats.has('22')).toBe(false);
    expect(s.portStats.get('443')?.slot).toBe(2); // slot 0 retired, not recycled
    s.hours = 0; // everything older than "now" goes
    expect(evictExpired(s, now + 1)).toHaveLength(2);
    expect(s.events).toHaveLength(0);
  });

  it('unknown port maps to "unknown"', () => {
    const s = createLiveState(1);
    recordEvent(s, ev(1, '', Date.now()));
    expect(s.portStats.has('unknown')).toBe(true);
  });

  it('last-seen moves repeated IPs to the front and trims', () => {
    const s = createLiveState(1, 3);
    const now = Date.now();
    for (let i = 1; i <= 4; i++) updateLastSeen(s, ev(i, '22', now), now);
    expect(s.lastSeen.map((e) => e.ip)).toEqual(['10.0.0.4', '10.0.0.3', '10.0.0.2']);
    updateLastSeen(s, ev(2, '22', now), now);
    expect(s.lastSeen.map((e) => e.ip)).toEqual(['10.0.0.2', '10.0.0.4', '10.0.0.3']);
    expect(updateLastSeen(s, ev(9, '22', now, { src_ip: '' }), now)).toBe(false);
  });

  it('reset clears everything', () => {
    const s = createLiveState(1);
    recordEvent(s, ev(1, '22', Date.now()));
    updateLastSeen(s, ev(1, '22', Date.now()));
    resetLiveState(s);
    expect(s.events).toHaveLength(0);
    expect(s.portStats.size).toBe(0);
    expect(s.lastSeen).toHaveLength(0);
    expect(s.nextSlot).toBe(0);
  });

  it('banKey is ip|port', () => {
    expect(banKey('1.2.3.4', '22')).toBe('1.2.3.4|22');
  });
});

describe('SlotAssigner', () => {
  it('assigns fixed-order slots and folds past 8 into other', () => {
    const a = new SlotAssigner();
    const colors = [...FALLBACK_SERIES];
    for (let i = 0; i < SERIES_SLOTS; i++) expect(a.color(`p${i}`, colors, '#other')).toBe(colors[i]);
    expect(a.color('p8', colors, '#other')).toBe('#other');
    expect(a.color('p0', colors, '#other')).toBe(colors[0]); // stable
  });
});

describe('Signal', () => {
  it('emits on change only', () => {
    const s = new Signal<number>(1);
    const seen: number[] = [];
    const off = s.subscribe((v) => seen.push(v));
    s.set(1);
    s.set(2);
    off();
    s.set(3);
    expect(seen).toEqual([1, 2]);
  });
});

describe('filterRecent', () => {
  const events = [ev(1, '22', 1, { client_data: 'aa' }), ev(2, '80', 2), ev(3, '22', 3, { client_data: 'bb' }), ev(4, '443', 4, { client_data: 'cc' })];
  it('filters by data, service ports and limit (keeps most recent)', () => {
    expect(filterRecent(events, { onlyWithData: true, limit: 10 }).map((e) => e.src_ip)).toEqual(['10.0.0.1', '10.0.0.3', '10.0.0.4']);
    expect(filterRecent(events, { onlyWithData: false, limit: 10 })).toHaveLength(4);
    expect(filterRecent(events, { onlyWithData: true, ports: new Set(['22']), limit: 10 })).toHaveLength(2);
    expect(filterRecent(events, { onlyWithData: true, limit: 1 }).map((e) => e.src_ip)).toEqual(['10.0.0.4']);
  });
});
