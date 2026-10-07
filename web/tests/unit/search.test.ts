import { describe, expect, it } from 'vitest';
import { eventBadges, badgeSummary } from '../../src/lib/badges';
import { filterByQuery, hideObserved, parseDuration } from '../../src/lib/match';
import { encodeUrlState, readUrlState } from '../../src/lib/urlstate';
import { deleteView, parseViews, upsertView } from '../../src/lib/views';
import { barPercents, normalizeCampaigns, normalizeTop, presetForHours, trend } from '../../src/history/top';
import { densityBins, eventSpan, eventsInWindow, isFullWindow, SCRUB_STEPS, stepsToWindow } from '../../src/history/scrub';
import type { ConnectionEvent } from '../../src/lib/types';

const NOW = Date.parse('2026-01-02T00:00:00Z');
const ev = (o: Partial<ConnectionEvent> = {}): ConnectionEvent => ({
  time: '2026-01-01T23:00:00Z',
  src_ip: '203.0.113.5',
  dst_ip: '1.1.1.1',
  dst_port: '22',
  src_lat: 0,
  src_lon: 0,
  dst_lat: 0,
  dst_lon: 0,
  ...o,
});

describe('filterByQuery', () => {
  const events = [
    ev({ src_cc: 'CN', kind: 'session', class: 'bruteforce', tags: ['scanner:zgrab'], meta: { user: 'root' }, detail: 'Login failed' }),
    ev({ src_cc: 'US', dst_port: '80', kind: 'observed', scanner: 'Shodan', asn: 'AS14061 DigitalOcean', src_ip: '198.51.100.1' }),
    ev({ src_cc: 'DE', dst_port: '23', protocol: 'udp', time: '2025-12-20T00:00:00Z' }),
  ];
  const n = (q: string) => filterByQuery(events, q, NOW).length;
  it('matches keyed terms', () => {
    expect(n('port:22')).toBe(1);
    expect(n('cc:cn')).toBe(1);
    expect(n('kind:observed')).toBe(1);
    expect(n('scanner:shodan')).toBe(1);
    expect(n('scanner:zgrab')).toBe(1);
    expect(n('asn:14061')).toBe(1);
    expect(n('asn:AS14061')).toBe(1);
    expect(n('user:root')).toBe(1);
    expect(n('proto:udp')).toBe(1);
    expect(n('ip:198.51')).toBe(1);
  });
  it('ORs the same key, ANDs different keys', () => {
    expect(n('cc:CN cc:US')).toBe(2);
    expect(n('cc:CN cc:US port:80')).toBe(1);
  });
  it('negates', () => {
    expect(n('-cc:CN')).toBe(2);
    expect(n('-kind:observed -cc:CN')).toBe(1);
  });
  it('matches free text and phrases', () => {
    expect(n('"login failed"')).toBe(1);
    expect(n('digitalocean')).toBe(1);
    expect(n('login digitalocean')).toBe(0);
  });
  it('handles since/until', () => {
    expect(n('since:2h')).toBe(2);
    expect(n('until:7d')).toBe(1);
    expect(parseDuration('7d')).toBe(7 * 86_400_000);
    expect(parseDuration('x')).toBeNull();
  });
  it('empty query keeps everything', () => {
    expect(n('')).toBe(3);
  });
  it('hideObserved drops kind=observed only', () => {
    expect(hideObserved(events, true)).toHaveLength(2);
    expect(hideObserved(events, false)).toHaveLength(3);
  });
});

describe('urlstate', () => {
  it('round-trips and skips empties', () => {
    const h = encodeUrlState({ q: 'port:22 "a b"', preset: '24', from: '', to: undefined });
    expect(h).toBe('#preset=24&q=port%3A22+%22a+b%22');
    expect(readUrlState(h)).toEqual({ preset: '24', q: 'port:22 "a b"' });
    expect(encodeUrlState({})).toBe('');
  });
  it('hash wins over query string', () => {
    expect(readUrlState('#q=b', '?q=a&x=1')).toEqual({ q: 'b', x: '1' });
  });
});

describe('saved views', () => {
  it('parses defensively', () => {
    expect(parseViews(null)).toEqual([]);
    expect(parseViews('not json')).toEqual([]);
    expect(parseViews('{"a":1}')).toEqual([]);
    expect(parseViews('[{"name":"a","q":"b"},{"name":1},null,{"name":" ","q":"x"}]')).toEqual([{ name: 'a', q: 'b' }]);
  });
  it('upserts case-insensitively and deletes', () => {
    let v = upsertView([], { name: 'Mine', q: 'a' });
    v = upsertView(v, { name: 'mine', q: 'b' });
    expect(v).toEqual([{ name: 'mine', q: 'b' }]);
    expect(upsertView(v, { name: '  ', q: 'z' })).toEqual(v);
    expect(deleteView(v, 'mine')).toEqual([]);
  });
});

describe('badges', () => {
  it('lists scanner, class and kind with text labels', () => {
    const b = eventBadges({ scanner: 'Shodan', class: 'exploit', kind: 'observed' });
    expect(b.map((x) => x.group)).toEqual(['scanner', 'class', 'kind']);
    expect(b.every((x) => x.glyph && x.text)).toBe(true);
    expect(badgeSummary({ kind: 'session' })).toBe('kind: session');
    expect(eventBadges({})).toEqual([]);
    expect(eventBadges({ class: 'novel' })[0]!.text).toBe('novel');
  });
});

describe('top helpers', () => {
  it('computes trends', () => {
    expect(trend({ prev: 900, delta_pct: 37.1 })).toMatchObject({ dir: 'up', text: '↑ 37%' });
    expect(trend({ prev: 10, delta_pct: -20 })).toMatchObject({ dir: 'down', text: '↓ 20%' });
    expect(trend({ prev: 0, delta_pct: null }).text).toBe('new');
    expect(trend({ prev: 5, delta_pct: 0.2 }).dir).toBe('flat');
    expect(trend({}).dir).toBe('none');
  });
  it('scales bars', () => {
    expect(barPercents([{ count: 100 }, { count: 50 }, { count: 0 }])).toEqual([100, 50, 2]);
    expect(barPercents([{ count: 0 }])).toEqual([0]);
  });
  it('normalises tolerant payloads', () => {
    expect(normalizeTop({ items: [{ key: 'a', count: '3' }, { count: 1 }, null] })).toEqual([{ key: 'a', count: 3 }]);
    expect(normalizeTop(null)).toEqual([]);
    expect(normalizeCampaigns([{ id: 'c1' }, { label: 'x' }, 5])).toMatchObject([{ id: 'c1', label: 'c1', ips: [], ports: [] }]);
    expect(presetForHours(24)).toBe('24');
    expect(presetForHours(5)).toBe('');
  });
});

describe('scrub helpers', () => {
  const evs = [0, 10, 20, 30, 40].map((m) => ev({ time: new Date(NOW + m * 60_000).toISOString() }));
  it('computes span, windows and bins', () => {
    const span = eventSpan(evs)!;
    expect(span.max - span.min).toBe(40 * 60_000);
    expect(eventSpan([ev({ time: 'bad' })])).toBeNull();
    const win = stepsToWindow(span, SCRUB_STEPS / 2, 0);
    expect(eventsInWindow(evs, win)).toHaveLength(3);
    expect(densityBins(evs, span, 4)).toEqual([1, 1, 1, 2]);
    expect(isFullWindow(0, SCRUB_STEPS)).toBe(true);
    expect(isFullWindow(1, SCRUB_STEPS)).toBe(false);
  });
});
