import { describe, expect, it } from 'vitest';
import { bucketsToPoints, countBy, summarize, sumByLabel, sumValues, topN, topTimelineKeys } from '../../src/history/aggregate';
import { buildPortMap, ServiceRegistry } from '../../src/lib/services';
import { arcWidth, dotRadius, fitTransform, pointAlong, quadArc } from '../../src/map/geometry';
import { fitBBox } from '../../src/map/magnifier';
import { modeLabel } from '../../src/panels/ebpf';

describe('history aggregation', () => {
  const conns = [
    { labels: { port: '22', cc: 'US', service: 'SSH' }, value: 5 },
    { labels: { port: '22', cc: 'JP', service: 'SSH' }, value: 2 },
    { labels: { port: '80', cc: 'US', service: 'HTTP' }, value: 4 },
    { labels: {}, value: 1 },
  ];
  it('sumByLabel / sumValues / topN', () => {
    const byPort = sumByLabel(conns, 'port');
    expect(byPort.get('22')).toBe(7);
    expect(byPort.get('unknown')).toBe(1);
    expect(sumValues(conns)).toBe(12);
    expect(topN(byPort, 2)).toEqual([
      ['22', 7],
      ['80', 4],
    ]);
  });
  it('countBy and bucketsToPoints sort by time', () => {
    expect(countBy(['a', 'b', 'a'], (x) => x).get('a')).toBe(2);
    const pts = bucketsToPoints([
      { bucket: '2026-01-01T02:00:00Z', value: 2, unique_ips: 9 },
      { bucket: '2026-01-01T01:00:00Z', value: 1 },
      { bucket: 'bad', value: 7 },
    ]);
    expect(pts.map((p) => p.v)).toEqual([1, 2]);
    expect(bucketsToPoints([{ bucket: '2026-01-01T02:00:00Z', value: 2, unique_ips: 9 }], 'unique_ips')[0]!.v).toBe(9);
  });
  it('topTimelineKeys and summarize', () => {
    const tl = { '22': [{ bucket: 'x', value: 10 }], '80': [{ bucket: 'x', value: 30 }], '443': [{ bucket: 'x', value: 20 }] };
    expect(topTimelineKeys(tl, 2)).toEqual(['80', '443']);
    const s = summarize(
      { connections: conns, bans: [{ labels: { type: 'auto' }, value: 2 }, { labels: { type: 'manual' }, value: 1 }], unique_ips: 42 },
      [],
    );
    expect(s).toEqual({ connections: 12, bans: 3, autoBans: 2, manualBans: 1, uniqueIPs: 42, rawEvents: 0 });
  });
});

describe('ServiceRegistry', () => {
  it('buildPortMap keeps the first name per port', () => {
    const m = buildPortMap([
      { name: 'HTTP', ports: [80, 8080] },
      { name: 'Proxy', ports: [8080] },
    ]);
    expect(m.get('8080')).toBe('HTTP');
  });
  it('uses fallback names until loaded, then server names win', async () => {
    const reg = new ServiceRegistry(() => Promise.resolve([{ name: 'Secure Shell', ports: [22, 2222] }]));
    expect(reg.name('22')).toBe('SSH');
    await reg.ready;
    expect(reg.isLoaded).toBe(true);
    expect(reg.name('22')).toBe('Secure Shell');
    expect(reg.name('2222')).toBe('Secure Shell');
    expect(reg.name('80')).toBe('HTTP'); // fallback still applies
    expect(reg.label('12345')).toBe('port 12345');
    expect(reg.label('unknown')).toBe('unknown');
    expect([...reg.portsFor('Secure Shell')!]).toEqual(['22', '2222']);
  });
  it('survives a failing loader', async () => {
    const reg = new ServiceRegistry(() => Promise.reject(new Error('down')));
    await reg.ready;
    expect(reg.isLoaded).toBe(false);
    expect(reg.name('22')).toBe('SSH');
  });
});

describe('geometry', () => {
  it('quadArc samples a bowed curve with increasing length for longer chords', () => {
    const a = quadArc(0, 100, 100, 100, 0.35, 1000);
    const b = quadArc(0, 100, 400, 100, 0.35, 1000);
    expect(a.points).toHaveLength(21);
    expect(a.points[0]).toEqual([0, 100]);
    expect(a.points[20]).toEqual([100, 100]);
    expect(a.ctrl[1]).toBeLessThan(100); // bulges upward
    expect(b.length).toBeGreaterThan(a.length);
    expect(quadArc(0, 0, 1000, 0, 0.35, 50).ctrl[1]).toBe(-50); // capped bulge
  });
  it('pointAlong interpolates', () => {
    const pts: Array<[number, number]> = [
      [0, 0],
      [10, 0],
      [20, 0],
    ];
    expect(pointAlong(pts, 0.25)).toEqual([5, 0]);
    expect(pointAlong(pts, 1)).toEqual([20, 0]);
    expect(pointAlong([], 0.5)[0]).toBeNaN();
  });
  it('arcWidth and dotRadius saturate', () => {
    expect(arcWidth(1)).toBe(1.5);
    expect(arcWidth(100)).toBe(6);
    expect(dotRadius(1)).toBe(3);
    expect(dotRadius(1024)).toBe(6);
  });
  it('fitTransform centres and scales a bbox, clamped to maxK', () => {
    const fit = fitTransform(
      [
        [100, 100],
        [200, 150],
      ],
      1000,
      500,
      0.1,
      10,
    );
    expect(fit).not.toBeNull();
    expect(fit!.k).toBeLessThanOrEqual(10);
    expect(fit!.tx).toBeCloseTo(500 - fit!.k * 150, 6);
    expect(fitTransform([[1, 1]], 10, 10)).toBeNull();
  });
});

describe('magnifier bbox', () => {
  it('enforces a minimum span and clamps to valid ranges', () => {
    const b = fitBBox([0, 0], [1, 1], 1.4);
    expect(b.lonMax - b.lonMin).toBeGreaterThanOrEqual(15);
    const edge = fitBBox([179, 84], [179.5, 84.5], 1.4);
    expect(edge.lonMax).toBeLessThanOrEqual(180);
    expect(edge.latMax).toBeLessThanOrEqual(85);
  });
});

describe('modeLabel', () => {
  it('maps known modes and passes unknown through', () => {
    expect(modeLabel('hybrid')).toBe('Hybrid');
    expect(modeLabel('go-only')).toBe('Go only');
    expect(modeLabel('weird')).toBe('weird');
    expect(modeLabel(undefined)).toBe('—');
  });
});
