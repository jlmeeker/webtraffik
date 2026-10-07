// Pure aggregation helpers for the History page (unit-tested).
import type { ConnectionEvent, MetricSeries, MetricsResponse, TimeBucket } from '../lib/types';

export function topN(map: Record<string, number> | Map<string, number>, n: number): Array<[string, number]> {
  const entries = map instanceof Map ? [...map.entries()] : Object.entries(map);
  return entries.sort((a, b) => b[1] - a[1]).slice(0, n);
}

/** Sum metric series values grouped by one label (missing label → fallback). */
export function sumByLabel(series: MetricSeries[] | undefined, label: string, fallback = 'unknown'): Map<string, number> {
  const out = new Map<string, number>();
  for (const s of series ?? []) {
    const k = s.labels?.[label] || fallback;
    out.set(k, (out.get(k) ?? 0) + (Number(s.value) || 0));
  }
  return out;
}

export function sumValues(series: MetricSeries[] | undefined): number {
  return (series ?? []).reduce((acc, s) => acc + (Number(s.value) || 0), 0);
}

export function countBy<T>(items: readonly T[], key: (t: T) => string): Map<string, number> {
  const out = new Map<string, number>();
  for (const it of items) {
    const k = key(it);
    out.set(k, (out.get(k) ?? 0) + 1);
  }
  return out;
}

export function bucketsToPoints(buckets: TimeBucket[] | undefined, field: 'value' | 'unique_ips' | 'bans' = 'value'): Array<{ t: Date; v: number }> {
  return (buckets ?? [])
    .map((b) => ({ t: new Date(b.bucket), v: Number(b[field] ?? 0) || 0 }))
    .filter((p) => !Number.isNaN(p.t.getTime()))
    .sort((a, b) => a.t.getTime() - b.t.getTime());
}

/** Pick the top-N keys of a timeline map by total volume (stable fixed order). */
export function topTimelineKeys(tl: Record<string, TimeBucket[]> | undefined, n: number): string[] {
  const totals = new Map<string, number>();
  for (const [k, buckets] of Object.entries(tl ?? {})) totals.set(k, buckets.reduce((s, b) => s + (Number(b.value) || 0), 0));
  return topN(totals, n).map(([k]) => k);
}

export interface Summary {
  connections: number;
  bans: number;
  autoBans: number;
  manualBans: number;
  uniqueIPs: number;
  rawEvents: number;
}

export function summarize(metrics: MetricsResponse, events: ConnectionEvent[]): Summary {
  const bans = metrics.bans ?? [];
  return {
    connections: sumValues(metrics.connections),
    bans: sumValues(bans),
    autoBans: sumValues(bans.filter((b) => b.labels?.type === 'auto')),
    manualBans: sumValues(bans.filter((b) => b.labels?.type === 'manual')),
    uniqueIPs: Number(metrics.unique_ips ?? 0) || 0,
    rawEvents: events.length,
  };
}
