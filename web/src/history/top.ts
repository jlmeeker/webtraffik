// Pure helpers for the Top-N and Campaigns panels (unit-tested).

import type { Campaign, TopItem } from '../lib/types';

export const TOP_DIMS: ReadonlyArray<{ id: string; label: string }> = [
  { id: 'credentials', label: 'Credentials' },
  { id: 'usernames', label: 'Usernames' },
  { id: 'passwords', label: 'Passwords' },
  { id: 'useragents', label: 'User agents' },
  { id: 'paths', label: 'Paths' },
  { id: 'asns', label: 'ASNs' },
  { id: 'ja4', label: 'JA4 fingerprints' },
  { id: 'ports', label: 'Ports' },
  { id: 'countries', label: 'Countries' },
  { id: 'tags', label: 'Tags' },
  { id: 'scanners', label: 'Scanners' },
];

export const TOP_HOURS: ReadonlyArray<{ hours: number; label: string }> = [
  { hours: 1, label: '1h' },
  { hours: 24, label: '24h' },
  { hours: 168, label: '7d' },
];

export type TrendDir = 'up' | 'down' | 'flat' | 'new' | 'none';

export interface Trend {
  dir: TrendDir;
  /** Visible text, e.g. "↑ 37%" or "new". */
  text: string;
  /** Screen-reader wording. */
  aria: string;
}

/** Trend vs the preceding equal period. Direction is never colour-only. */
export function trend(item: Pick<TopItem, 'prev' | 'delta_pct'>): Trend {
  const d = item.delta_pct;
  if (typeof d === 'number' && Number.isFinite(d)) {
    const pct = Math.round(Math.abs(d));
    if (pct === 0) return { dir: 'flat', text: '→ 0%', aria: 'unchanged' };
    return d > 0 ? { dir: 'up', text: `↑ ${pct}%`, aria: `up ${pct} percent` } : { dir: 'down', text: `↓ ${pct}%`, aria: `down ${pct} percent` };
  }
  if (item.prev === 0) return { dir: 'new', text: 'new', aria: 'new in this period' };
  return { dir: 'none', text: '', aria: '' };
}

/** Bar widths as percentages of the largest count (min 2% so every row shows). */
export function barPercents(items: readonly Pick<TopItem, 'count'>[]): number[] {
  const max = items.reduce((m, i) => Math.max(m, Number(i.count) || 0), 0);
  if (max <= 0) return items.map(() => 0);
  return items.map((i) => Math.max(2, Math.round(((Number(i.count) || 0) / max) * 100)));
}

/** Tolerant normalisation of a /api/top response. */
export function normalizeTop(data: unknown): TopItem[] {
  const items = (data as { items?: unknown } | null)?.items;
  if (!Array.isArray(items)) return [];
  const out: TopItem[] = [];
  for (const i of items) {
    if (!i || typeof i !== 'object') continue;
    const o = i as Partial<TopItem>;
    if (typeof o.key !== 'string' && typeof o.key !== 'number') continue;
    out.push({ ...o, key: String(o.key), count: Number(o.count) || 0 } as TopItem);
  }
  return out;
}

export function normalizeCampaigns(data: unknown): Campaign[] {
  if (!Array.isArray(data)) return [];
  const out: Campaign[] = [];
  for (const c of data) {
    if (!c || typeof c !== 'object') continue;
    const o = c as Partial<Campaign>;
    if (typeof o.id !== 'string') continue;
    out.push({
      ...o,
      id: o.id,
      label: typeof o.label === 'string' && o.label ? o.label : o.id,
      ips: Array.isArray(o.ips) ? o.ips.filter((x): x is string => typeof x === 'string') : [],
      ports: Array.isArray(o.ports) ? o.ports.filter((x): x is number => typeof x === 'number') : [],
      countries: Array.isArray(o.countries) ? o.countries.filter((x): x is string => typeof x === 'string') : [],
      tags: Array.isArray(o.tags) ? o.tags.filter((x): x is string => typeof x === 'string') : [],
    });
  }
  return out;
}

/** IP count for display: the server total when present, else the listed sample. */
export function campaignIpCount(c: Campaign): number {
  return typeof c.ip_count === 'number' ? c.ip_count : (c.ips?.length ?? 0);
}

/** History preset (hours) matching a Top window, if the History range select has one. */
export function presetForHours(hours: number): string {
  return [1, 6, 24, 168, 720].includes(hours) ? String(hours) : '';
}
