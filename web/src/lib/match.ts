// Client-side evaluation of the search grammar against already-loaded events
// (Recent page, live noise filter). The server evaluates the same grammar for
// /api/history; this is a best-effort mirror for in-memory lists.
//
// Semantics: positive terms of the SAME key are alternatives (OR); different
// keys are combined with AND; negated terms each exclude (AND NOT); free words
// must all match (AND).

import type { ConnectionEvent } from './types';
import { parseQuery, type Term } from './query';

export const DURATION_RE = /^(\d+)\s*([smhdw])$/i;
const UNIT_MS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 };

/** "24h" -> ms; null when not a duration. */
export function parseDuration(s: string): number | null {
  const m = DURATION_RE.exec(s.trim());
  if (!m) return null;
  return Number(m[1]) * UNIT_MS[m[2]!.toLowerCase()]!;
}

function metaString(ev: ConnectionEvent, key: string): string {
  const v = ev.meta?.[key] ?? ev[key];
  return v === undefined || v === null ? '' : String(v);
}

function tagValues(ev: ConnectionEvent, prefix: string): string[] {
  const p = `${prefix}:`;
  return (ev.tags ?? []).filter((t) => t.toLowerCase().startsWith(p)).map((t) => t.slice(p.length));
}

function asnNumber(ev: ConnectionEvent): string {
  const m = /^(?:AS)?(\d+)/i.exec(String(ev.asn ?? '').trim());
  return m ? m[1]! : '';
}

function haystack(ev: ConnectionEvent): string {
  let meta = '';
  if (ev.meta) {
    try {
      meta = JSON.stringify(ev.meta);
    } catch {
      meta = '';
    }
  }
  return [ev.detail, ev.asn, ev.src_city, ev.src_ip, meta]
    .filter((x) => x !== undefined && x !== null)
    .join('\n')
    .toLowerCase();
}

function eq(a: string | undefined, b: string): boolean {
  return (a ?? '').toLowerCase() === b.toLowerCase();
}

/** Does a single (non-negated) condition hold? */
function holds(ev: ConnectionEvent, t: Term, now: number): boolean {
  const v = t.value;
  switch (t.key) {
    case 'port':
      return ev.dst_port === v;
    case 'ip':
      return (ev.src_ip ?? '').startsWith(v);
    case 'cc':
      return eq(ev.src_cc, v);
    case 'asn':
      return asnNumber(ev) === v.replace(/^AS/i, '');
    case 'tag':
      return (ev.tags ?? []).some((x) => eq(x, v));
    case 'kind':
      return eq(ev.kind, v);
    case 'class':
      return eq(ev.class, v);
    case 'scanner':
      return eq(ev.scanner, v) || tagValues(ev, 'scanner').some((x) => eq(x, v));
    case 'proto':
      return eq(ev.protocol ?? 'tcp', v);
    case 'ja3':
    case 'ja4':
    case 'sni':
    case 'user':
      return eq(metaString(ev, t.key), v) || tagValues(ev, t.key).some((x) => eq(x, v));
    case 'since': {
      const ms = parseDuration(v);
      const at = Date.parse(ev.time);
      return ms === null || Number.isNaN(at) ? true : at >= now - ms;
    }
    case 'until': {
      const ms = parseDuration(v);
      const at = Date.parse(ev.time);
      return ms === null || Number.isNaN(at) ? true : at <= now - ms;
    }
    default:
      return haystack(ev).includes(v.toLowerCase());
  }
}

export function matchTerms(ev: ConnectionEvent, terms: readonly Term[], now: number = Date.now()): boolean {
  const groups = new Map<string, Term[]>();
  let words = 0;
  for (const t of terms) {
    if (t.neg) {
      if (holds(ev, t, now)) return false;
      continue;
    }
    // Free words are individually required; keyed terms group by key.
    const group = t.key ?? `word:${words++}`;
    const list = groups.get(group);
    if (list) list.push(t);
    else groups.set(group, [t]);
  }
  for (const list of groups.values()) {
    if (!list.some((t) => holds(ev, t, now))) return false;
  }
  return true;
}

export function filterByQuery(events: readonly ConnectionEvent[], q: string, now: number = Date.now()): ConnectionEvent[] {
  const { terms } = parseQuery(q);
  if (terms.length === 0) return events.slice();
  return events.filter((e) => matchTerms(e, terms, now));
}

/** XDP-only observations (no listener saw a payload). */
export function isObservedOnly(ev: ConnectionEvent): boolean {
  return ev.kind === 'observed';
}

export function hideObserved(events: readonly ConnectionEvent[], on: boolean): ConnectionEvent[] {
  return on ? events.filter((e) => !isObservedOnly(e)) : events.slice();
}
