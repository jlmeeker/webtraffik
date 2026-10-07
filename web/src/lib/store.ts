import type { ConnectionEvent, SelfInfo } from './types';

// ── Pure reducers (unit-tested) ─────────────────────────────────────────────

export interface PortStat {
  count: number;
  slot: number; // categorical slot index (0-based); >= 8 means "other"
}

export interface LastSeenEntry {
  ip: string;
  cc: string;
  lat: number;
  lon: number;
  city: string;
  at: number; // ms epoch of most recent hit
}

export interface LiveState {
  /** Oldest-first ring of events inside the current time window. */
  events: ConnectionEvent[];
  /** Window in hours (1..24). */
  hours: number;
  portStats: Map<string, PortStat>;
  nextSlot: number;
  lastSeen: LastSeenEntry[];
  lastSeenMax: number;
}

export function createLiveState(hours = 1, lastSeenMax = 25): LiveState {
  return { events: [], hours, portStats: new Map(), nextSlot: 0, lastSeen: [], lastSeenMax };
}

export function portKey(ev: ConnectionEvent): string {
  return ev.dst_port || 'unknown';
}

/** Assign a stable slot to a port the first time it is seen. */
export function ensurePort(state: LiveState, port: string): PortStat {
  let ps = state.portStats.get(port);
  if (!ps) {
    ps = { count: 0, slot: state.nextSlot++ };
    state.portStats.set(port, ps);
  }
  return ps;
}

/**
 * Record an event: append to the ring, bump port counts, and evict events
 * that fell outside the time window. Returns the list of evicted events.
 */
export function recordEvent(state: LiveState, ev: ConnectionEvent, now: number = Date.now()): ConnectionEvent[] {
  state.events.push(ev);
  ensurePort(state, portKey(ev)).count++;
  return evictExpired(state, now);
}

export function evictExpired(state: LiveState, now: number = Date.now()): ConnectionEvent[] {
  const cutoff = now - state.hours * 3_600_000;
  const evicted: ConnectionEvent[] = [];
  while (state.events.length > 0) {
    const head = state.events[0]!;
    const t = new Date(head.time).getTime();
    if (Number.isNaN(t) || t >= cutoff) break;
    state.events.shift();
    evicted.push(head);
    const k = portKey(head);
    const ps = state.portStats.get(k);
    if (ps) {
      ps.count--;
      if (ps.count <= 0) state.portStats.delete(k); // slot is intentionally NOT reused
    }
  }
  return evicted;
}

/** Top-N ports by count, descending. */
export function topPorts(state: LiveState, n: number): Array<[string, PortStat]> {
  return [...state.portStats.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, n);
}

/** Move/insert ip at the front of the last-seen list; trims to lastSeenMax. */
export function updateLastSeen(state: LiveState, ev: ConnectionEvent, now: number = Date.now()): boolean {
  if (!ev.src_ip) return false;
  const idx = state.lastSeen.findIndex((e) => e.ip === ev.src_ip);
  if (idx !== -1) state.lastSeen.splice(idx, 1);
  state.lastSeen.unshift({
    ip: ev.src_ip,
    cc: ev.src_cc ?? '',
    lat: ev.src_lat,
    lon: ev.src_lon,
    city: ev.src_city ?? '',
    at: now,
  });
  if (state.lastSeen.length > state.lastSeenMax) state.lastSeen.length = state.lastSeenMax;
  return true;
}

export function resetLiveState(state: LiveState): void {
  state.events.length = 0;
  state.portStats.clear();
  state.nextSlot = 0;
  state.lastSeen.length = 0;
}

// ── Ban set helpers ─────────────────────────────────────────────────────────

export function banKey(ip: string, port: string): string {
  return `${ip}|${port}`;
}

// ── Tiny observable for UI-level shared values ──────────────────────────────

export type Listener<T> = (value: T) => void;

export class Signal<T> {
  private listeners = new Set<Listener<T>>();
  constructor(private _value: T) {}
  get value(): T {
    return this._value;
  }
  set(v: T): void {
    if (Object.is(v, this._value)) return;
    this._value = v;
    for (const l of this.listeners) l(v);
  }
  subscribe(fn: Listener<T>, emitNow = true): () => void {
    this.listeners.add(fn);
    if (emitNow) fn(this._value);
    return () => this.listeners.delete(fn);
  }
}

export type SelfSignal = Signal<SelfInfo | null>;
