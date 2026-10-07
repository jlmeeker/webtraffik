// Pure helpers for the history time scrubber (unit-tested).

import type { ConnectionEvent } from '../lib/types';

export const SCRUB_STEPS = 1000;

export interface TimeSpan {
  min: number;
  max: number;
}

function timeOf(ev: ConnectionEvent): number {
  return Date.parse(ev.time);
}

/** First/last event time in ms, or null when nothing has a valid time. */
export function eventSpan(events: readonly ConnectionEvent[]): TimeSpan | null {
  let min = Infinity;
  let max = -Infinity;
  for (const e of events) {
    const t = timeOf(e);
    if (Number.isNaN(t)) continue;
    if (t < min) min = t;
    if (t > max) max = t;
  }
  return min === Infinity ? null : { min, max };
}

/** Map slider positions (0..SCRUB_STEPS) onto the span; handles are order-independent. */
export function stepsToWindow(span: TimeSpan, a: number, b: number): TimeSpan {
  const lo = Math.min(a, b);
  const hi = Math.max(a, b);
  const w = span.max - span.min;
  return { min: span.min + (w * lo) / SCRUB_STEPS, max: span.min + (w * hi) / SCRUB_STEPS };
}

/** Events whose time lies inside [win.min, win.max]. A full-span window keeps everything dated. */
export function eventsInWindow(events: readonly ConnectionEvent[], win: TimeSpan): ConnectionEvent[] {
  return events.filter((e) => {
    const t = timeOf(e);
    return !Number.isNaN(t) && t >= win.min && t <= win.max;
  });
}

/** Event counts per equal-width bin across the span (for the density strip). */
export function densityBins(events: readonly ConnectionEvent[], span: TimeSpan, bins: number): number[] {
  const out = new Array<number>(bins).fill(0);
  const w = span.max - span.min;
  for (const e of events) {
    const t = timeOf(e);
    if (Number.isNaN(t)) continue;
    const i = w <= 0 ? 0 : Math.min(bins - 1, Math.floor(((t - span.min) / w) * bins));
    out[i]!++;
  }
  return out;
}

export function isFullWindow(a: number, b: number): boolean {
  return Math.min(a, b) <= 0 && Math.max(a, b) >= SCRUB_STEPS;
}
