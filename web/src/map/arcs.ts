import * as d3 from 'd3';
import type { ConnectionEvent, LonLat } from '../lib/types';
import { hasGeo } from '../lib/utils/geo';
import { allFinite, arcWidth, dotRadius, pointAlong, quadArc } from './geometry';
import type { MapView } from './view';
import type { DotTooltip } from './tooltip';

export const MAX_ARCS = 150;
export const MAX_DOTS = 1000;
export const MAX_PULSES = 80;
export const ARC_TTL_MS = 12_000;
export const ARC_REST_OPACITY = 0.3;
export const PULSE_DURATION_MS = 1200;
export const FLOOD_THRESHOLD = 10; // events/sec above which arcs are batched
export const ARC_BULGE = 0.35;

type CircleSel = d3.Selection<SVGCircleElement, unknown, null, undefined>;
type PathSel = d3.Selection<SVGPathElement, unknown, null, undefined>;

interface GradientEntry {
  el: d3.Selection<SVGLinearGradientElement, unknown, null, undefined>;
  id: string;
  refCount: number;
}

interface ArcEntry {
  key: string;
  arcPath: PathSel;
  grad: GradientEntry;
  c1: string;
  c2: string;
  srcPt: LonLat;
  dstPt: LonLat;
  points: Array<[number, number]>;
  hitCount: number;
  expireTimer: ReturnType<typeof setTimeout> | null;
  dot: DotRecord;
  ev: ConnectionEvent;
}

interface DotRecord {
  el: CircleSel;
  ev: ConnectionEvent;
  hitCount: number;
}

export interface ArcLayerDeps {
  view: MapView;
  tooltip: DotTooltip;
  colorForPort: (port: string) => string;
  arcEndColor: () => string;
  bannedColor: () => string;
  isBanned: (ip: string, port: string) => boolean;
  /** Return true to suppress live arc drawing (e.g. during a traceroute). */
  suppressArcs: () => boolean;
  reducedMotion: () => boolean;
  /** Hook for the magnifier inset. */
  onArc?: (ev: ConnectionEvent, srcPt: LonLat, dstPt: LonLat, c1: string, hitCount: number) => void;
  /** Hook for the audio engine. */
  onTone?: (srcPt: LonLat, dstPt: LonLat) => void;
}

/**
 * Persistent arcs + source dots with pulse reuse, flood batching, TTL expiry,
 * gradient pooling and hard caps. History dots (replay) are drawn without arcs
 * and de-duplicated per source IP.
 */
export class ArcLayer {
  private readonly registry = new Map<string, ArcEntry>();
  private readonly arcRing: string[] = [];
  private readonly dotRing: SVGCircleElement[] = [];
  private readonly historyDots = new Map<string, DotRecord>();
  private readonly gradients = new Map<string, GradientEntry>();
  private readonly pulseTimers = new Set<d3.Timer>();
  private activePulses = 0;
  private readonly arcTimestamps: number[] = [];
  private readonly floodBuffer = new Map<string, { ev: ConnectionEvent; count: number }>();
  private floodTimer: ReturnType<typeof setTimeout> | null = null;
  private selfDot: CircleSel | null = null;
  private selfPos: LonLat | null = null;

  constructor(private readonly deps: ArcLayerDeps) {
    deps.view.onReproject(() => this.reproject());
  }

  // ── Self dot ──────────────────────────────────────────────────────────────
  setSelf(pos: LonLat | null): void {
    this.selfPos = pos;
    this.drawSelf();
  }

  private drawSelf(): void {
    if (this.selfDot) {
      this.selfDot.remove();
      this.selfDot = null;
    }
    if (!this.selfPos) return;
    const p = this.deps.view.project(this.selfPos);
    if (!p) return;
    this.selfDot = this.deps.view.layers.dots
      .append('circle')
      .attr('class', 'self-dot')
      .attr('cx', p[0])
      .attr('cy', p[1])
      .attr('r', 5)
      .attr('filter', 'url(#glow-accent)')
      .attr('aria-label', 'This server');
  }

  // ── Gradient pool ─────────────────────────────────────────────────────────
  private acquireGradient(c1: string, c2: string, x0: number, y0: number, x1: number, y1: number): GradientEntry {
    const key = `${c1}|${c2}`;
    let g = this.gradients.get(key);
    if (!g) {
      const id = `arc-grad-${this.gradients.size}`;
      const el = this.deps.view.defs.append('linearGradient').attr('id', id).attr('gradientUnits', 'userSpaceOnUse');
      el.append('stop').attr('offset', '0%').attr('stop-color', c1).attr('stop-opacity', 0.95);
      el.append('stop').attr('offset', '100%').attr('stop-color', c2).attr('stop-opacity', 0.75);
      g = { el, id, refCount: 0 };
      this.gradients.set(key, g);
    }
    g.refCount++;
    g.el.attr('x1', x0).attr('y1', y0).attr('x2', x1).attr('y2', y1);
    return g;
  }

  private releaseGradient(g: GradientEntry): void {
    g.refCount = Math.max(0, g.refCount - 1); // kept in DOM for reuse
  }

  // ── Live events ───────────────────────────────────────────────────────────
  /** Entry point for a live (non-replay) event. */
  handleLive(ev: ConnectionEvent): void {
    if (this.deps.suppressArcs()) return;
    if (!hasGeo(ev.src_lat, ev.src_lon)) return;
    const now = performance.now();
    this.arcTimestamps.push(now);
    while (this.arcTimestamps.length && now - this.arcTimestamps[0]! > 1000) this.arcTimestamps.shift();

    if (this.arcTimestamps.length < FLOOD_THRESHOLD) {
      this.dispatch(ev, 1);
      return;
    }
    const key = this.keyFor(ev);
    const b = this.floodBuffer.get(key);
    if (b) b.count++;
    else this.floodBuffer.set(key, { ev, count: 1 });
    if (!this.floodTimer) this.floodTimer = setTimeout(() => this.flushFlood(), 1000);
  }

  private flushFlood(): void {
    this.floodTimer = null;
    const entries = [...this.floodBuffer.values()];
    this.floodBuffer.clear();
    for (const { ev, count } of entries) this.dispatch(ev, count);
  }

  private keyFor(ev: ConnectionEvent): string {
    return ev.src_ip || `${ev.src_lon},${ev.src_lat}`;
  }

  private dispatch(ev: ConnectionEvent, hitCount: number): void {
    const key = this.keyFor(ev);
    const existing = this.registry.get(key);
    if (existing) {
      existing.hitCount += hitCount;
      existing.ev = ev;
      existing.dot.ev = ev;
      existing.dot.hitCount = existing.hitCount;
      this.resetTTL(existing);
      existing.arcPath.attr('stroke-width', arcWidth(Math.min(existing.hitCount, 20)));
      this.sendPulse(existing, hitCount);
      this.pulseDot(existing.dot);
      this.deps.onArc?.(ev, existing.srcPt, existing.dstPt, existing.c1, existing.hitCount);
    } else {
      this.drawArc(ev, hitCount);
    }
    this.deps.onTone?.([ev.src_lon, ev.src_lat], [ev.dst_lon, ev.dst_lat]);
  }

  private drawArc(ev: ConnectionEvent, hitCount: number): void {
    const view = this.deps.view;
    const srcPt: LonLat = [ev.src_lon, ev.src_lat];
    const dstPt: LonLat = this.selfPos ?? [ev.dst_lon, ev.dst_lat];
    const p0 = view.project(srcPt);
    const p1 = view.project(dstPt);
    if (!p0 || !p1) return;

    // A history dot for the same IP becomes the live dot (avoid duplicates).
    const prevHistory = this.historyDots.get(ev.src_ip);
    if (prevHistory) {
      this.historyDots.delete(ev.src_ip);
      this.removeDotNode(prevHistory.el.node());
    }

    const c1 = this.deps.colorForPort(ev.dst_port || 'unknown');
    const c2 = this.deps.arcEndColor();
    const grad = this.acquireGradient(c1, c2, p0[0], p0[1], p1[0], p1[1]);
    const geom = quadArc(p0[0], p0[1], p1[0], p1[1], ARC_BULGE, view.h * 0.25);

    const arcPath = view.layers.arcs
      .append('path')
      .attr('class', 'arc-path resting')
      .attr('d', geom.d)
      .attr('stroke', `url(#${grad.id})`)
      .attr('stroke-width', arcWidth(hitCount))
      .attr('opacity', ARC_REST_OPACITY);

    const banned = this.deps.isBanned(ev.src_ip, ev.dst_port);
    const r = dotRadius(hitCount);
    const dotEl = view.layers.dots
      .append('circle')
      .attr('class', 'src-dot')
      .attr('cx', p0[0])
      .attr('cy', p0[1])
      .attr('r', 0)
      .attr('fill', banned ? this.deps.bannedColor() : c1)
      .attr('opacity', 1)
      .datum(srcPt)
      .attr('aria-label', `${ev.src_ip} ${ev.src_city ?? ''} ${ev.src_cc ?? ''}`.trim()) as unknown as CircleSel;
    if (banned) dotEl.classed('banned', true);

    const dot: DotRecord = { el: dotEl, ev, hitCount };
    this.deps.tooltip.attach(dotEl, () => ({ ev: dot.ev, hitCount: dot.hitCount }));
    this.tagDot(dotEl.node(), dot);

    if (this.deps.reducedMotion()) {
      dotEl.attr('r', r).attr('opacity', banned ? 0.9 : 0.5);
    } else if (banned) {
      dotEl.attr('opacity', 0.9).transition().duration(300).attr('r', r + 1).transition().duration(300).attr('r', r);
    } else {
      dotEl
        .transition()
        .duration(300)
        .attr('r', r + 1)
        .transition()
        .delay(2500)
        .duration(600)
        .attr('r', r)
        .attr('opacity', 0.35);
    }
    this.trackDot(dotEl.node());

    const key = this.keyFor(ev);
    const entry: ArcEntry = {
      key,
      arcPath,
      grad,
      c1,
      c2,
      srcPt,
      dstPt,
      points: geom.points,
      hitCount,
      expireTimer: null,
      dot,
      ev,
    };
    this.registry.set(key, entry);
    this.resetTTL(entry);
    this.trackArc(key);
    this.sendPulse(entry, hitCount);
    this.deps.onArc?.(ev, srcPt, dstPt, c1, hitCount);
  }

  private tagDot(node: SVGCircleElement | null, rec: DotRecord): void {
    if (node) (node as SVGCircleElement & { __wt?: DotRecord }).__wt = rec;
  }

  private recordOf(node: SVGCircleElement): DotRecord | undefined {
    return (node as SVGCircleElement & { __wt?: DotRecord }).__wt;
  }

  // ── History (replay) dots ─────────────────────────────────────────────────
  drawHistoryDot(ev: ConnectionEvent): void {
    if (!hasGeo(ev.src_lat, ev.src_lon)) return;
    const existing = this.historyDots.get(ev.src_ip) ?? this.registry.get(this.keyFor(ev))?.dot;
    if (existing) {
      existing.hitCount++;
      existing.ev = ev;
      existing.el.attr('r', dotRadius(existing.hitCount));
      return;
    }
    const srcPt: LonLat = [ev.src_lon, ev.src_lat];
    const p = this.deps.view.project(srcPt);
    if (!p) return;
    const banned = this.deps.isBanned(ev.src_ip, ev.dst_port);
    const el = this.deps.view.layers.dots
      .append('circle')
      .attr('class', 'src-dot')
      .attr('cx', p[0])
      .attr('cy', p[1])
      .attr('r', 3)
      .attr('fill', banned ? this.deps.bannedColor() : this.deps.colorForPort(ev.dst_port || 'unknown'))
      .attr('opacity', banned ? 0.9 : 0.35)
      .datum(srcPt)
      .attr('aria-label', `${ev.src_ip} ${ev.src_city ?? ''} ${ev.src_cc ?? ''}`.trim()) as unknown as CircleSel;
    if (banned) el.classed('banned', true);
    const rec: DotRecord = { el, ev, hitCount: 1 };
    this.deps.tooltip.attach(el, () => ({ ev: rec.ev, hitCount: rec.hitCount }));
    this.tagDot(el.node(), rec);
    this.historyDots.set(ev.src_ip, rec);
    this.trackDot(el.node());
  }

  // ── TTL / caps ────────────────────────────────────────────────────────────
  private resetTTL(entry: ArcEntry): void {
    if (entry.expireTimer) clearTimeout(entry.expireTimer);
    entry.expireTimer = setTimeout(() => this.expireArc(entry.key), ARC_TTL_MS);
  }

  private expireArc(key: string): void {
    const entry = this.registry.get(key);
    if (!entry) return;
    this.registry.delete(key);
    entry.arcPath
      .interrupt()
      .transition()
      .duration(this.deps.reducedMotion() ? 0 : 800)
      .attr('opacity', 0)
      .on('end', function () {
        d3.select(this).remove();
      });
    this.releaseGradient(entry.grad);
    const i = this.arcRing.indexOf(key);
    if (i !== -1) this.arcRing.splice(i, 1);
    // The dot stays as a (now historical) dot so the IP remains visible.
    if (!this.historyDots.has(entry.ev.src_ip)) this.historyDots.set(entry.ev.src_ip, entry.dot);
  }

  private trackArc(key: string): void {
    this.arcRing.push(key);
    while (this.arcRing.length > MAX_ARCS) {
      const old = this.arcRing.shift()!;
      const e = this.registry.get(old);
      if (e) {
        if (e.expireTimer) clearTimeout(e.expireTimer);
        this.registry.delete(old);
        e.arcPath.interrupt().remove();
        this.releaseGradient(e.grad);
        if (!this.historyDots.has(e.ev.src_ip)) this.historyDots.set(e.ev.src_ip, e.dot);
      }
    }
  }

  private trackDot(node: SVGCircleElement | null): void {
    if (!node) return;
    this.dotRing.push(node);
    while (this.dotRing.length > MAX_DOTS) {
      const old = this.dotRing.shift()!;
      const rec = this.recordOf(old);
      if (rec && this.historyDots.get(rec.ev.src_ip) === rec) this.historyDots.delete(rec.ev.src_ip);
      old.remove();
    }
  }

  private removeDotNode(node: SVGCircleElement | null): void {
    if (!node) return;
    const i = this.dotRing.indexOf(node);
    if (i !== -1) this.dotRing.splice(i, 1);
    d3.select(node).interrupt().remove();
  }

  // ── Pulses ────────────────────────────────────────────────────────────────
  private sendPulse(entry: ArcEntry, hitCount: number): void {
    if (this.deps.reducedMotion()) return;
    if (this.activePulses >= MAX_PULSES) return;
    const pts = entry.points;
    if (pts.length < 2 || !allFinite(pts)) return;
    this.activePulses++;
    const r = Math.min(8, 4 + Math.log2(Math.max(1, hitCount)) * 0.8);
    const pulse = this.deps.view.layers.pulses
      .append('circle')
      .attr('class', 'arc-pulse')
      .attr('cx', pts[0]![0])
      .attr('cy', pts[0]![1])
      .attr('r', r)
      .attr('fill', entry.c1)
      .attr('opacity', 0.95)
      .attr('stroke', entry.c1)
      .attr('stroke-width', r * 0.8)
      .attr('stroke-opacity', 0.45);

    const timer = d3.timer((elapsed) => {
      const t = Math.min(1, elapsed / PULSE_DURATION_MS);
      const [x, y] = pointAlong(entry.points, d3.easeQuadInOut(t));
      if (!Number.isFinite(x) || !Number.isFinite(y) || t >= 1) {
        pulse.remove();
        this.activePulses--;
        this.pulseTimers.delete(timer);
        timer.stop();
        return;
      }
      pulse.attr('cx', x).attr('cy', y);
      if (t > 0.8) pulse.attr('opacity', 0.95 * (1 - (t - 0.8) / 0.2));
    });
    this.pulseTimers.add(timer);
  }

  private pulseDot(dot: DotRecord): void {
    const r = dotRadius(dot.hitCount);
    if (this.deps.reducedMotion()) {
      dot.el.attr('r', r).attr('opacity', 0.6);
      return;
    }
    dot.el.interrupt().attr('opacity', 1).attr('r', r + 2).transition().duration(400).attr('r', r).attr('opacity', 0.5);
  }

  // ── Ban styling ───────────────────────────────────────────────────────────
  /** Re-style every dot from the current ban set; flash newly banned dots. */
  syncBanned(): void {
    const banned = this.deps.bannedColor();
    for (const node of this.deps.view.layers.dots.selectAll<SVGCircleElement, unknown>('.src-dot').nodes()) {
      const rec = this.recordOf(node);
      if (!rec) continue;
      const sel = d3.select(node);
      const isBanned = this.deps.isBanned(rec.ev.src_ip, rec.ev.dst_port);
      const was = sel.classed('banned');
      sel.classed('banned', isBanned);
      if (isBanned) {
        sel.interrupt().attr('fill', banned).attr('opacity', 0.9);
        if (!was && !this.deps.reducedMotion()) {
          sel.classed('banned-flash', true);
          node.addEventListener('animationend', () => sel.classed('banned-flash', false), { once: true });
        }
      } else if (was) {
        sel.attr('fill', this.deps.colorForPort(rec.ev.dst_port || 'unknown')).attr('opacity', 0.35);
      }
    }
  }

  /** Re-colour dots/arcs after a theme change (port slot colours shift). */
  recolor(): void {
    for (const node of this.deps.view.layers.dots.selectAll<SVGCircleElement, unknown>('.src-dot').nodes()) {
      const rec = this.recordOf(node);
      if (!rec) continue;
      const sel = d3.select(node);
      if (sel.classed('banned')) sel.attr('fill', this.deps.bannedColor());
      else sel.attr('fill', this.deps.colorForPort(rec.ev.dst_port || 'unknown'));
    }
    for (const e of this.registry.values()) {
      const c1 = this.deps.colorForPort(e.ev.dst_port || 'unknown');
      const c2 = this.deps.arcEndColor();
      if (c1 !== e.c1 || c2 !== e.c2) {
        this.releaseGradient(e.grad);
        const p0 = this.deps.view.project(e.srcPt);
        const p1 = this.deps.view.project(e.dstPt);
        e.grad = this.acquireGradient(c1, c2, p0?.[0] ?? 0, p0?.[1] ?? 0, p1?.[0] ?? 0, p1?.[1] ?? 0);
        e.c1 = c1;
        e.c2 = c2;
        e.arcPath.attr('stroke', `url(#${e.grad.id})`);
      }
    }
  }

  // ── Reprojection ──────────────────────────────────────────────────────────
  private reproject(): void {
    const view = this.deps.view;
    view.layers.dots.selectAll<SVGCircleElement, LonLat>('.src-dot').each(function (d) {
      if (!d) return;
      const p = view.project(d);
      if (p) d3.select(this).attr('cx', p[0]).attr('cy', p[1]);
    });
    for (const e of this.registry.values()) {
      const p0 = view.project(e.srcPt);
      const p1 = view.project(e.dstPt);
      if (!p0 || !p1) continue;
      const geom = quadArc(p0[0], p0[1], p1[0], p1[1], ARC_BULGE, view.h * 0.25);
      e.points = geom.points;
      e.arcPath.attr('d', geom.d);
      e.grad.el.attr('x1', p0[0]).attr('y1', p0[1]).attr('x2', p1[0]).attr('y2', p1[1]);
    }
    this.drawSelf();
  }

  // ── Reset ─────────────────────────────────────────────────────────────────
  reset(): void {
    for (const e of this.registry.values()) {
      if (e.expireTimer) clearTimeout(e.expireTimer);
      e.arcPath.interrupt().remove();
    }
    this.registry.clear();
    this.arcRing.length = 0;
    this.deps.view.layers.arcs.selectAll('*').remove();
    this.deps.view.layers.pulses.selectAll('*').remove();
    for (const t of this.pulseTimers) t.stop();
    this.pulseTimers.clear();
    this.activePulses = 0;
    for (const g of this.gradients.values()) g.refCount = 0;
    this.deps.view.layers.dots.selectAll('.src-dot').interrupt().remove();
    this.dotRing.length = 0;
    this.historyDots.clear();
    this.floodBuffer.clear();
    if (this.floodTimer) clearTimeout(this.floodTimer);
    this.floodTimer = null;
    this.arcTimestamps.length = 0;
    this.drawSelf();
  }

  get arcCount(): number {
    return this.registry.size;
  }

  get dotCount(): number {
    return this.dotRing.length;
  }
}
