import * as d3 from 'd3';
import { openTraceroute } from '../lib/api';
import type { GeoPoint, Hop, LonLat } from '../lib/types';
import { cssVar } from '../lib/theme';
import { quadArc } from '../map/geometry';
import type { MapView } from '../map/view';
import { buildTracePath, type TracePoint } from './filter';

export const TRACE_ZOOM_IN_MS = 900;
export const TRACE_ZOOM_OUT_MS = 1200;
export const TRACE_ARC_DRAW_MS = 1800;
export const TRACE_STAGGER_MS = 2000;
export const TRACE_HOLD_MS = 2500;
export const TRACE_FADE_MS = 800;
const TRACE_DOT_RADIUS = 5;
const TRACE_BULGE = 0.3;

export interface TraceLayerOptions {
  indicator: HTMLElement;
  reducedMotion: () => boolean;
  getSelf: () => (GeoPoint & { ip?: string }) | null;
  onActiveChange?: (active: boolean) => void;
}

/**
 * Traceroute visualisation: SSE client → hop pipeline → sequential arc
 * animation (source → us) with auto-zoom, hold, fade and Escape to cancel.
 * While active, the live arc layer is suppressed so the path has the stage.
 */
export class TraceLayer {
  private _active = false;
  private drawing = false;
  private closeStream: (() => void) | null = null;
  private timers: ReturnType<typeof setTimeout>[] = [];
  private lastHops: TracePoint[] | null = null;
  private readonly g: d3.Selection<SVGGElement, unknown, null, undefined>;
  private colorScale = d3.scaleSequential<string>().domain([0, 1]);

  constructor(
    private readonly view: MapView,
    private readonly opts: TraceLayerOptions,
  ) {
    this.g = view.layers.trace;
    view.onReproject(() => {
      if (this.lastHops && this.lastHops.length >= 2 && !this.drawing) this.drawStatic(this.lastHops);
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this._active) {
        this.cancel();
        this.view.zoomToWorld(this.motionMs(TRACE_ZOOM_OUT_MS));
      }
    });
  }

  get active(): boolean {
    return this._active;
  }

  private setActive(v: boolean): void {
    if (this._active === v) return;
    this._active = v;
    this.opts.onActiveChange?.(v);
  }

  private motionMs(ms: number): number {
    return this.opts.reducedMotion() ? 0 : ms;
  }

  private refreshColors(): void {
    this.colorScale.interpolator(
      d3.interpolateRgbBasis([cssVar('--trace-far', '#ef5350'), cssVar('--trace-mid', '#ffb74d'), cssVar('--trace-near', '#b2ebf2')]),
    );
  }

  private hopColor(i: number, total: number): string {
    return this.colorScale(total <= 1 ? 1 : i / (total - 1));
  }

  private setIndicator(text: string | null): void {
    this.opts.indicator.textContent = text ?? '';
    this.opts.indicator.classList.toggle('visible', text !== null);
  }

  /** Begin a trace for `ip`; `srcGeo` is the known location of the source. */
  start(ip: string, srcGeo: GeoPoint | null): void {
    this.cancel();
    this.refreshColors();
    this.setActive(true);
    this.setIndicator(`Tracing route to ${ip}…`);
    const hops: Hop[] = [];

    this.closeStream = openTraceroute(ip, {
      onHop: (hop) => {
        if (!hop.lat && !hop.lon) return;
        hops.push(hop);
      },
      onDone: () => {
        this.closeStream = null;
        const path = buildTracePath(hops, ip, { srcGeo, self: this.opts.getSelf() });
        this.setIndicator(path.length >= 2 ? `${ip}: ${path.length - 1} hops` : `${ip}: no plottable hops`);
        this.animate(path);
      },
      onError: () => {
        this.closeStream = null;
        this.setIndicator('Traceroute unavailable');
        const t = setTimeout(() => {
          this.setIndicator(null);
          this.setActive(false);
        }, 1800);
        this.timers.push(t);
      },
    });
  }

  cancel(): void {
    if (this.closeStream) {
      this.closeStream();
      this.closeStream = null;
    }
    while (this.timers.length) clearTimeout(this.timers.pop());
    this.drawing = false;
    this.lastHops = null;
    this.g.selectAll('*').interrupt().remove();
    this.g.attr('opacity', 1);
    this.setIndicator(null);
    if (this._active) this.view.snapTo(d3.zoomIdentity);
    this.setActive(false);
  }

  private animate(hops: TracePoint[]): void {
    if (hops.length < 2) {
      const t = setTimeout(() => {
        this.setIndicator(null);
        this.setActive(false);
        this.view.zoomToWorld(this.motionMs(TRACE_ZOOM_OUT_MS));
      }, 1500);
      this.timers.push(t);
      return;
    }
    this.lastHops = hops;
    const pts: LonLat[] = hops.map((h) => [h.lon, h.lat]);
    this.view.zoomToPoints(pts, this.motionMs(TRACE_ZOOM_IN_MS));
    this.g.selectAll('*').remove();
    this.g.attr('opacity', 1);

    if (this.opts.reducedMotion()) {
      // No staggered animation: draw everything, hold, then clear.
      const t0 = setTimeout(() => {
        this.drawStatic(hops);
        const t1 = setTimeout(() => this.finish(), TRACE_HOLD_MS + hops.length * 400);
        this.timers.push(t1);
      }, 50);
      this.timers.push(t0);
      return;
    }

    this.drawing = true;
    const n = hops.length;
    let seg = 1;
    const next = () => {
      if (seg >= n || !this._active) {
        this.drawing = false;
        const hold = setTimeout(() => {
          this.g.selectAll('*').transition().duration(TRACE_FADE_MS).style('opacity', 0);
          const clean = setTimeout(() => this.finish(), TRACE_FADE_MS + 50);
          this.timers.push(clean);
        }, TRACE_HOLD_MS);
        this.timers.push(hold);
        return;
      }
      this.drawSegment(hops, seg);
      seg++;
      this.timers.push(setTimeout(next, TRACE_STAGGER_MS));
    };
    this.timers.push(setTimeout(next, TRACE_ZOOM_IN_MS + 100));
  }

  private finish(): void {
    this.g.selectAll('*').remove();
    this.g.attr('opacity', 1);
    this.lastHops = null;
    this.setIndicator(null);
    this.setActive(false);
    this.view.zoomToWorld(this.motionMs(TRACE_ZOOM_OUT_MS));
  }

  private segmentGeom(prev: [number, number], pt: [number, number]) {
    return quadArc(prev[0], prev[1], pt[0], pt[1], TRACE_BULGE, this.view.h * 0.15, 10);
  }

  private drawSegment(hops: TracePoint[], i: number): void {
    const n = hops.length;
    const pts = hops.map((h) => this.view.project([h.lon, h.lat]));
    if (i === 1 && pts[0]) {
      const c0 = this.hopColor(0, n - 1);
      this.g.append('circle').attr('cx', pts[0][0]).attr('cy', pts[0][1]).attr('r', 0).attr('fill', c0).attr('opacity', 0.95).transition().duration(250).attr('r', TRACE_DOT_RADIUS);
      this.label(pts[0], c0, hops[0]!, 1, true);
    }
    const prev = pts[i - 1];
    const pt = pts[i];
    if (!prev || !pt) return;
    const geom = this.segmentGeom(prev, pt);
    const segColor = this.hopColor(i - 0.5, n - 1);
    this.g
      .append('path')
      .attr('class', 'trace-arc')
      .attr('stroke', segColor)
      .attr('stroke-dasharray', geom.length)
      .attr('stroke-dashoffset', geom.length)
      .attr('d', geom.d)
      .transition()
      .duration(TRACE_ARC_DRAW_MS)
      .ease(d3.easeQuadOut)
      .attr('stroke-dashoffset', 0);

    const dotColor = this.hopColor(i, n - 1);
    const t = setTimeout(() => {
      this.g.append('circle').attr('cx', pt[0]).attr('cy', pt[1]).attr('r', 0).attr('fill', dotColor).attr('opacity', 0.95).transition().duration(250).attr('r', TRACE_DOT_RADIUS);
      this.label(pt, dotColor, hops[i]!, i + 1, true);
    }, TRACE_ARC_DRAW_MS * 0.8);
    this.timers.push(t);
  }

  private label(p: [number, number], color: string, hop: TracePoint, idx: number, fade: boolean): void {
    const text = String(idx);
    const x = p[0] + TRACE_DOT_RADIUS + 4;
    const y = p[1] - TRACE_DOT_RADIUS - 2;
    const w = text.length * 6 + 6;
    const g = this.g.append('g').attr('class', 'trace-label').attr('opacity', fade ? 0 : 1).attr('pointer-events', 'none');
    g.append('title').text([hop.ip, hop.city, hop.cc].filter(Boolean).join(' · '));
    g.append('rect').attr('x', x - 2).attr('y', y - 9).attr('width', w).attr('height', 12).attr('rx', 2);
    g.append('text').attr('x', x + 1).attr('y', y).attr('fill', color).text(text);
    if (fade) g.transition().duration(250).attr('opacity', 1);
  }

  /** Instant redraw of the full path (resize/zoom, reduced motion). */
  private drawStatic(hops: TracePoint[]): void {
    this.g.selectAll('*').remove();
    const n = hops.length;
    const pts = hops.map((h) => this.view.project([h.lon, h.lat]));
    for (let i = 1; i < n; i++) {
      const prev = pts[i - 1];
      const pt = pts[i];
      if (!prev || !pt) continue;
      const geom = this.segmentGeom(prev, pt);
      this.g.append('path').attr('class', 'trace-arc').attr('stroke', this.hopColor(i - 0.5, n - 1)).attr('d', geom.d);
    }
    hops.forEach((h, i) => {
      const p = pts[i];
      if (!p) return;
      const c = this.hopColor(i, n - 1);
      this.g.append('circle').attr('cx', p[0]).attr('cy', p[1]).attr('r', TRACE_DOT_RADIUS).attr('fill', c).attr('opacity', 0.95);
      this.label(p, c, h, i + 1, false);
    });
  }
}
