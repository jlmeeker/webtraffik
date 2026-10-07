import * as d3 from 'd3';
import type { ConnectionEvent, LonLat } from '../lib/types';
import { placeLabel } from '../lib/utils/format';
import type { MapView } from './view';

const MAG_IDLE_MS = 5000;
const MAG_PAD_DEG = 8;
const MAG_MIN_SPAN = 15;
const MAG_BBOX_TOLERANCE = 0.5;
const MAG_THROTTLE_MS = 200;
const MAG_SHORT_THRESHOLD = 0.25;
const MAG_ZOOMED_THRESHOLD = 0.12;

interface BBox {
  lonMin: number;
  lonMax: number;
  latMin: number;
  latMax: number;
}

/**
 * Compute a Mercator bbox around two points with padding, a minimum span, and
 * an aspect-ratio correction so arcs are not squished (pure; unit-testable).
 */
export function fitBBox(src: LonLat, dst: LonLat, aspect: number): BBox {
  let lonMin = Math.min(src[0], dst[0]) - MAG_PAD_DEG;
  let lonMax = Math.max(src[0], dst[0]) + MAG_PAD_DEG;
  let latMin = Math.min(src[1], dst[1]) - MAG_PAD_DEG;
  let latMax = Math.max(src[1], dst[1]) + MAG_PAD_DEG;
  if (lonMax - lonMin < MAG_MIN_SPAN) {
    const pad = (MAG_MIN_SPAN - (lonMax - lonMin)) / 2;
    lonMin -= pad;
    lonMax += pad;
  }
  if (latMax - latMin < MAG_MIN_SPAN) {
    const pad = (MAG_MIN_SPAN - (latMax - latMin)) / 2;
    latMin -= pad;
    latMax += pad;
  }
  lonMin = Math.max(-180, lonMin);
  lonMax = Math.min(180, lonMax);
  latMin = Math.max(-85, latMin);
  latMax = Math.min(85, latMax);

  const proj = d3.geoMercator().scale(1).center([0, 0]).translate([0, 0]);
  const measure = () => {
    const tl = proj([lonMin, latMax])!;
    const br = proj([lonMax, latMin])!;
    return { w: Math.abs(br[0] - tl[0]), h: Math.abs(br[1] - tl[1]) };
  };
  const m = measure();
  const projAspect = m.h > 0 ? m.w / m.h : aspect;
  if (projAspect < aspect * 0.5) {
    const factor = (m.h * aspect) / m.w;
    const c = (lonMin + lonMax) / 2;
    const half = ((lonMax - lonMin) * factor) / 2;
    lonMin = Math.max(-180, c - half);
    lonMax = Math.min(180, c + half);
  } else if (projAspect > aspect * 2) {
    const factor = m.w / aspect / m.h;
    const c = (latMin + latMax) / 2;
    const half = ((latMax - latMin) * factor) / 2;
    latMin = Math.max(-85, c - half);
    latMax = Math.min(85, c + half);
  }
  return { lonMin, lonMax, latMin, latMax };
}

/** Inset that zooms into short arcs (or arcs clipped by the main zoom). */
export class Magnifier {
  private readonly root: HTMLElement;
  private readonly svg: d3.Selection<SVGSVGElement, unknown, null, undefined>;
  private readonly projection = d3.geoMercator();
  private readonly path = d3.geoPath(this.projection);
  private readonly gSphere: d3.Selection<SVGGElement, unknown, null, undefined>;
  private readonly gLand: d3.Selection<SVGGElement, unknown, null, undefined>;
  private readonly gArc: d3.Selection<SVGGElement, unknown, null, undefined>;
  private readonly gDot: d3.Selection<SVGGElement, unknown, null, undefined>;
  private initialized = false;
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private throttleTimer: ReturnType<typeof setTimeout> | null = null;
  private pending: Parameters<Magnifier['showArc']> | null = null;
  private lastBBox: BBox | null = null;
  private w = 420;
  private h = 300;

  constructor(
    rootEl: HTMLElement,
    svgEl: SVGSVGElement,
    private readonly view: MapView,
    private readonly selfColor: () => string,
    private readonly reducedMotion: () => boolean,
  ) {
    this.root = rootEl;
    this.svg = d3.select(svgEl);
    this.gSphere = this.svg.append('g');
    this.gLand = this.svg.append('g');
    this.gArc = this.svg.append('g');
    this.gDot = this.svg.append('g');
    this.gSphere.append('path').datum({ type: 'Sphere' }).attr('class', 'mag-sphere');
  }

  private init(): boolean {
    const world = this.view.getWorld();
    if (this.initialized || !world) return this.initialized;
    this.initialized = true;
    this.w = this.root.clientWidth || 420;
    this.h = this.root.clientHeight || 300;
    this.svg.attr('viewBox', `0 0 ${this.w} ${this.h}`);
    this.gLand.append('path').datum(world.land).attr('class', 'mag-land');
    this.gLand.append('path').datum(world.borders).attr('class', 'mag-border');
    this.gLand.append('path').datum(world.lakes).attr('class', 'mag-lake');
    this.gLand.append('path').datum(world.rivers).attr('class', 'mag-river');
    return true;
  }

  /** Decide whether the inset adds value for this arc. */
  shouldShow(src: LonLat, dst: LonLat): boolean {
    const p0 = this.view.project(src);
    const p1 = this.view.project(dst);
    if (!p0 || !p1) return false;
    const dist = Math.hypot(p1[0] - p0[0], p1[1] - p0[1]);
    const w = this.view.w;
    const isShort = dist < w * MAG_SHORT_THRESHOLD;
    const offScreen = !this.view.isOnScreen(p0) || !this.view.isOnScreen(p1);
    const isZoomed = this.view.k > 1.5;
    if (isShort && isZoomed && dist >= w * MAG_ZOOMED_THRESHOLD) return false;
    if (isZoomed && offScreen) return true;
    return isShort;
  }

  /** Throttled entry point — only the latest call per window is rendered. */
  showArcThrottled(ev: ConnectionEvent, src: LonLat, dst: LonLat, color: string, hitCount: number): void {
    this.pending = [ev, src, dst, color, hitCount];
    if (this.throttleTimer) return;
    this.throttleTimer = setTimeout(() => {
      this.throttleTimer = null;
      if (this.pending) {
        this.showArc(...this.pending);
        this.pending = null;
      }
    }, MAG_THROTTLE_MS);
  }

  showArc(ev: ConnectionEvent, src: LonLat, dst: LonLat, color: string, hitCount: number): void {
    if (!this.init()) return;
    const bbox = fitBBox(src, dst, this.w / this.h);
    const changed =
      !this.lastBBox ||
      Math.abs(bbox.lonMin - this.lastBBox.lonMin) > MAG_BBOX_TOLERANCE ||
      Math.abs(bbox.lonMax - this.lastBBox.lonMax) > MAG_BBOX_TOLERANCE ||
      Math.abs(bbox.latMin - this.lastBBox.latMin) > MAG_BBOX_TOLERANCE ||
      Math.abs(bbox.latMax - this.lastBBox.latMax) > MAG_BBOX_TOLERANCE;
    if (changed) {
      this.fitProjection(bbox);
      this.gSphere.select('path').attr('d', this.path as unknown as string);
      this.gLand.selectAll('path').attr('d', this.path as unknown as string);
      this.lastBBox = bbox;
    }

    this.gArc.selectAll('*').remove();
    this.gDot.selectAll('*').remove();
    const m0 = this.projection(src);
    const m1 = this.projection(dst);
    if (!m0 || !m1) return;

    const interp = d3.geoInterpolate(src, dst);
    const N = 30;
    const line: Array<[number, number]> = [];
    for (let i = 0; i <= N; i++) {
      const p = this.projection(interp(i / N));
      if (p) line.push([p[0], p[1]]);
    }
    const gen = d3
      .line<[number, number]>()
      .x((d) => d[0])
      .y((d) => d[1])
      .curve(d3.curveNatural);
    let len = 0;
    for (let i = 1; i < line.length; i++) len += Math.hypot(line[i]![0] - line[i - 1]![0], line[i]![1] - line[i - 1]![1]);

    const arc = this.gArc
      .append('path')
      .attr('class', 'mag-arc')
      .attr('d', gen(line) ?? '')
      .attr('stroke', color)
      .attr('stroke-width', Math.min(8, 2 + (hitCount - 1) * 0.5));
    if (!this.reducedMotion()) {
      arc.attr('stroke-dasharray', len).attr('stroke-dashoffset', len).transition().duration(800).ease(d3.easeQuadInOut).attr('stroke-dashoffset', 0);
    }

    const dotR = Math.min(8, 4 + Math.log2(Math.max(1, hitCount)));
    const d0 = this.gDot.append('circle').attr('class', 'mag-dot').attr('cx', m0[0]).attr('cy', m0[1]).attr('fill', color);
    if (this.reducedMotion()) d0.attr('r', dotR);
    else d0.attr('r', 0).transition().duration(300).attr('r', dotR);
    this.gDot.append('circle').attr('class', 'mag-self-dot').attr('cx', m1[0]).attr('cy', m1[1]).attr('r', 5).attr('fill', this.selfColor());

    const label = placeLabel(ev.src_city, ev.src_cc, ev.src_ip);
    if (label) {
      this.gDot
        .append('text')
        .attr('class', 'mag-label-text')
        .attr('x', m0[0] + 8)
        .attr('y', m0[1] - 6)
        .text(label);
    }
    this.show();
  }

  private fitProjection(b: BBox): void {
    const centerLon = (b.lonMin + b.lonMax) / 2;
    const centerLat = (b.latMin + b.latMax) / 2;
    this.projection.scale(1).center([0, 0]).translate([0, 0]);
    const tl = this.projection([b.lonMin, b.latMax])!;
    const br = this.projection([b.lonMax, b.latMin])!;
    const pw = Math.max(1e-6, Math.abs(br[0] - tl[0]));
    const ph = Math.max(1e-6, Math.abs(br[1] - tl[1]));
    const scale = 0.85 * Math.min(this.w / pw, this.h / ph);
    this.projection.scale(scale).center([centerLon, centerLat]).translate([this.w / 2, this.h / 2]);
  }

  private show(): void {
    this.root.classList.add('visible');
    this.root.setAttribute('aria-hidden', 'false');
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.hide(), MAG_IDLE_MS);
  }

  hide(): void {
    this.root.classList.remove('visible');
    this.root.setAttribute('aria-hidden', 'true');
    this.idleTimer = null;
  }

  reset(): void {
    if (this.throttleTimer) clearTimeout(this.throttleTimer);
    this.throttleTimer = null;
    this.pending = null;
    this.lastBBox = null;
    this.hide();
  }
}
