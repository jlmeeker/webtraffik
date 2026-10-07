import * as d3 from 'd3';
import type { LonLat } from '../lib/types';
import { fitTransform } from './geometry';
import type { WorldGeo } from './world';

export type Sel<E extends Element = SVGGElement> = d3.Selection<E, unknown, null, undefined>;

/**
 * Owns the SVG, the Natural Earth projection and projection-based zoom.
 * Zooming updates the projection (not an SVG transform) so strokes and dots
 * stay crisp; every layer registers a reprojector that is called on
 * zoom/resize.
 */
export class MapView {
  readonly svg: Sel<SVGSVGElement>;
  readonly projection = d3.geoNaturalEarth1();
  readonly path = d3.geoPath(this.projection);
  readonly defs: Sel<SVGDefsElement>;
  readonly layers: {
    sphere: Sel;
    graticule: Sel;
    land: Sel;
    arcs: Sel;
    pulses: Sel;
    dots: Sel;
    trace: Sel;
  };
  w = 0;
  h = 0;
  private baseScale = 1;
  private baseTranslate: [number, number] = [0, 0];
  transform: d3.ZoomTransform = d3.zoomIdentity;
  readonly zoom: d3.ZoomBehavior<SVGSVGElement, unknown>;
  private reprojectors = new Set<() => void>();
  private zoomListeners = new Set<(k: number) => void>();
  private world: WorldGeo | null = null;

  constructor(readonly el: SVGSVGElement) {
    this.svg = d3.select(el);
    this.svg.attr('role', 'img').attr('aria-label', 'World map of live connections');
    this.defs = this.svg.append('defs');
    this.makeGlow('glow-accent', 3);
    this.makeGlow('glow-arc', 2);

    this.layers = {
      sphere: this.svg.append('g').attr('class', 'layer-sphere'),
      graticule: this.svg.append('g').attr('class', 'layer-graticule'),
      land: this.svg.append('g').attr('class', 'layer-land'),
      arcs: this.svg.append('g').attr('class', 'layer-arcs'),
      pulses: this.svg.append('g').attr('class', 'layer-pulses'),
      dots: this.svg.append('g').attr('class', 'layer-dots'),
      trace: this.svg.append('g').attr('class', 'layer-trace'),
    };

    this.layers.sphere.append('path').datum({ type: 'Sphere' }).attr('class', 'sphere');
    this.layers.graticule.append('path').datum(d3.geoGraticule()()).attr('class', 'graticule');

    this.zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 20])
      .filter((event: Event & { type: string; button?: number; target: EventTarget | null }) => {
        if (event.type === 'wheel') return true;
        const t = event.target as Element | null;
        if (t && t.classList && t.classList.contains('src-dot')) return false;
        return !event.button;
      })
      .on('zoom', (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        this.transform = event.transform;
        this.reproject();
        for (const l of this.zoomListeners) l(this.transform.k);
      });

    this.svg.call(this.zoom);
    this.svg.on('dblclick.zoom', null);
    this.svg.on('dblclick', () => this.zoomTo(d3.zoomIdentity, 750));

    this.measure();
    this.reproject();
    window.addEventListener('resize', () => this.resize());
  }

  private makeGlow(id: string, std: number): void {
    const f = this.defs
      .append('filter')
      .attr('id', id)
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', std).attr('result', 'blur');
    const m = f.append('feMerge');
    m.append('feMergeNode').attr('in', 'blur');
    m.append('feMergeNode').attr('in', 'blur');
    m.append('feMergeNode').attr('in', 'SourceGraphic');
  }

  private measure(): void {
    this.w = Math.max(1, this.el.clientWidth);
    this.h = Math.max(1, this.el.clientHeight);
    // Fit the full sphere into the viewport whichever dimension is tighter.
    this.baseScale = Math.min(this.w / 6.3, this.h / 3.1);
    this.baseTranslate = [this.w / 2, this.h / 2];
  }

  get k(): number {
    return this.transform.k;
  }

  onReproject(fn: () => void): () => void {
    this.reprojectors.add(fn);
    return () => this.reprojectors.delete(fn);
  }

  onZoom(fn: (k: number) => void): () => void {
    this.zoomListeners.add(fn);
    return () => this.zoomListeners.delete(fn);
  }

  /** Apply current zoom to the base projection and redraw all layers. */
  reproject(): void {
    const t = this.transform;
    this.projection
      .scale(this.baseScale * t.k)
      .translate([t.x + t.k * this.baseTranslate[0], t.y + t.k * this.baseTranslate[1]]);
    this.layers.sphere.select('path').attr('d', this.path as unknown as string);
    this.layers.graticule.select('path').attr('d', this.path as unknown as string);
    this.layers.land.selectAll('path').attr('d', this.path as unknown as string);
    for (const fn of this.reprojectors) fn();
  }

  resize(): void {
    this.measure();
    this.reproject();
  }

  /** Project [lon, lat] → screen or null when off-globe/invalid. */
  project(p: LonLat): [number, number] | null {
    const r = this.projection(p);
    if (!r || !Number.isFinite(r[0]) || !Number.isFinite(r[1])) return null;
    return r;
  }

  /** Project with the identity (unzoomed) projection. */
  projectBase(p: LonLat): [number, number] | null {
    const base = d3.geoNaturalEarth1().scale(this.baseScale).translate(this.baseTranslate);
    const r = base(p);
    if (!r || !Number.isFinite(r[0]) || !Number.isFinite(r[1])) return null;
    return r;
  }

  isOnScreen(xy: readonly [number, number]): boolean {
    return xy[0] >= 0 && xy[0] <= this.w && xy[1] >= 0 && xy[1] <= this.h;
  }

  zoomTo(t: d3.ZoomTransform, durationMs: number): void {
    if (durationMs <= 0) {
      this.svg.call(this.zoom.transform, t);
      return;
    }
    this.svg.transition().duration(durationMs).ease(d3.easeCubicInOut).call(this.zoom.transform, t);
  }

  zoomToWorld(durationMs: number): void {
    this.zoomTo(d3.zoomIdentity, durationMs);
  }

  /** Smoothly fit a set of geo points into the viewport. */
  zoomToPoints(points: readonly LonLat[], durationMs: number, pad = 0.15, maxK = 10): void {
    const projected = points.map((p) => this.projectBase(p)).filter((p): p is [number, number] => p !== null);
    const fit = fitTransform(projected, this.w, this.h, pad, maxK);
    if (!fit) return;
    this.zoomTo(d3.zoomIdentity.translate(fit.tx, fit.ty).scale(fit.k), durationMs);
  }

  /** Interrupt any zoom transition and snap to a transform. */
  snapTo(t: d3.ZoomTransform): void {
    this.svg.interrupt();
    this.svg.call(this.zoom.transform, t);
  }

  setWorld(world: WorldGeo): void {
    this.world = world;
    const g = this.layers.land;
    g.selectAll('*').remove();
    g.append('path').datum(world.land).attr('class', 'land');
    g.append('path').datum(world.borders).attr('class', 'border');
    g.append('path').datum(world.lakes).attr('class', 'lake');
    g.append('path').datum(world.rivers).attr('class', 'river');
    this.reproject();
  }

  getWorld(): WorldGeo | null {
    return this.world;
  }
}
