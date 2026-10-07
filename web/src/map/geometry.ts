// Pure screen-space arc geometry (unit-tested, no DOM).

export interface QuadArc {
  d: string;
  /** Sampled points along the curve (for pulse travel + length estimate). */
  points: Array<[number, number]>;
  length: number;
  ctrl: [number, number];
}

/**
 * Quadratic bezier "bow" from (x0,y0) to (x1,y1). The control point sits above
 * the chord midpoint; bulge scales with chord length and is capped so tall
 * arcs never leave the viewport.
 */
export function quadArc(
  x0: number,
  y0: number,
  x1: number,
  y1: number,
  bulgeFactor: number,
  maxBulge: number,
  samples = 20,
): QuadArc {
  const mx = (x0 + x1) / 2;
  const my = (y0 + y1) / 2;
  const chord = Math.hypot(x1 - x0, y1 - y0);
  const bulge = Math.min(chord * bulgeFactor, maxBulge);
  const cx = mx;
  const cy = my - bulge;
  const points: Array<[number, number]> = [];
  for (let i = 0; i <= samples; i++) {
    const t = i / samples;
    const u = 1 - t;
    points.push([u * u * x0 + 2 * u * t * cx + t * t * x1, u * u * y0 + 2 * u * t * cy + t * t * y1]);
  }
  let length = 0;
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1]!;
    const b = points[i]!;
    length += Math.hypot(b[0] - a[0], b[1] - a[1]);
  }
  return { d: `M${x0},${y0} Q${cx},${cy} ${x1},${y1}`, points, length, ctrl: [cx, cy] };
}

/** Linear interpolation along a sampled polyline at eased parameter t∈[0,1]. */
export function pointAlong(points: ReadonlyArray<readonly [number, number]>, t: number): [number, number] {
  const last = points.length - 1;
  if (last < 0) return [NaN, NaN];
  if (last === 0) return [points[0]![0], points[0]![1]];
  const raw = Math.min(1, Math.max(0, t)) * last;
  const i = Math.min(Math.floor(raw), last - 1);
  const f = raw - i;
  const a = points[i]!;
  const b = points[i + 1]!;
  return [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f];
}

/** stroke width grows with hit count: 1 → 1.5px, 10+ → 6px. */
export function arcWidth(count: number): number {
  return Math.min(6, 1.5 + (Math.max(1, count) - 1) * 0.5);
}

export function dotRadius(count: number): number {
  return Math.min(6, 3 + Math.log2(Math.max(1, count)));
}

export function allFinite(points: ReadonlyArray<readonly [number, number]>): boolean {
  return points.every((p) => Number.isFinite(p[0]) && Number.isFinite(p[1]));
}

export interface FitBox {
  k: number;
  tx: number;
  ty: number;
}

/**
 * Zoom transform (k, tx, ty) that fits the given *base-projected* points into
 * a w×h viewport with `pad` fraction padding, capped at maxK.
 */
export function fitTransform(
  pts: ReadonlyArray<readonly [number, number]>,
  w: number,
  h: number,
  pad = 0.15,
  maxK = 10,
): FitBox | null {
  const valid = pts.filter((p) => Number.isFinite(p[0]) && Number.isFinite(p[1]));
  if (valid.length < 2) return null;
  let x0 = Infinity,
    x1 = -Infinity,
    y0 = Infinity,
    y1 = -Infinity;
  for (const [x, y] of valid) {
    if (x < x0) x0 = x;
    if (x > x1) x1 = x;
    if (y < y0) y0 = y;
    if (y > y1) y1 = y;
  }
  const bw = Math.max(x1 - x0, 1);
  const bh = Math.max(y1 - y0, 1);
  const k = Math.max(1, Math.min(maxK, (1 - 2 * pad) * Math.min(w / bw, h / bh)));
  const cx = (x0 + x1) / 2;
  const cy = (y0 + y1) / 2;
  return { k, tx: w / 2 - k * cx, ty: h / 2 - k * cy };
}
