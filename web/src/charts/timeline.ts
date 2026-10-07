import * as d3 from 'd3';
import { chartTip, chartTokens, fmtInt, gridLines, legend, makeSvg, MARGIN, styleAxis, tipRows, type GSel } from './base';

export interface TimePoint {
  t: Date;
  v: number;
}

export interface Series {
  key: string;
  label: string;
  color: string;
  points: TimePoint[];
}

function timeFormat(domain: [Date, Date]): (d: Date) => string {
  const span = domain[1].getTime() - domain[0].getTime();
  if (span <= 36 * 3600e3) return d3.timeFormat('%H:%M');
  if (span <= 14 * 86400e3) return d3.timeFormat('%b %d %H:%M');
  return d3.timeFormat('%b %d');
}

/** Single-series column chart over time with hover tooltip. */
export function columns(container: HTMLElement, points: TimePoint[], opts: { label: string; color?: string | undefined; height?: number }): void {
  const t = chartTokens();
  const height = opts.height ?? 220;
  const { svg, w } = makeSvg(container, height, opts.label);
  const m = MARGIN;
  const innerW = w - m.left - m.right;
  const innerH = height - m.top - m.bottom;
  const g = svg.append('g').attr('transform', `translate(${m.left},${m.top})`);
  if (points.length === 0) {
    g.append('text').attr('x', innerW / 2).attr('y', innerH / 2).attr('text-anchor', 'middle').attr('fill', t.muted).attr('font-size', 11).text('no data');
    return;
  }
  const times = points.map((p) => p.t.getTime());
  const step = points.length > 1 ? d3.min(d3.pairs(times), ([a, b]) => b - a) ?? 3600e3 : 3600e3;
  const domain: [Date, Date] = [new Date(Math.min(...times)), new Date(Math.max(...times) + step)];
  const x = d3.scaleTime().domain(domain).range([0, innerW]);
  const y = d3.scaleLinear().domain([0, d3.max(points, (p) => p.v) ?? 1]).nice().range([innerH, 0]);
  const color = opts.color ?? t.accent;

  gridLines(g.append('g'), y, innerW, t);
  const barW = Math.max(2, (x(new Date(domain[0].getTime() + step)) - x(domain[0])) - 2);

  g.selectAll('rect')
    .data(points)
    .join('rect')
    .attr('x', (p) => x(p.t) + 1)
    .attr('y', (p) => y(p.v))
    .attr('width', barW)
    .attr('height', (p) => Math.max(0, innerH - y(p.v)))
    .attr('rx', Math.min(3, barW / 2))
    .attr('fill', color)
    .attr('opacity', 0.9);

  styleAxis(g.append('g').attr('transform', `translate(0,${innerH})`).call(d3.axisBottom(x).ticks(Math.min(8, Math.floor(innerW / 90))).tickFormat((d) => timeFormat(domain)(d as Date)).tickSizeOuter(0)) as GSel, t);
  styleAxis(g.append('g').call(d3.axisLeft(y).ticks(4).tickFormat((d) => fmtInt(d as number)).tickSize(0)) as GSel, t);

  const tip = chartTip();
  const fmt = timeFormat(domain);
  g.append('rect')
    .attr('width', innerW)
    .attr('height', innerH)
    .attr('fill', 'transparent')
    .on('mousemove', (event: MouseEvent) => {
      const [mx] = d3.pointer(event);
      const tt = x.invert(mx).getTime();
      const i = d3.bisector((p: TimePoint) => p.t.getTime()).left(points, tt) - 1;
      const p = points[Math.max(0, Math.min(points.length - 1, i))];
      if (!p) return;
      tip.show(event.clientX, event.clientY, tipRows([[fmt(p.t), fmtInt(p.v), color]]));
    })
    .on('mouseleave', () => tip.hide());
}

/**
 * Multi-series line chart. ≤ 8 series in fixed slot colours, legend always
 * present, hover crosshair tooltip listing every series at that time.
 */
export function lines(container: HTMLElement, series: Series[], opts: { label: string; height?: number }): void {
  const t = chartTokens();
  const height = opts.height ?? 220;
  const { svg, w } = makeSvg(container, height, opts.label);
  const m = MARGIN;
  const innerW = w - m.left - m.right;
  const innerH = height - m.top - m.bottom;
  const g = svg.append('g').attr('transform', `translate(${m.left},${m.top})`);
  const all = series.flatMap((s) => s.points);
  if (all.length === 0) {
    g.append('text').attr('x', innerW / 2).attr('y', innerH / 2).attr('text-anchor', 'middle').attr('fill', t.muted).attr('font-size', 11).text('no data');
    return;
  }
  const domain = d3.extent(all, (p) => p.t) as [Date, Date];
  if (domain[0].getTime() === domain[1].getTime()) domain[1] = new Date(domain[0].getTime() + 3600e3);
  const x = d3.scaleTime().domain(domain).range([0, innerW]);
  const y = d3.scaleLinear().domain([0, d3.max(all, (p) => p.v) ?? 1]).nice().range([innerH, 0]);
  gridLines(g.append('g'), y, innerW, t);

  const line = d3
    .line<TimePoint>()
    .x((p) => x(p.t))
    .y((p) => y(p.v))
    .curve(d3.curveMonotoneX);

  for (const s of series) {
    const sorted = [...s.points].sort((a, b) => a.t.getTime() - b.t.getTime());
    g.append('path').datum(sorted).attr('fill', 'none').attr('stroke', s.color).attr('stroke-width', 2).attr('stroke-linejoin', 'round').attr('d', line);
    if (sorted.length <= 3) {
      g.selectAll(null)
        .data(sorted)
        .join('circle')
        .attr('cx', (p) => x(p.t))
        .attr('cy', (p) => y(p.v))
        .attr('r', 3.5)
        .attr('fill', s.color)
        .attr('stroke', t.surface)
        .attr('stroke-width', 2);
    }
  }

  styleAxis(g.append('g').attr('transform', `translate(0,${innerH})`).call(d3.axisBottom(x).ticks(Math.min(8, Math.floor(innerW / 90))).tickFormat((d) => timeFormat(domain)(d as Date)).tickSizeOuter(0)) as GSel, t);
  styleAxis(g.append('g').call(d3.axisLeft(y).ticks(4).tickFormat((d) => fmtInt(d as number)).tickSize(0)) as GSel, t);

  const cross = g.append('line').attr('y1', 0).attr('y2', innerH).attr('stroke', t.axis).attr('stroke-width', 1).style('display', 'none');
  const tip = chartTip();
  const fmt = timeFormat(domain);
  g.append('rect')
    .attr('width', innerW)
    .attr('height', innerH)
    .attr('fill', 'transparent')
    .on('mousemove', (event: MouseEvent) => {
      const [mx] = d3.pointer(event);
      const tt = x.invert(mx).getTime();
      let bestT: number | null = null;
      for (const p of all) {
        if (bestT === null || Math.abs(p.t.getTime() - tt) < Math.abs(bestT - tt)) bestT = p.t.getTime();
      }
      if (bestT === null) return;
      cross.style('display', null).attr('x1', x(bestT)).attr('x2', x(bestT));
      const rows: Array<[string, string, string?]> = [[fmt(new Date(bestT)), '']];
      for (const s of series) {
        const p = s.points.find((q) => q.t.getTime() === bestT);
        rows.push([s.label, p ? fmtInt(p.v) : '—', s.color]);
      }
      tip.show(event.clientX, event.clientY, tipRows(rows));
    })
    .on('mouseleave', () => {
      cross.style('display', 'none');
      tip.hide();
    });

  legend(
    container,
    series.map((s) => ({ label: s.label, color: s.color })),
  );
}
