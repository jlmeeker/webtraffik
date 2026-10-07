import * as d3 from 'd3';
import { chartTip, chartTokens, fmtInt, makeSvg, tipRows } from './base';

export interface BarDatum {
  label: string;
  value: number;
  /** Optional per-entity colour (identity); default = one hue for all bars. */
  color?: string;
  title?: string;
}

/**
 * Horizontal bar chart for ranked nominal categories. One hue by default
 * (magnitude is already encoded by length); direct value labels at bar ends.
 */
export function horizontalBars(container: HTMLElement, data: BarDatum[], opts: { label: string; rowHeight?: number } = { label: 'bar chart' }): void {
  const t = chartTokens();
  const rowH = opts.rowHeight ?? 22;
  const labelW = Math.min(170, Math.max(60, d3.max(data, (d) => d.label.length)! * 7 + 8));
  const margin = { top: 4, right: 56, bottom: 4, left: labelW };
  const height = margin.top + margin.bottom + Math.max(1, data.length) * rowH;
  const { svg, w } = makeSvg(container, height, opts.label);
  if (data.length === 0) {
    svg.append('text').attr('x', w / 2).attr('y', height / 2).attr('text-anchor', 'middle').attr('fill', t.muted).attr('font-size', 11).text('no data');
    return;
  }
  const innerW = Math.max(10, w - margin.left - margin.right);
  const x = d3.scaleLinear().domain([0, d3.max(data, (d) => d.value) ?? 1]).nice().range([0, innerW]);
  const y = d3.scaleBand<string>().domain(data.map((d) => d.label)).range([0, data.length * rowH]).paddingInner(0.25);
  const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);
  const tip = chartTip();

  g.selectAll('text.lbl')
    .data(data)
    .join('text')
    .attr('class', 'lbl')
    .attr('x', -8)
    .attr('y', (d) => (y(d.label) ?? 0) + y.bandwidth() / 2)
    .attr('dy', '0.35em')
    .attr('text-anchor', 'end')
    .attr('fill', t.text2)
    .attr('font-size', 10.5)
    .attr('font-family', t.font)
    .text((d) => (d.label.length > 24 ? d.label.slice(0, 23) + '…' : d.label));

  g.selectAll('rect.bar')
    .data(data)
    .join('rect')
    .attr('class', 'bar')
    .attr('x', 0)
    .attr('y', (d) => y(d.label) ?? 0)
    .attr('height', y.bandwidth())
    .attr('width', (d) => Math.max(2, x(d.value)))
    .attr('rx', 3)
    .attr('fill', (d) => d.color ?? t.accent)
    .attr('opacity', 0.9);

  g.selectAll('text.val')
    .data(data)
    .join('text')
    .attr('class', 'val')
    .attr('x', (d) => Math.max(2, x(d.value)) + 6)
    .attr('y', (d) => (y(d.label) ?? 0) + y.bandwidth() / 2)
    .attr('dy', '0.35em')
    .attr('fill', t.text2)
    .attr('font-size', 10)
    .attr('font-family', t.font)
    .style('font-variant-numeric', 'tabular-nums')
    .text((d) => fmtInt(d.value));

  // Hit targets bigger than the marks: full row width.
  g.selectAll('rect.hit')
    .data(data)
    .join('rect')
    .attr('class', 'hit')
    .attr('x', -margin.left)
    .attr('y', (d) => (y(d.label) ?? 0) - (y.step() - y.bandwidth()) / 2)
    .attr('width', w)
    .attr('height', y.step())
    .attr('fill', 'transparent')
    .attr('tabindex', 0)
    .attr('role', 'listitem')
    .attr('aria-label', (d) => `${d.label}: ${fmtInt(d.value)}`)
    .on('mousemove focus', function (event: MouseEvent | FocusEvent, d) {
      const r = (this as SVGRectElement).getBoundingClientRect();
      const mx = 'clientX' in event ? event.clientX : r.left + r.width / 2;
      const my = 'clientY' in event ? event.clientY : r.top;
      tip.show(mx, my, tipRows([[d.title ?? d.label, fmtInt(d.value), d.color ?? t.accent]]));
    })
    .on('mouseleave blur', () => tip.hide());
}
