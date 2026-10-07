import * as d3 from 'd3';
import { cssVar } from '../lib/theme';
import { el } from '../lib/utils/dom';

export interface ChartTokens {
  text: string;
  text2: string;
  muted: string;
  grid: string;
  axis: string;
  surface: string;
  accent: string;
  series: string[];
  other: string;
  critical: string;
  good: string;
  font: string;
}

export function chartTokens(): ChartTokens {
  const series: string[] = [];
  for (let i = 1; i <= 8; i++) series.push(cssVar(`--series-${i}`, '#888'));
  return {
    text: cssVar('--text', '#eee'),
    text2: cssVar('--text-2', '#ccc'),
    muted: cssVar('--muted', '#888'),
    grid: cssVar('--grid', '#333'),
    axis: cssVar('--axis', '#555'),
    surface: cssVar('--surface-1', '#111'),
    accent: cssVar('--series-1', '#3987e5'),
    series,
    other: cssVar('--series-other', '#7a8699'),
    critical: cssVar('--critical', '#e66767'),
    good: cssVar('--good', '#0ca30c'),
    font: cssVar('--font', 'monospace'),
  };
}

export const MARGIN = { top: 10, right: 16, bottom: 28, left: 44 };

export type SVGSel = d3.Selection<SVGSVGElement, unknown, null, undefined>;
export type GSel = d3.Selection<SVGGElement, unknown, null, undefined>;

/** Clear a container and append a responsive SVG of the container's size. */
export function makeSvg(container: HTMLElement, height: number, label: string): { svg: SVGSel; w: number; h: number } {
  container.replaceChildren();
  const w = Math.max(200, container.clientWidth || 600);
  const svg = d3
    .select(container)
    .append('svg')
    .attr('width', w)
    .attr('height', height)
    .attr('viewBox', `0 0 ${w} ${height}`)
    .attr('role', 'img')
    .attr('aria-label', label) as unknown as SVGSel;
  return { svg, w, h: height };
}

let tipEl: HTMLElement | null = null;

/** Single shared HTML tooltip for all charts. */
export function chartTip(): { show: (x: number, y: number, html: Node | string) => void; hide: () => void } {
  if (!tipEl) {
    tipEl = el('div', { class: 'chart-tip', role: 'tooltip' });
    tipEl.style.display = 'none';
    document.body.append(tipEl);
  }
  const t = tipEl;
  return {
    show(x, y, content) {
      t.replaceChildren(content);
      t.style.display = 'block';
      const w = t.offsetWidth;
      const h = t.offsetHeight;
      t.style.left = `${Math.min(x + 12, window.innerWidth - w - 8)}px`;
      t.style.top = `${Math.max(4, Math.min(y - h - 10, window.innerHeight - h - 8))}px`;
    },
    hide() {
      t.style.display = 'none';
    },
  };
}

export function tipRows(rows: Array<[string, string, string?]>): Node {
  const frag = document.createDocumentFragment();
  for (const [k, v, color] of rows) {
    const r = el('div', { class: 'chart-tip-row' });
    if (color) r.append(el('span', { class: 'swatch', style: `background:${color}` }));
    r.append(el('span', { class: 'k', text: k }), el('span', { class: 'v', text: v }));
    frag.append(r);
  }
  return frag;
}

export function fmtInt(n: number): string {
  return Math.round(n).toLocaleString('en-US');
}

/** Recessive y grid + axis text in muted ink. */
export function styleAxis(g: GSel, t: ChartTokens): void {
  g.selectAll('text').attr('fill', t.muted).attr('font-family', t.font).attr('font-size', 10);
  g.selectAll('line').attr('stroke', t.axis);
  g.select('.domain').attr('stroke', t.axis);
}

export function gridLines(g: GSel, scale: d3.ScaleLinear<number, number>, width: number, t: ChartTokens, ticks = 4): void {
  g.selectAll('line')
    .data(scale.ticks(ticks))
    .join('line')
    .attr('x1', 0)
    .attr('x2', width)
    .attr('y1', (d) => scale(d))
    .attr('y2', (d) => scale(d))
    .attr('stroke', t.grid)
    .attr('stroke-width', 1);
}

/** Legend row: swatch + label per series (always present for >= 2 series). */
export function legend(container: HTMLElement, items: Array<{ label: string; color: string }>): void {
  if (items.length < 2) return;
  const row = el('div', { class: 'chart-legend', role: 'list' });
  for (const it of items) {
    row.append(
      el('span', { class: 'legend-item', role: 'listitem' }, [el('span', { class: 'swatch', style: `background:${it.color}` }), it.label]),
    );
  }
  container.append(row);
}
