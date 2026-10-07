import { el } from '../lib/utils/dom';

export interface Tile {
  label: string;
  value: string;
  hint?: string | undefined;
  tone?: 'default' | 'critical' | 'good';
}

/** KPI row of stat tiles (the number is the chart). */
export function statTiles(container: HTMLElement, tiles: Tile[]): void {
  container.replaceChildren(
    ...tiles.map((t) =>
      el('div', { class: `tile tone-${t.tone ?? 'default'}`, role: 'group', 'aria-label': `${t.label} ${t.value}` }, [
        el('div', { class: 'tile-label', text: t.label }),
        el('div', { class: 'tile-value', text: t.value }),
        ...(t.hint ? [el('div', { class: 'tile-hint', text: t.hint })] : []),
      ]),
    ),
  );
}

/** Ratio meter (0..1) with a same-ramp track; value labelled in text. */
export function meter(container: HTMLElement, ratio: number, opts: { label: string; valueText: string; tone?: 'default' | 'critical' }): void {
  const pct = Math.max(0, Math.min(1, Number.isFinite(ratio) ? ratio : 0));
  const fill = el('div', { class: `meter-fill tone-${opts.tone ?? 'default'}` });
  fill.style.width = `${(pct * 100).toFixed(2)}%`;
  container.replaceChildren(
    el('div', { class: 'meter', role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': '1', 'aria-valuenow': pct.toFixed(4), 'aria-label': opts.label }, [
      el('div', { class: 'meter-head' }, [el('span', { class: 'meter-label', text: opts.label }), el('span', { class: 'meter-value', text: opts.valueText })]),
      el('div', { class: 'meter-track' }, [fill]),
    ]),
  );
}
