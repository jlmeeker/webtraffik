import type { LiveState } from '../lib/store';
import { topPorts } from '../lib/store';
import type { ServiceRegistry } from '../lib/services';
import { el } from '../lib/utils/dom';
import type { Panel } from './scheduler';

interface Row {
  row: HTMLElement;
  countEl: HTMLElement;
  barEl: HTMLElement;
  nameEl: HTMLElement;
  swatch: HTMLElement;
}

/** Top Services: top-N ports with proportional bars (bar colour = port slot). */
export class ServicesPanel implements Panel {
  private rows = new Map<string, Row>();
  dirty = true;

  constructor(
    private readonly container: HTMLElement,
    private readonly state: LiveState,
    private readonly services: ServiceRegistry,
    private readonly colorForPort: (port: string) => string,
    private readonly topN = 12,
  ) {}

  render(): void {
    if (!this.dirty) return;
    this.dirty = false;
    const top = topPorts(this.state, this.topN);
    const keep = new Set(top.map(([p]) => p));
    for (const [p, r] of this.rows) {
      if (!keep.has(p)) {
        r.row.remove();
        this.rows.delete(p);
      }
    }
    const max = top[0]?.[1].count ?? 1;
    const empty = this.container.querySelector('.empty');
    if (top.length === 0) {
      if (!empty) this.container.append(el('div', { class: 'empty', text: 'waiting for events…' }));
      return;
    }
    empty?.remove();

    for (const [port, stat] of top) {
      const color = this.colorForPort(port);
      const name = this.services.label(port);
      let r = this.rows.get(port);
      if (!r) {
        const swatch = el('span', { class: 'swatch', 'aria-hidden': 'true' });
        const nameEl = el('span', { class: 'svc-name' });
        const countEl = el('span', { class: 'svc-count' });
        const barEl = el('div', { class: 'bar-fill' });
        const row = el('div', { class: 'svc-row', role: 'listitem' }, [
          el('div', { class: 'svc-line' }, [swatch, el('span', { class: 'svc-port', text: `:${port}` }), nameEl, countEl]),
          el('div', { class: 'bar-track', 'aria-hidden': 'true' }, [barEl]),
        ]);
        r = { row, countEl, barEl, nameEl, swatch };
        this.rows.set(port, r);
        this.container.append(row);
      }
      r.swatch.style.background = color;
      r.barEl.style.background = color;
      if (r.nameEl.textContent !== name) r.nameEl.textContent = name;
      const c = String(stat.count);
      if (r.countEl.textContent !== c) r.countEl.textContent = c;
      const pct = `${Math.max(3, Math.round((stat.count / max) * 100))}%`;
      if (r.barEl.style.width !== pct) r.barEl.style.width = pct;
      r.row.setAttribute('aria-label', `${name} port ${port}: ${c} connections`);
    }
    // Reorder DOM only when the order changed.
    const current = [...this.container.querySelectorAll<HTMLElement>('.svc-row')].map((n) => n.dataset.port ?? '');
    const wanted = top.map(([p]) => p);
    if (wanted.some((p, i) => current[i] !== p)) {
      for (const p of wanted) {
        const r = this.rows.get(p)!;
        r.row.dataset.port = p;
        this.container.append(r.row);
      }
    } else {
      for (const p of wanted) this.rows.get(p)!.row.dataset.port = p;
    }
  }

  reset(): void {
    for (const r of this.rows.values()) r.row.remove();
    this.rows.clear();
    this.dirty = true;
  }
}
