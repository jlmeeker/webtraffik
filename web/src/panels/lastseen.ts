import type { LastSeenEntry, LiveState } from '../lib/store';
import { el } from '../lib/utils/dom';
import type { Panel } from './scheduler';

/** Last Seen: most recent distinct source IPs; click/Enter → traceroute. */
export class LastSeenPanel implements Panel {
  dirty = true;

  constructor(
    private readonly container: HTMLElement,
    private readonly state: LiveState,
    private readonly onSelect: (entry: LastSeenEntry) => void,
  ) {}

  render(): void {
    if (!this.dirty) return;
    this.dirty = false;
    const list = this.state.lastSeen;
    if (list.length === 0) {
      if (!this.container.querySelector('.empty')) {
        this.container.replaceChildren(el('div', { class: 'empty', text: 'waiting…' }));
      }
      return;
    }
    const existing = new Map<string, HTMLElement>();
    for (const n of this.container.querySelectorAll<HTMLElement>('.ls-row[data-ip]')) existing.set(n.dataset.ip!, n);
    const frag = document.createDocumentFragment();
    for (const e of list) {
      let row = existing.get(e.ip);
      if (!row) {
        row = el('button', { class: 'ls-row', type: 'button', title: `Trace route to ${e.ip}` }, [
          el('span', { class: 'ls-ip', text: e.ip }),
          el('span', { class: 'ls-cc', text: e.cc }),
        ]);
        row.dataset.ip = e.ip;
        const entry = e;
        row.addEventListener('click', () => this.onSelect(entry));
      } else {
        const cc = row.querySelector('.ls-cc');
        if (cc && cc.textContent !== e.cc) cc.textContent = e.cc;
      }
      frag.append(row);
    }
    this.container.replaceChildren(frag);
  }

  reset(): void {
    this.container.replaceChildren();
    this.dirty = true;
  }
}
