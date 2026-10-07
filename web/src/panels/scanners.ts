import { api } from '../lib/api';
import type { ScannerEntry } from '../lib/types';
import { el } from '../lib/utils/dom';
import { formatTimeAgo, formatTimeRemaining } from '../lib/utils/format';

/** Port Scanners: polled from /api/scanners; exposes the IP set for filtering. */
export class ScannersPanel {
  readonly ips = new Set<string>();
  private list: ScannerEntry[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly container: HTMLElement,
    private readonly countEl: Element | null,
    private readonly onChange?: () => void,
  ) {}

  start(intervalMs = 10_000): void {
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), intervalMs);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async refresh(): Promise<void> {
    try {
      const list = await api.scanners();
      this.list = Array.isArray(list) ? list : [];
      this.ips.clear();
      for (const s of this.list) this.ips.add(s.ip);
      this.render();
      this.onChange?.();
    } catch {
      /* keep previous */
    }
  }

  render(): void {
    const list = this.list;
    if (this.countEl) this.countEl.textContent = String(list.length);
    if (list.length === 0) {
      if (!this.container.querySelector('.empty')) this.container.replaceChildren(el('div', { class: 'empty', text: 'none detected' }));
      return;
    }
    const now = Date.now();
    const existing = new Map<string, HTMLElement>();
    for (const n of this.container.querySelectorAll<HTMLElement>('.scan-row[data-ip]')) existing.set(n.dataset.ip!, n);
    const frag = document.createDocumentFragment();
    for (const s of list) {
      const meta = `${s.port_count} ports — detected ${formatTimeAgo(s.detected_at, now)}`;
      const exp = `clears in ${formatTimeRemaining(s.expires_at, now)}`;
      let row = existing.get(s.ip);
      if (!row) {
        row = el('div', { class: 'scan-row', role: 'listitem' }, [
          el('div', { class: 'scan-ip', text: s.ip }),
          el('div', { class: 'scan-meta', text: meta }),
          el('div', { class: 'scan-expire', text: exp }),
        ]);
        row.dataset.ip = s.ip;
      } else {
        const m = row.querySelector('.scan-meta');
        const x = row.querySelector('.scan-expire');
        if (m && m.textContent !== meta) m.textContent = meta;
        if (x && x.textContent !== exp) x.textContent = exp;
      }
      frag.append(row);
    }
    this.container.replaceChildren(frag);
  }
}
