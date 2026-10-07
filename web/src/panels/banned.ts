import { api } from '../lib/api';
import { banKey } from '../lib/store';
import type { BanEntry } from '../lib/types';
import { el } from '../lib/utils/dom';
import { formatTimeRemaining } from '../lib/utils/format';

/** Banned IPs: polled from /api/banned; owns the ban set used by dots/tooltip. */
export class BannedPanel {
  readonly set = new Set<string>();
  private list: BanEntry[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly container: HTMLElement,
    private readonly countEl: Element | null,
    private readonly onChange?: () => void,
  ) {}

  isBanned(ip: string, port: string): boolean {
    return this.set.has(banKey(ip, port));
  }

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
      const bans = await api.banned();
      this.list = Array.isArray(bans) ? bans : [];
      this.list.sort((a, b) => new Date(b.banned_at).getTime() - new Date(a.banned_at).getTime());
      this.set.clear();
      for (const b of this.list) this.set.add(banKey(b.ip, b.port));
      this.render();
      this.onChange?.();
    } catch {
      /* keep previous */
    }
  }

  /** Toggle ban state for ip:port, then refresh. */
  async toggle(ip: string, port: string): Promise<void> {
    try {
      if (this.isBanned(ip, port)) await api.unban(ip, port);
      else await api.ban(ip, port);
    } catch {
      /* ignore */
    }
    await this.refresh();
  }

  render(): void {
    if (this.countEl) this.countEl.textContent = String(this.list.length);
    if (this.list.length === 0) {
      this.container.replaceChildren(el('div', { class: 'empty', text: 'no active bans' }));
      return;
    }
    const now = Date.now();
    const frag = document.createDocumentFragment();
    for (const b of this.list.slice(0, 40)) {
      const unban = el('button', { class: 'ban-unban', type: 'button', title: `Unban ${b.ip} on port ${b.port}`, 'aria-label': `Unban ${b.ip} port ${b.port}` });
      unban.textContent = '✕';
      unban.addEventListener('click', () => void this.toggle(b.ip, b.port));
      const row = el('div', { class: 'ban-row', role: 'listitem' }, [
        el('div', { class: 'ban-main' }, [
          el('span', { class: 'ban-ip', text: b.ip }),
          el('span', { class: 'ban-port', text: `:${b.port}${b.service ? ' ' + b.service : ''}` }),
        ]),
        el('div', { class: 'ban-meta', text: `${b.cc ? b.cc + ' · ' : ''}expires in ${formatTimeRemaining(b.expires_at, now)}` }),
        unban,
      ]);
      frag.append(row);
    }
    this.container.replaceChildren(frag);
  }
}
