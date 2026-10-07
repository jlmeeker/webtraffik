import { badgeEls, badgeSummary } from './lib/badges';
import type { ServiceRegistry } from './lib/services';
import type { ConnectionEvent } from './lib/types';
import { el, rafBatcher } from './lib/utils/dom';
import { timeHMS } from './lib/utils/format';
import { hasGeo } from './lib/utils/geo';

export const LOG_MAX_ROWS = 200;

/** Build one log row (shared with the Recent page). */
export function buildLogRow(
  ev: ConnectionEvent,
  services: ServiceRegistry,
  opts: { withDate?: string; onActivate?: (ev: ConnectionEvent) => void } = {},
): HTMLElement {
  const portNum = ev.dst_port && ev.dst_port !== 'unknown' ? ev.dst_port : '';
  const svc = portNum ? services.name(portNum) : '';
  const proto = ev.protocol ? ev.protocol.toUpperCase() : '';
  const canTrace = Boolean(opts.onActivate) && hasGeo(ev.src_lat, ev.src_lon) && Boolean(ev.src_ip);

  const row = el('div', { class: `log-entry${canTrace ? ' clickable' : ''}` });
  row.append(el('span', { class: 'log-time', text: `${opts.withDate ? opts.withDate + ' ' : ''}${timeHMS(ev.time)}` }));
  const src = el('span', { class: 'log-src' });
  src.append(el('span', { class: 'ip', text: ev.src_ip }));
  const place = [ev.src_city, ev.src_cc].filter(Boolean).join(', ');
  if (place) src.append(` · ${place}`);
  row.append(src);
  if (portNum) {
    row.append(el('span', { class: 'log-arrow', text: '→', 'aria-hidden': 'true' }));
    row.append(el('span', { class: 'log-port', text: `:${portNum}${svc ? ' ' + svc : ''}` }));
  }
  const badges = badgeEls(ev);
  if (badges.length > 0) row.append(el('span', { class: 'log-badges', title: badgeSummary(ev) }, badges));
  if (proto) row.append(el('span', { class: 'log-proto', text: proto }));

  if (canTrace) {
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');
    row.setAttribute('aria-label', `Trace route to ${ev.src_ip}`);
    const act = () => {
      opts.onActivate?.(ev);
      row.classList.add('arc-flash');
      setTimeout(() => row.classList.remove('arc-flash'), 400);
    };
    row.addEventListener('click', act);
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        act();
      }
    });
  }
  return row;
}

/** Live log: newest first, rAF-batched DOM writes, capped at 200 rows. */
export class LogPanel {
  private buffer: ConnectionEvent[] = [];
  private readonly flushRaf: () => void;

  constructor(
    private readonly container: HTMLElement,
    private readonly services: ServiceRegistry,
    private readonly onActivate: (ev: ConnectionEvent) => void,
  ) {
    this.flushRaf = rafBatcher(() => this.flush());
  }

  add(ev: ConnectionEvent): void {
    this.buffer.push(ev);
    if (this.buffer.length > LOG_MAX_ROWS) this.buffer.splice(0, this.buffer.length - LOG_MAX_ROWS);
    this.flushRaf();
  }

  flush(): void {
    if (this.buffer.length === 0) return;
    const entries = this.buffer.splice(0);
    const frag = document.createDocumentFragment();
    for (const ev of entries) frag.prepend(buildLogRow(ev, this.services, { onActivate: this.onActivate }));
    this.container.prepend(frag);
    while (this.container.children.length > LOG_MAX_ROWS) this.container.lastChild?.remove();
  }

  reset(): void {
    this.buffer.length = 0;
    this.container.replaceChildren();
  }
}
