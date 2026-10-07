import type * as d3 from 'd3';
import type { ConnectionEvent } from '../lib/types';
import { placeLabel } from '../lib/utils/format';
import { $ } from '../lib/utils/dom';

export interface TooltipActions {
  isBanned: (ip: string, port: string) => boolean;
  onToggleBan: (ev: ConnectionEvent) => void;
  onTrace: (ev: ConnectionEvent) => void;
}

/** Per-dot hover card: location, IP, Trace route + Ban/Unban actions. */
export class DotTooltip {
  private readonly root: HTMLElement;
  private readonly labelEl: HTMLElement;
  private readonly ipEl: HTMLElement;
  private readonly traceBtn: HTMLButtonElement;
  private readonly banBtn: HTMLButtonElement;
  private hideTimer: ReturnType<typeof setTimeout> | null = null;
  private current: ConnectionEvent | null = null;

  constructor(
    rootSelector: string,
    private readonly actions: TooltipActions,
  ) {
    this.root = $(rootSelector);
    this.labelEl = $('.tip-label', this.root);
    this.ipEl = $('.tip-ip', this.root);
    this.traceBtn = $<HTMLButtonElement>('.tip-trace', this.root);
    this.banBtn = $<HTMLButtonElement>('.tip-ban', this.root);

    this.root.addEventListener('mouseenter', () => this.cancelHide());
    this.root.addEventListener('mouseleave', () => this.scheduleHide());
    this.root.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') this.hide();
    });
    this.banBtn.addEventListener('click', () => {
      const ev = this.current;
      this.hide();
      if (ev) this.actions.onToggleBan(ev);
    });
    this.traceBtn.addEventListener('click', () => {
      const ev = this.current;
      this.hide();
      if (ev && ev.src_ip) this.actions.onTrace(ev);
    });
  }

  static label(ev: ConnectionEvent, hitCount = 1): string {
    const loc = placeLabel(ev.src_city, ev.src_cc, ev.src_ip);
    return hitCount > 1 ? `${loc} ×${hitCount}` : loc;
  }

  show(x: number, y: number, ev: ConnectionEvent, hitCount = 1): void {
    this.cancelHide();
    this.current = ev;
    this.labelEl.textContent = DotTooltip.label(ev, hitCount);
    this.ipEl.textContent = ev.src_ip || '';
    this.ipEl.style.display = ev.src_ip ? 'block' : 'none';
    this.traceBtn.style.display = ev.src_ip ? 'block' : 'none';
    const banned = this.actions.isBanned(ev.src_ip, ev.dst_port);
    this.banBtn.textContent = banned ? `Unban :${ev.dst_port}` : `Ban :${ev.dst_port}`;
    this.banBtn.classList.toggle('tip-unban', banned);
    this.root.style.display = 'block';
    this.position(x, y);
  }

  move(x: number, y: number): void {
    this.position(x, y);
  }

  private position(cx: number, cy: number): void {
    const w = this.root.offsetWidth || 150;
    const h = this.root.offsetHeight || 80;
    const x = Math.max(4, Math.min(cx + 14, window.innerWidth - w - 6));
    const y = Math.max(4, Math.min(cy - 10, window.innerHeight - h - 6));
    this.root.style.left = `${x}px`;
    this.root.style.top = `${y}px`;
  }

  scheduleHide(): void {
    this.cancelHide();
    this.hideTimer = setTimeout(() => this.hide(), 140);
  }

  private cancelHide(): void {
    if (this.hideTimer) clearTimeout(this.hideTimer);
    this.hideTimer = null;
  }

  hide(): void {
    this.cancelHide();
    this.root.style.display = 'none';
    this.current = null;
  }

  /** Wire hover/dblclick on a dot selection. `get` returns latest ev + count. */
  attach(
    sel: d3.Selection<SVGCircleElement, unknown, null, undefined>,
    get: () => { ev: ConnectionEvent; hitCount: number },
  ): void {
    sel
      .on('mouseover', (event: MouseEvent) => {
        const { ev, hitCount } = get();
        this.show(event.clientX, event.clientY, ev, hitCount);
      })
      .on('mousemove', (event: MouseEvent) => this.move(event.clientX, event.clientY))
      .on('mouseout', () => this.scheduleHide())
      .on('dblclick', (event: MouseEvent) => {
        event.stopPropagation();
        const { ev } = get();
        if (ev.src_ip) this.actions.onTrace(ev);
      });
  }
}
