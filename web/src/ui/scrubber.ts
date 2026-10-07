import { densityBins, eventSpan, isFullWindow, SCRUB_STEPS, stepsToWindow, type TimeSpan } from '../history/scrub';
import type { ConnectionEvent } from '../lib/types';
import { $ } from '../lib/utils/dom';
import { dateTimeFull } from '../lib/utils/format';

const BINS = 60;
const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Two-handle time scrubber over the loaded events. A density strip shows when
 * the traffic happened; the handles narrow the visible window (table and
 * per-IP chart). Both handles are native range inputs, so arrow keys work.
 */
export class Scrubber {
  private readonly lo: HTMLInputElement;
  private readonly hi: HTMLInputElement;
  private readonly label: HTMLElement;
  private readonly strip: HTMLElement;
  private readonly reset: HTMLButtonElement;
  private span: TimeSpan | null = null;
  private events: readonly ConnectionEvent[] = [];

  constructor(
    root: HTMLElement,
    private readonly onChange: (win: TimeSpan | null) => void,
  ) {
    this.lo = $<HTMLInputElement>('#scrub-lo', root);
    this.hi = $<HTMLInputElement>('#scrub-hi', root);
    this.label = $('#scrub-label', root);
    this.strip = $('#scrub-strip', root);
    this.reset = $<HTMLButtonElement>('#scrub-reset', root);
    for (const r of [this.lo, this.hi]) {
      r.min = '0';
      r.max = String(SCRUB_STEPS);
      r.step = '1';
      r.addEventListener('input', () => this.changed(r));
    }
    this.reset.addEventListener('click', () => {
      this.lo.value = '0';
      this.hi.value = String(SCRUB_STEPS);
      this.changed(null);
    });
  }

  /** Load a new event set; the window resets to the full span. */
  setEvents(events: readonly ConnectionEvent[]): void {
    this.events = events;
    this.span = eventSpan(events);
    this.lo.value = '0';
    this.hi.value = String(SCRUB_STEPS);
    const usable = this.span !== null && this.span.max > this.span.min && events.length > 1;
    this.lo.disabled = this.hi.disabled = !usable;
    this.drawStrip();
    this.updateLabel();
  }

  get window(): TimeSpan | null {
    if (!this.span) return null;
    const a = Number(this.lo.value);
    const b = Number(this.hi.value);
    return isFullWindow(a, b) ? null : stepsToWindow(this.span, a, b);
  }

  private changed(moved: HTMLInputElement | null): void {
    // Handles never cross: the one being dragged stops at the other.
    if (Number(this.lo.value) > Number(this.hi.value)) {
      if (moved === this.hi) this.hi.value = this.lo.value;
      else this.lo.value = this.hi.value;
    }
    this.updateLabel();
    this.onChange(this.window);
  }

  private updateLabel(): void {
    const s = this.span;
    if (!s) {
      this.label.textContent = 'No dated events to scrub.';
      this.reset.disabled = true;
      return;
    }
    const w = this.window ?? s;
    const fmt = (t: number) => dateTimeFull(new Date(t).toISOString());
    this.label.textContent = `${fmt(w.min)} → ${fmt(w.max)}`;
    const text = `From ${fmt(w.min)} to ${fmt(w.max)}`;
    this.lo.setAttribute('aria-valuetext', `Window start: ${fmt(w.min)}`);
    this.hi.setAttribute('aria-valuetext', `Window end: ${fmt(w.max)}`);
    this.label.setAttribute('aria-label', text);
    this.reset.disabled = this.window === null;
    const a = Number(this.lo.value);
    const b = Number(this.hi.value);
    // Shade the selected part of the strip (CSS custom properties, no inline style attr).
    this.strip.style.setProperty('--lo', `${(a / SCRUB_STEPS) * 100}%`);
    this.strip.style.setProperty('--hi', `${(b / SCRUB_STEPS) * 100}%`);
  }

  private drawStrip(): void {
    this.strip.querySelector('svg')?.remove();
    if (!this.span) return;
    const bins = densityBins(this.events, this.span, BINS);
    const max = Math.max(1, ...bins);
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${BINS} 20`);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('aria-hidden', 'true');
    bins.forEach((n, i) => {
      if (n === 0) return;
      const h = Math.max(1, (n / max) * 20);
      const r = document.createElementNS(SVG_NS, 'rect');
      r.setAttribute('x', String(i + 0.08));
      r.setAttribute('y', String(20 - h));
      r.setAttribute('width', '0.84');
      r.setAttribute('height', String(h));
      svg.append(r);
    });
    this.strip.prepend(svg);
  }
}
