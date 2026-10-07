import { scheduleIdle } from '../lib/utils/dom';

export interface Panel {
  /** Render if dirty; must be cheap when nothing changed. */
  render(): void;
}

/**
 * Renders registered panels every `intervalMs` inside an idle callback so
 * panel DOM work never competes with arc animation frames.
 */
export class PanelScheduler {
  private panels = new Set<Panel>();
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly intervalMs = 2000) {}

  add(panel: Panel): void {
    this.panels.add(panel);
  }

  start(): void {
    if (this.timer) return;
    const loop = () => {
      scheduleIdle(() => {
        this.renderAll();
        this.timer = setTimeout(loop, this.intervalMs);
      });
    };
    this.timer = setTimeout(loop, this.intervalMs);
  }

  stop(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  renderAll(): void {
    for (const p of this.panels) p.render();
  }
}
