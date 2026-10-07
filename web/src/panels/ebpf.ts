import { api } from '../lib/api';
import type { EBPFStats } from '../lib/types';
import { el } from '../lib/utils/dom';
import { fmtNum, fmtUptime } from '../lib/utils/format';

export const MODE_LABELS: Readonly<Record<string, string>> = {
  'ebpf-only': 'eBPF only',
  hybrid: 'Hybrid',
  'go-only': 'Go only',
};

export function modeLabel(mode: string | undefined): string {
  if (!mode) return '—';
  return MODE_LABELS[mode] ?? mode;
}

/** Capture Mode panel: polled from /api/ebpf/stats every 30 s. */
export class EBPFPanel {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly container: HTMLElement) {}

  start(intervalMs = 30_000): void {
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), intervalMs);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async refresh(): Promise<void> {
    try {
      this.render(await api.ebpfStats());
    } catch {
      this.render(null);
    }
  }

  render(stats: EBPFStats | null): void {
    if (!stats) {
      this.container.replaceChildren(el('div', { class: 'empty', text: 'unavailable' }));
      return;
    }
    const on = Boolean(stats.enabled);
    const rows: Array<[string, string, string]> = [
      ['Mode', modeLabel(stats.mode), `mode-${stats.mode}`],
      ['Interface', on ? stats.interface || '—' : '—', ''],
      ['Passed', on ? fmtNum(stats.packets_passed) : '—', ''],
      ['Dropped', on ? fmtNum(stats.packets_dropped) : '—', ''],
      ['Bans', on ? String(stats.bans_active) : '—', ''],
      ['Uptime', on ? fmtUptime(stats.uptime_seconds) : '—', ''],
    ];
    const frag = document.createDocumentFragment();
    for (const [k, v, cls] of rows) {
      frag.append(
        el('div', { class: 'kv-row' }, [el('span', { class: 'kv-label', text: k }), el('span', { class: `kv-value ${cls}`.trim(), text: v })]),
      );
    }
    this.container.replaceChildren(frag);
  }
}
