import { cssVar } from './theme';

/** Number of categorical series slots (validated colour-blind-safe order). */
export const SERIES_SLOTS = 8;

/**
 * Categorical palette read from CSS tokens so it follows the theme.
 * Slot order is the CVD-safety mechanism — never shuffle or cycle past 8.
 */
export function seriesColors(): string[] {
  const out: string[] = [];
  for (let i = 1; i <= SERIES_SLOTS; i++) out.push(cssVar(`--series-${i}`, FALLBACK_SERIES[i - 1] ?? '#888'));
  return out;
}

/** Colour used for ports beyond the 8th slot ("Other"). */
export function otherColor(): string {
  return cssVar('--series-other', '#7a8699');
}

export const FALLBACK_SERIES: readonly string[] = [
  '#3987e5',
  '#d95926',
  '#199e70',
  '#c98500',
  '#d55181',
  '#008300',
  '#9085e9',
  '#e66767',
];

/** Fixed-order slot assigner: the n-th distinct key gets slot n; past 8 → other. */
export class SlotAssigner {
  private slots = new Map<string, number>();

  slot(key: string): number {
    let s = this.slots.get(key);
    if (s === undefined) {
      s = this.slots.size;
      this.slots.set(key, s);
    }
    return s;
  }

  has(key: string): boolean {
    return this.slots.has(key);
  }

  reset(): void {
    this.slots.clear();
  }

  color(key: string, colors: readonly string[] = seriesColors(), other: string = otherColor()): string {
    const s = this.slot(key);
    return s < SERIES_SLOTS ? (colors[s] ?? other) : other;
  }
}
