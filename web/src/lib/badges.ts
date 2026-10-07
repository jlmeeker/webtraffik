// Kind / class / scanner badges. Meaning is carried by a glyph AND a text
// label (never colour alone), so the set stays readable for colour-blind users.

import type { ConnectionEvent } from './types';

export interface BadgeSpec {
  group: 'kind' | 'class' | 'scanner';
  value: string;
  glyph: string;
  text: string;
  title: string;
}

type Badged = Pick<ConnectionEvent, 'kind' | 'class' | 'scanner'>;

const KIND: Record<string, { glyph: string; text: string; title: string }> = {
  session: { glyph: '◆', text: 'session', title: 'A honeypot conversation was captured' },
  probe: { glyph: '◇', text: 'probe', title: 'Connection with no payload' },
  observed: { glyph: '○', text: 'XDP', title: 'Seen by XDP only (no listener on this port)' },
};

const CLASS: Record<string, { glyph: string; title: string }> = {
  exploit: { glyph: '▲', title: 'Exploit attempt' },
  bruteforce: { glyph: '■', title: 'Credential brute force' },
  scan: { glyph: '●', title: 'Port / service scan' },
  research: { glyph: '◐', title: 'Research or survey traffic' },
  unknown: { glyph: '?', title: 'Unclassified' },
};

/** Badges to show for an event, in a fixed order. Unknown values still render. */
export function eventBadges(ev: Badged): BadgeSpec[] {
  const out: BadgeSpec[] = [];
  if (ev.scanner) out.push({ group: 'scanner', value: ev.scanner, glyph: '◎', text: ev.scanner, title: `Known research scanner: ${ev.scanner}` });
  if (ev.class) {
    const c = CLASS[ev.class];
    out.push({ group: 'class', value: ev.class, glyph: c?.glyph ?? '·', text: ev.class, title: c?.title ?? `Class: ${ev.class}` });
  }
  if (ev.kind) {
    const k = KIND[ev.kind];
    out.push({ group: 'kind', value: ev.kind, glyph: k?.glyph ?? '·', text: k?.text ?? ev.kind, title: k?.title ?? `Kind: ${ev.kind}` });
  }
  return out;
}

/** Plain-text summary, e.g. for aria-labels. */
export function badgeSummary(ev: Badged): string {
  return eventBadges(ev)
    .map((b) => `${b.group}: ${b.text}`)
    .join(', ');
}

export function badgeEl(b: BadgeSpec): HTMLElement {
  const span = document.createElement('span');
  span.className = `badge badge-${b.group}`;
  span.dataset.value = b.value;
  span.title = b.title;
  const g = document.createElement('span');
  g.className = 'badge-glyph';
  g.setAttribute('aria-hidden', 'true');
  g.textContent = b.glyph;
  span.append(g, document.createTextNode(b.text));
  return span;
}

export function badgeEls(ev: Badged): HTMLElement[] {
  return eventBadges(ev).map(badgeEl);
}
