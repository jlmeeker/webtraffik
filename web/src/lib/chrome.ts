import { api } from './api';
import { Signal } from './store';
import { bindThemeToggle, initTheme } from './theme';
import type { SelfInfo } from './types';
import { $maybe } from './utils/dom';
import { placeLabel } from './utils/format';

/** Shared page chrome: theme, nav current-page marker, self-info. */
export function initChrome(): Signal<SelfInfo | null> {
  initTheme();
  const toggle = $maybe<HTMLButtonElement>('[data-theme-toggle]');
  if (toggle) bindThemeToggle(toggle);

  const here = location.pathname.replace(/\/index\.html$/, '/');
  for (const a of document.querySelectorAll<HTMLAnchorElement>('.app-nav a')) {
    const target = new URL(a.getAttribute('href') ?? '/', location.origin).pathname.replace(/\/index\.html$/, '/');
    if (target === here) a.setAttribute('aria-current', 'page');
  }

  const self = new Signal<SelfInfo | null>(null);
  const ipEl = $maybe('#my-ip');
  const locEl = $maybe('#my-loc');
  api
    .self()
    .then((data) => {
      self.set(data);
      if (ipEl) ipEl.textContent = data.ip || '—';
      if (locEl) locEl.textContent = placeLabel(data.city, data.cc, '—');
    })
    .catch(() => {
      /* leave placeholders */
    });
  return self;
}
