import { getPref, setPref } from './utils/prefs';

export type Theme = 'light' | 'dark';
const KEY = 'wt_theme';

function systemTheme(): Theme {
  try {
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

/** The theme in effect: explicit choice, else OS preference. */
export function currentTheme(): Theme {
  const saved = getPref(KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return systemTheme();
}

const listeners = new Set<(t: Theme) => void>();

export function onThemeChange(fn: (t: Theme) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function apply(t: Theme | null): void {
  const root = document.documentElement;
  if (t) root.setAttribute('data-theme', t);
  else root.removeAttribute('data-theme');
  const effective = currentTheme();
  for (const fn of listeners) fn(effective);
}

/** Apply the stored choice before first paint (call at the top of each page). */
export function initTheme(): void {
  const saved = getPref(KEY);
  apply(saved === 'light' || saved === 'dark' ? saved : null);
  try {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
      if (!getPref(KEY)) apply(null);
    });
  } catch {
    /* ignore */
  }
}

export function setTheme(t: Theme): void {
  setPref(KEY, t);
  apply(t);
}

export function toggleTheme(): Theme {
  const next: Theme = currentTheme() === 'dark' ? 'light' : 'dark';
  setTheme(next);
  return next;
}

/** Wire a <button> as a theme toggle with an accessible label. */
export function bindThemeToggle(btn: HTMLButtonElement): void {
  const render = () => {
    const t = currentTheme();
    btn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    btn.setAttribute('aria-pressed', t === 'dark' ? 'true' : 'false');
    btn.dataset.theme = t;
  };
  btn.addEventListener('click', () => {
    toggleTheme();
    render();
  });
  onThemeChange(render);
  render();
}

/** Read a CSS custom property from :root (trimmed). */
export function cssVar(name: string, fallback = ''): string {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  } catch {
    return fallback;
  }
}
