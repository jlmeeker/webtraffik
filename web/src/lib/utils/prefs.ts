// Per-viewer preferences. Cookies are kept for backwards compatibility with
// the previous UI (wt_live_hours, audioEnabled, wt_hist_from/to); new keys use
// localStorage with a cookie fallback.

export function setCookie(name: string, value: string, days: number): void {
  try {
    const d = new Date();
    d.setTime(d.getTime() + days * 86400000);
    document.cookie = `${name}=${encodeURIComponent(value)};expires=${d.toUTCString()};path=/;SameSite=Lax`;
  } catch {
    /* ignore */
  }
}

export function getCookie(name: string): string {
  try {
    const prefix = name + '=';
    for (const part of document.cookie.split(';')) {
      const c = part.trim();
      if (c.startsWith(prefix)) return decodeURIComponent(c.slice(prefix.length));
    }
  } catch {
    /* ignore */
  }
  return '';
}

export function getPref(key: string): string {
  try {
    const v = localStorage.getItem(key);
    if (v !== null) return v;
  } catch {
    /* ignore */
  }
  return getCookie(key);
}

export function setPref(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* ignore */
  }
  setCookie(key, value, 365);
}
