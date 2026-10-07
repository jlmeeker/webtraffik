// Shareable view state in the URL hash: "#q=port%3A22&preset=24". Pure helpers
// (the pages call them with location.hash / location.search).

export type UrlState = Record<string, string>;

function parse(raw: string): UrlState {
  const out: UrlState = {};
  const s = raw.replace(/^[#?]/, '');
  if (!s) return out;
  for (const [k, v] of new URLSearchParams(s)) if (v !== '') out[k] = v;
  return out;
}

/** Hash wins over the query string; both are accepted for shareable links. */
export function readUrlState(hash: string, search = ''): UrlState {
  return { ...parse(search), ...parse(hash) };
}

export function encodeUrlState(state: Record<string, string | undefined | null>): string {
  const p = new URLSearchParams();
  for (const k of Object.keys(state).sort()) {
    const v = state[k];
    if (v !== undefined && v !== null && v !== '') p.set(k, v);
  }
  const s = p.toString();
  return s ? `#${s}` : '';
}

/** Write state with replaceState so Back does not fill with every keystroke. */
export function writeUrlState(state: Record<string, string | undefined | null>): void {
  try {
    history.replaceState(null, '', `${location.pathname}${encodeUrlState(state)}`);
  } catch {
    /* sandboxed / unsupported */
  }
}
