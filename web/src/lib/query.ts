// Search-query grammar shared by the History and Recent pages. Pure: no DOM.
//
//   query  := term (whitespace term)*
//   term   := ["-"] key ":" value      key in QUERY_KEYS (case-insensitive)
//           | word                     free text (detail, ASN org, city, meta)
//   value  := bare | "double quoted"   backslash escapes \" and \\ inside quotes
//
// A leading "-" negates only a known key:value term; "-v" stays a literal
// word. A quoted token ("port:22") is always free text, never a key.

export const QUERY_KEYS = ['port', 'ip', 'cc', 'asn', 'tag', 'kind', 'class', 'scanner', 'proto', 'ja3', 'ja4', 'sni', 'user', 'since', 'until'] as const;
export type QueryKey = (typeof QUERY_KEYS)[number];

export const KEY_HINTS: Record<QueryKey, string> = {
  port: 'destination port, e.g. port:22',
  ip: 'source IP or prefix, e.g. ip:203.0.113',
  cc: 'source country code, e.g. cc:CN',
  asn: 'AS number, e.g. asn:14061',
  tag: 'event tag, e.g. tag:scanner:zgrab',
  kind: 'session, probe or observed',
  class: 'exploit, bruteforce, scan, research, unknown',
  scanner: 'known research scanner, e.g. scanner:Shodan',
  proto: 'tcp, udp or icmp',
  ja3: 'TLS JA3 fingerprint',
  ja4: 'TLS JA4 fingerprint',
  sni: 'TLS server name',
  user: 'login username',
  since: 'relative start, e.g. since:24h or since:7d',
  until: 'relative end, e.g. until:1h',
};

export const KIND_VALUES = ['session', 'probe', 'observed'] as const;
export const CLASS_VALUES = ['exploit', 'bruteforce', 'scan', 'research', 'unknown'] as const;
export const PROTO_VALUES = ['tcp', 'udp', 'icmp'] as const;
export const DURATION_VALUES = ['1h', '6h', '24h', '7d', '30d'] as const;

export const KEY_VALUES: Partial<Record<QueryKey, readonly string[]>> = {
  kind: KIND_VALUES,
  class: CLASS_VALUES,
  proto: PROTO_VALUES,
  since: DURATION_VALUES,
  until: DURATION_VALUES,
};

export interface Term {
  neg: boolean;
  /** null = free-text word. */
  key: QueryKey | null;
  value: string;
}

export interface ParseResult {
  terms: Term[];
  /** Syntax problem found client-side (unterminated quote, empty value). */
  error: string | null;
}

const KEY_SET: ReadonlySet<string> = new Set(QUERY_KEYS);

export function isQueryKey(s: string): s is QueryKey {
  return KEY_SET.has(s);
}

interface RawToken {
  text: string; // as typed, quotes retained
  unterminated: boolean;
}

function splitRaw(q: string): RawToken[] {
  const out: RawToken[] = [];
  let cur = '';
  let inQ = false;
  let started = false;
  for (let i = 0; i < q.length; i++) {
    const c = q[i]!;
    if (inQ) {
      cur += c;
      if (c === '\\' && i + 1 < q.length) cur += q[++i]!;
      else if (c === '"') inQ = false;
      continue;
    }
    if (c === '"') {
      inQ = true;
      started = true;
      cur += c;
    } else if (/\s/.test(c)) {
      if (started) out.push({ text: cur, unterminated: false });
      cur = '';
      started = false;
    } else {
      started = true;
      cur += c;
    }
  }
  if (started) out.push({ text: cur, unterminated: inQ });
  return out;
}

function unquote(raw: string): string {
  let out = '';
  let inQ = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]!;
    if (inQ) {
      if (c === '\\' && i + 1 < raw.length) out += raw[++i]!;
      else if (c === '"') inQ = false;
      else out += c;
    } else if (c === '"') inQ = true;
    else out += c;
  }
  return out;
}

const KEY_PREFIX = /^(-?)([A-Za-z0-9]+):/;

export function parseQuery(q: string): ParseResult {
  const terms: Term[] = [];
  let error: string | null = null;
  for (const tok of splitRaw(q)) {
    if (tok.unterminated && !error) error = 'Unterminated quote';
    const m = KEY_PREFIX.exec(tok.text);
    const key = m ? m[2]!.toLowerCase() : '';
    if (m && isQueryKey(key)) {
      const raw = tok.text.slice(m[0].length);
      const value = unquote(raw);
      if (raw === '' && !error) error = `Missing value after "${key}:"`;
      terms.push({ neg: m[1] === '-', key, value });
    } else {
      terms.push({ neg: false, key: null, value: unquote(tok.text) });
    }
  }
  return { terms, error };
}

/** Quote a value when whitespace, quotes or backslashes require it. */
export function quoteValue(v: string, force = false): string {
  if (force || v === '' || /[\s"\\]/.test(v)) return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  return v;
}

export function serializeTerm(t: Term): string {
  if (t.key) return `${t.neg ? '-' : ''}${t.key}:${quoteValue(t.value)}`;
  // A free word that would re-parse as a key:value term must stay quoted.
  const m = KEY_PREFIX.exec(t.value);
  const clash = m !== null && isQueryKey(m[2]!.toLowerCase());
  return quoteValue(t.value, clash);
}

export function serializeQuery(terms: readonly Term[]): string {
  return terms.map(serializeTerm).join(' ');
}

/** Client-side syntax check; the server remains the authority. */
export function validateQuery(q: string): string | null {
  return parseQuery(q).error;
}

const sameTerm = (a: Term, b: Term): boolean => a.key === b.key && a.neg === b.neg && a.value.toLowerCase() === b.value.toLowerCase();

export function hasTerm(q: string, t: Term): boolean {
  return parseQuery(q).terms.some((x) => sameTerm(x, t));
}

/** Append a term unless already present. Returns the new query string. */
export function addTerm(q: string, t: Term): string {
  const { terms } = parseQuery(q);
  if (terms.some((x) => sameTerm(x, t))) return serializeQuery(terms);
  return serializeQuery([...terms, t]);
}

export function removeTerm(q: string, t: Term): string {
  return serializeQuery(parseQuery(q).terms.filter((x) => !sameTerm(x, t)));
}

export function toggleTerm(q: string, t: Term): string {
  return hasTerm(q, t) ? removeTerm(q, t) : addTerm(q, t);
}

export const kv = (key: QueryKey, value: string, neg = false): Term => ({ neg, key, value });
export const word = (value: string): Term => ({ neg: false, key: null, value });

// ── Autocomplete ────────────────────────────────────────────────────────────

export interface Suggestion {
  label: string;
  /** Text that replaces the token under the caret. */
  insert: string;
  hint: string;
}

export interface SuggestResult {
  start: number;
  end: number;
  items: Suggestion[];
}

/** Suggestions for the whitespace-delimited token at `caret` (outside quotes). */
export function suggestAt(input: string, caret: number): SuggestResult {
  const empty: SuggestResult = { start: caret, end: caret, items: [] };
  let start = caret;
  while (start > 0 && !/\s/.test(input[start - 1]!)) start--;
  let end = caret;
  while (end < input.length && !/\s/.test(input[end]!)) end++;
  const token = input.slice(start, end);
  // Inside an open quote earlier in the string: no suggestions.
  const quotes = (input.slice(0, start).match(/(?<!\\)"/g) ?? []).length;
  if (quotes % 2 === 1 || token.includes('"')) return empty;

  const neg = token.startsWith('-');
  const body = neg ? token.slice(1) : token;
  const colon = body.indexOf(':');
  const prefix = neg ? '-' : '';
  if (colon === -1) {
    if (body === '') return { ...empty, start, end };
    const items = QUERY_KEYS.filter((k) => k.startsWith(body.toLowerCase()) && k !== body.toLowerCase()).map((k) => ({ label: `${prefix}${k}:`, insert: `${prefix}${k}:`, hint: KEY_HINTS[k] }));
    return { start, end, items };
  }
  const key = body.slice(0, colon).toLowerCase();
  if (!isQueryKey(key)) return { ...empty, start, end };
  const vals = KEY_VALUES[key];
  if (!vals) return { ...empty, start, end };
  const typed = body.slice(colon + 1).toLowerCase();
  const items = vals.filter((v) => v.startsWith(typed) && v !== typed).map((v) => ({ label: `${prefix}${key}:${v}`, insert: `${prefix}${key}:${v}`, hint: '' }));
  return { start, end, items };
}

/** Apply a suggestion to the input; returns new text + caret. */
export function applySuggestion(input: string, r: SuggestResult, s: Suggestion): { text: string; caret: number } {
  const complete = !s.insert.endsWith(':');
  const tail = input.slice(r.end);
  const sep = complete && !/^\s/.test(tail) ? ' ' : '';
  const text = input.slice(0, r.start) + s.insert + sep + tail;
  return { text, caret: r.start + s.insert.length + sep.length };
}

// ── Top-N → search terms ────────────────────────────────────────────────────

export type TopDim = 'credentials' | 'usernames' | 'passwords' | 'useragents' | 'paths' | 'asns' | 'ja4' | 'ports' | 'countries' | 'tags' | 'scanners';

/** Translate a Top-N row into the search terms that reproduce it. */
export function termsForTop(dim: string, key: string): Term[] {
  switch (dim) {
    case 'credentials': {
      const i = key.indexOf(':');
      if (i === -1) return [kv('user', key)];
      const user = key.slice(0, i);
      const pass = key.slice(i + 1);
      const out: Term[] = [];
      if (user) out.push(kv('user', user));
      if (pass) out.push(word(pass));
      return out;
    }
    case 'usernames':
      return [kv('user', key)];
    case 'passwords':
    case 'useragents':
    case 'paths':
      return [word(key)];
    case 'asns': {
      const m = /^AS?(\d+)/i.exec(key.trim());
      return m ? [kv('asn', m[1]!)] : [word(key)];
    }
    case 'ja4':
      return [kv('ja4', key)];
    case 'ports': {
      const m = /^(\d+)/.exec(key.trim());
      return m ? [kv('port', m[1]!)] : [word(key)];
    }
    case 'countries':
      return /^[A-Za-z]{2}$/.test(key.trim()) ? [kv('cc', key.trim().toUpperCase())] : [word(key)];
    case 'tags':
      return [kv('tag', key)];
    case 'scanners':
      return [kv('scanner', key)];
    default:
      return [word(key)];
  }
}

export function applyTerms(q: string, terms: readonly Term[]): string {
  let out = q;
  for (const t of terms) out = addTerm(out, t);
  return out;
}
