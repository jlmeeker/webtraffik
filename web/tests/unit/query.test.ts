import { describe, expect, it } from 'vitest';
import {
  addTerm,
  applySuggestion,
  applyTerms,
  hasTerm,
  kv,
  parseQuery,
  quoteValue,
  removeTerm,
  serializeQuery,
  suggestAt,
  termsForTop,
  toggleTerm,
  validateQuery,
  word,
  type Term,
} from '../../src/lib/query';

const t = (q: string) => parseQuery(q).terms;

describe('parseQuery', () => {
  it('splits on whitespace into key:value and free-text terms', () => {
    expect(t('port:22  cc:CN   mirai')).toEqual([kv('port', '22'), kv('cc', 'CN'), word('mirai')]);
  });

  it('returns no terms for blank input', () => {
    expect(t('')).toEqual([]);
    expect(t('   \t ')).toEqual([]);
  });

  it('handles negation on known keys only', () => {
    expect(t('-cc:US')).toEqual([kv('cc', 'US', true)]);
    expect(t('-v')).toEqual([word('-v')]);
    expect(t('-nokey:1')).toEqual([word('-nokey:1')]);
  });

  it('treats unknown keys as free text and keys case-insensitively', () => {
    expect(t('foo:bar')).toEqual([word('foo:bar')]);
    expect(t('PORT:22 Cc:de')).toEqual([kv('port', '22'), kv('cc', 'de')]);
  });

  it('parses quoted phrases and quoted values', () => {
    expect(t('"hello world" user:"john smith"')).toEqual([word('hello world'), kv('user', 'john smith')]);
  });

  it('honours escapes inside quotes', () => {
    expect(t('"say \\"hi\\"" sni:"a\\\\b"')).toEqual([word('say "hi"'), kv('sni', 'a\\b')]);
  });

  it('a quoted token is never a key', () => {
    expect(t('"port:22"')).toEqual([word('port:22')]);
    expect(t('"-cc:US"')).toEqual([word('-cc:US')]);
  });

  it('keeps colons inside values', () => {
    expect(t('tag:scanner:zgrab ja4:t13d1516h2_8daaf6152771')).toEqual([kv('tag', 'scanner:zgrab'), kv('ja4', 't13d1516h2_8daaf6152771')]);
  });

  it('reports unterminated quotes and empty values', () => {
    expect(parseQuery('user:"abc').error).toBe('Unterminated quote');
    expect(parseQuery('"abc def').error).toBe('Unterminated quote');
    expect(parseQuery('port:').error).toMatch(/Missing value/);
    expect(parseQuery('port:22 cc:CN').error).toBeNull();
    expect(validateQuery('x "y')).toBe('Unterminated quote');
  });

  it('does not throw on hostile input', () => {
    for (const s of ['"', '\\', '-', '-:', ':', '""', 'a"b', '\\"', '"\\', 'user:"\\"', '\u0000', '-"x"']) {
      expect(() => parseQuery(s)).not.toThrow();
    }
  });
});

describe('serializeQuery', () => {
  it('quotes only when needed', () => {
    expect(quoteValue('abc')).toBe('abc');
    expect(quoteValue('a b')).toBe('"a b"');
    expect(quoteValue('')).toBe('""');
    expect(quoteValue('a"b')).toBe('"a\\"b"');
    expect(quoteValue('a\\b')).toBe('"a\\\\b"');
  });

  it('writes negation prefixes', () => {
    expect(serializeQuery([kv('cc', 'US', true), kv('port', '22')])).toBe('-cc:US port:22');
  });

  it('quotes free words that would otherwise parse as keys', () => {
    expect(serializeQuery([word('port:22')])).toBe('"port:22"');
    expect(serializeQuery([word('-cc:US')])).toBe('"-cc:US"');
    expect(serializeQuery([word('foo:bar')])).toBe('foo:bar');
  });

  const samples = [
    'port:22 cc:CN mirai',
    '-cc:US -tag:scanner:zgrab',
    '"hello world" user:"john smith" -sni:"a b"',
    'user:"say \\"hi\\"" "back\\\\slash"',
    '"port:22" "-cc:US" -v',
    'since:24h until:1h kind:session class:exploit scanner:Shodan proto:udp ja3:abc ja4:def asn:14061 ip:203.0.113',
    'user:""',
  ];
  it.each(samples)('round-trips %s', (q) => {
    const first = t(q);
    const again = t(serializeQuery(first));
    expect(again).toEqual(first);
    // Serialisation is idempotent.
    expect(serializeQuery(again)).toBe(serializeQuery(first));
  });

  it('round-trips arbitrary values through quoting', () => {
    const values = ['a b', 'x"y', '\\', 'tab\there', '-dash', 'port:22', "it's", 'ünï', ''];
    for (const v of values) {
      for (const term of [word(v), kv('user', v), kv('sni', v, true)] as Term[]) {
        expect(t(serializeQuery([term]))).toEqual([term]);
      }
    }
  });
});

describe('term editing helpers', () => {
  it('adds without duplicating (case-insensitive value)', () => {
    expect(addTerm('', kv('kind', 'session'))).toBe('kind:session');
    expect(addTerm('kind:session', kv('kind', 'SESSION'))).toBe('kind:session');
    expect(addTerm('mirai', kv('port', '23'))).toBe('mirai port:23');
  });
  it('removes and toggles', () => {
    expect(removeTerm('port:22 cc:CN', kv('port', '22'))).toBe('cc:CN');
    expect(removeTerm('port:22', kv('port', '23'))).toBe('port:22');
    expect(toggleTerm('port:22', kv('port', '22'))).toBe('');
    expect(toggleTerm('', kv('port', '22'))).toBe('port:22');
    expect(hasTerm('-cc:US', kv('cc', 'US'))).toBe(false);
    expect(hasTerm('-cc:US', kv('cc', 'US', true))).toBe(true);
  });
  it('applyTerms folds several terms', () => {
    expect(applyTerms('cc:CN', [kv('user', 'root'), word('pass word')])).toBe('cc:CN user:root "pass word"');
  });
});

describe('suggestAt', () => {
  it('suggests keys by prefix', () => {
    const r = suggestAt('po', 2);
    expect(r.items.map((i) => i.insert)).toEqual(['port:']);
    expect(suggestAt('s', 1).items.map((i) => i.insert)).toEqual(['scanner:', 'sni:', 'since:']);
  });
  it('keeps the negation prefix', () => {
    expect(suggestAt('-cl', 3).items.map((i) => i.insert)).toEqual(['-class:']);
  });
  it('suggests enumerated values', () => {
    expect(suggestAt('kind:', 5).items.map((i) => i.insert)).toEqual(['kind:session', 'kind:probe', 'kind:observed']);
    expect(suggestAt('port:22 class:ex', 16).items.map((i) => i.insert)).toEqual(['class:exploit']);
    expect(suggestAt('since:', 6).items.length).toBeGreaterThan(0);
  });
  it('is quiet for empty tokens, free keys, unknown keys and inside quotes', () => {
    expect(suggestAt('', 0).items).toEqual([]);
    expect(suggestAt('port:22 ', 8).items).toEqual([]);
    expect(suggestAt('port:2', 6).items).toEqual([]);
    expect(suggestAt('zzz:', 4).items).toEqual([]);
    expect(suggestAt('"hello po', 9).items).toEqual([]);
  });
  it('applies a suggestion at the caret', () => {
    const q = 'port:22 cl more';
    const r = suggestAt(q, 10);
    const key = applySuggestion(q, r, r.items[0]!);
    expect(key.text).toBe('port:22 class: more');
    expect(key.caret).toBe('port:22 class:'.length);
    const q2 = 'kind:se';
    const r2 = suggestAt(q2, q2.length);
    expect(applySuggestion(q2, r2, r2.items[0]!).text).toBe('kind:session ');
  });
});

describe('termsForTop', () => {
  it('maps each dimension onto grammar terms', () => {
    expect(termsForTop('asns', 'AS14061 DigitalOcean')).toEqual([kv('asn', '14061')]);
    expect(termsForTop('ports', '22')).toEqual([kv('port', '22')]);
    expect(termsForTop('countries', 'cn')).toEqual([kv('cc', 'CN')]);
    expect(termsForTop('countries', 'China')).toEqual([word('China')]);
    expect(termsForTop('usernames', 'root')).toEqual([kv('user', 'root')]);
    expect(termsForTop('passwords', '123456')).toEqual([word('123456')]);
    expect(termsForTop('credentials', 'root:pa:ss')).toEqual([kv('user', 'root'), word('pa:ss')]);
    expect(termsForTop('credentials', 'admin:')).toEqual([kv('user', 'admin')]);
    expect(termsForTop('ja4', 't13d')).toEqual([kv('ja4', 't13d')]);
    expect(termsForTop('tags', 'scanner:zgrab')).toEqual([kv('tag', 'scanner:zgrab')]);
    expect(termsForTop('scanners', 'Shodan')).toEqual([kv('scanner', 'Shodan')]);
    expect(termsForTop('useragents', 'curl/8.0 x')).toEqual([word('curl/8.0 x')]);
    expect(termsForTop('paths', '/.env')).toEqual([word('/.env')]);
  });
  it('produces queries that parse back to the same terms', () => {
    for (const [dim, key] of [['credentials', 'root:pass word'], ['useragents', 'Mozilla/5.0 (X11; Linux)'], ['paths', '/a b'], ['asns', 'AS1 x']] as const) {
      const terms = termsForTop(dim, key);
      expect(t(serializeQuery(terms))).toEqual(terms);
    }
  });
});
