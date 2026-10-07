import type { Page } from '@playwright/test';

export const SELF = { ip: '203.0.113.10', lat: 51.5, lon: -0.12, city: 'London', cc: 'GB' };

export const SERVICES = [
  { name: 'SSH', ports: [22] },
  { name: 'HTTP', ports: [80, 8080] },
  { name: 'Redis', ports: [6379] },
];

export function makeEvent(i: number, overrides: Record<string, unknown> = {}) {
  const ports = ['22', '80', '6379', '3389'];
  const places = [
    { lat: 40.7, lon: -74.0, city: 'New York', cc: 'US' },
    { lat: 35.7, lon: 139.7, city: 'Tokyo', cc: 'JP' },
    { lat: -33.9, lon: 151.2, city: 'Sydney', cc: 'AU' },
    { lat: 55.75, lon: 37.6, city: 'Moscow', cc: 'RU' },
  ];
  const p = places[i % places.length]!;
  return {
    time: new Date(Date.now() - (50 - i) * 1000).toISOString(),
    src_ip: `198.51.100.${(i % 200) + 1}`,
    dst_ip: SELF.ip,
    dst_port: ports[i % ports.length],
    protocol: 'tcp',
    src_lat: p.lat,
    src_lon: p.lon,
    dst_lat: SELF.lat,
    dst_lon: SELF.lon,
    src_city: p.city,
    dst_city: SELF.city,
    src_cc: p.cc,
    dst_cc: SELF.cc,
    ...overrides,
  };
}

/** Extra fields the extended backend adds to events (kind / class / scanner / tags). */
export function enrich(i: number): Record<string, unknown> {
  const extra: Record<string, unknown> = {};
  if (i % 3 === 0) Object.assign(extra, { kind: 'session', class: 'bruteforce', tags: ['bruteforce:ssh'] });
  else if (i % 5 === 0) Object.assign(extra, { kind: 'probe', class: 'research', scanner: 'Shodan', tags: ['scanner:shodan'] });
  else if (i % 7 === 0) Object.assign(extra, { kind: 'observed' });
  return extra;
}

export const TOP: Record<string, Array<Record<string, unknown>>> = {
  asns: [
    { key: 'AS14061 DigitalOcean', count: 1234, ips: 57, prev: 900, delta_pct: 37.1 },
    { key: 'AS4134 Chinanet', count: 800, ips: 40, prev: 1000, delta_pct: -20 },
    { key: 'AS9009 M247', count: 120, ips: 3, prev: 0, delta_pct: null },
    { key: 'AS16509 Amazon', count: 50, ips: 9 },
  ],
  usernames: [{ key: 'root', count: 500, ips: 20, prev: 500, delta_pct: 0 }],
};

export const CAMPAIGNS = [
  {
    id: 'c-1a2b3c',
    label: 'ja4:t13d1516h2_8daaf6152771',
    ips: ['198.51.100.4', '198.51.100.5', '198.51.100.6'],
    ip_count: 40,
    events: 300,
    ports: [22, 23],
    countries: ['CN', 'US'],
    tags: ['scanner:zgrab'],
    first_seen: new Date(Date.now() - 3 * 3600e3).toISOString(),
    last_seen: new Date(Date.now() - 60e3).toISOString(),
  },
  { id: 'c-9f9f9f', label: 'ua:Go-http-client', ips: ['203.0.113.77'], ip_count: 1, events: 12, ports: [80], countries: ['NL'], tags: [] },
];

export const BANNED = [
  { ip: '198.51.100.7', port: '22', service: 'SSH', cc: 'RU', banned_at: new Date().toISOString(), expires_at: new Date(Date.now() + 3_600_000).toISOString() },
];

export const SCANNERS = [
  {
    ip: '198.51.100.99',
    port_count: 7,
    detected_at: new Date(Date.now() - 120_000).toISOString(),
    expires_at: new Date(Date.now() + 3_000_000).toISOString(),
    last_seen_at: new Date().toISOString(),
  },
];

export const EBPF = { enabled: true, mode: 'hybrid', interface: 'eth0', packets_passed: 123456, packets_dropped: 789, bans_active: 1, uptime_seconds: 3700 };

export function metricsPayload() {
  const buckets = [];
  const now = Date.now();
  for (let i = 5; i >= 0; i--) {
    buckets.push({ bucket: new Date(Math.floor((now - i * 3600e3) / 3600e3) * 3600e3).toISOString(), value: 100 + i * 17, unique_ips: 20 + i, bans: i % 2 });
  }
  return {
    connections: [
      { labels: { port: '22', protocol: 'tcp', service: 'SSH', cc: 'US' }, value: 300 },
      { labels: { port: '80', protocol: 'tcp', service: 'HTTP', cc: 'JP' }, value: 200 },
      { labels: { port: '6379', protocol: 'tcp', service: 'Redis', cc: 'RU' }, value: 50 },
    ],
    bans: [{ labels: { type: 'auto' }, value: 3 }],
    unique_ips: 123,
    time_buckets: buckets,
    port_timeline: { '22': buckets.map((b) => ({ bucket: b.bucket, value: b.value / 2 })), '80': buckets.map((b) => ({ bucket: b.bucket, value: b.value / 3 })) },
    country_timeline: { US: buckets.map((b) => ({ bucket: b.bucket, value: b.value / 2 })), JP: buckets.map((b) => ({ bucket: b.bucket, value: b.value / 4 })) },
  };
}

/** Mock every /api/* endpoint and the /ws stream. */
export interface MockOptions {
  replay?: number;
  live?: number;
  /** Extra XDP-only ("observed") events appended to the WebSocket replay. */
  observedReplay?: number;
  /** Endpoints answering 404, like a backend without the feature. */
  missing?: Array<'top' | 'campaigns' | 'intel'>;
  /** Records the query string of every /api/history request. */
  historyLog?: string[];
}

export async function installMocks(page: Page, opts: MockOptions = {}): Promise<void> {
  const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/api/self', (r) => r.fulfill(json(SELF)));
  await page.route('**/api/services', (r) => r.fulfill(json(SERVICES)));
  await page.route('**/api/banned', (r) => r.fulfill(json(BANNED)));
  await page.route('**/api/scanners', (r) => r.fulfill(json(SCANNERS)));
  await page.route('**/api/ebpf/stats', (r) => r.fulfill(json(EBPF)));
  await page.route('**/api/metrics**', (r) => r.fulfill(json(metricsPayload())));
  await page.route('**/api/history**', (r) => {
    const url = new URL(r.request().url());
    opts.historyLog?.push(url.search);
    // Mimic the backend's 400 + text/plain for an invalid search query.
    if ((url.searchParams.get('q') ?? '').includes('explode')) {
      return r.fulfill({ status: 400, contentType: 'text/plain', body: 'invalid query: unexpected token "explode"' });
    }
    return r.fulfill(json(Array.from({ length: 30 }, (_, i) => makeEvent(i, enrich(i)))));
  });
  const missing = new Set(opts.missing ?? []);
  const notFound = { status: 404, contentType: 'text/plain', body: '404 page not found' };
  await page.route('**/api/top**', (r) => {
    if (missing.has('top')) return r.fulfill(notFound);
    const by = new URL(r.request().url()).searchParams.get('by') ?? 'asns';
    return r.fulfill(json({ by, hours: 24, items: TOP[by] ?? [] }));
  });
  await page.route('**/api/campaigns**', (r) => (missing.has('campaigns') ? r.fulfill(notFound) : r.fulfill(json(CAMPAIGNS))));
  await page.route('**/api/intel**', (r) => (missing.has('intel') ? r.fulfill(notFound) : r.fulfill(json({ ip: '198.51.100.4', rdns: 'scan.example.net', scanner: 'Shodan' }))));
  await page.route('**/api/recent', (r) =>
    r.fulfill(
      json([
        ...Array.from({ length: 12 }, (_, i) => makeEvent(i, i % 2 === 0 ? { client_data: '474554202f20485454502f312e310d0a', ...(i === 0 ? { kind: 'session', class: 'exploit', scanner: 'Shodan' } : {}) } : {})),
        // XDP-only observations: hidden by the default "hide XDP-only noise" toggle.
        ...Array.from({ length: 4 }, (_, i) => makeEvent(13 + 2 * i, { kind: 'observed' })),
      ]),
    ),
  );
  await page.route('**/api/ban', (r) => r.fulfill(json({ status: 'banned' })));
  await page.route('**/api/unban', (r) => r.fulfill(json({ status: 'unbanned' })));
  await page.route('**/api/traceroute**', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'text/event-stream',
      body:
        `data: ${JSON.stringify({ n: 1, ip: '192.0.2.1', rtt: 2, lat: 51.5, lon: -0.1, city: 'London', cc: 'GB', accuracy_km: 20 })}\n\n` +
        `data: ${JSON.stringify({ n: 2, ip: '192.0.2.2', rtt: 40, lat: 40.7, lon: -74, city: 'New York', cc: 'US', accuracy_km: 10 })}\n\n` +
        `event: done\ndata: {}\n\n`,
    }),
  );

  const replay = opts.replay ?? 20;
  const live = opts.live ?? 3;
  await page.routeWebSocket('**/ws**', (ws) => {
    for (let i = 0; i < replay; i++) ws.send(JSON.stringify({ ...makeEvent(i), replay: true }));
    for (let i = 0; i < (opts.observedReplay ?? 0); i++) ws.send(JSON.stringify({ ...makeEvent(i), kind: 'observed', replay: true }));
    let n = 0;
    const timer = setInterval(() => {
      if (n >= live) {
        clearInterval(timer);
        return;
      }
      ws.send(JSON.stringify(makeEvent(replay + n++)));
    }, 400);
    ws.onClose(() => clearInterval(timer));
  });
}
