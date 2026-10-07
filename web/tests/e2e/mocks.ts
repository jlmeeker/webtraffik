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
export async function installMocks(page: Page, opts: { replay?: number; live?: number } = {}): Promise<void> {
  const json = (body: unknown) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/api/self', (r) => r.fulfill(json(SELF)));
  await page.route('**/api/services', (r) => r.fulfill(json(SERVICES)));
  await page.route('**/api/banned', (r) => r.fulfill(json(BANNED)));
  await page.route('**/api/scanners', (r) => r.fulfill(json(SCANNERS)));
  await page.route('**/api/ebpf/stats', (r) => r.fulfill(json(EBPF)));
  await page.route('**/api/metrics**', (r) => r.fulfill(json(metricsPayload())));
  await page.route('**/api/history**', (r) => r.fulfill(json(Array.from({ length: 30 }, (_, i) => makeEvent(i)))));
  await page.route('**/api/recent', (r) =>
    r.fulfill(json(Array.from({ length: 12 }, (_, i) => makeEvent(i, i % 2 === 0 ? { client_data: '474554202f20485454502f312e310d0a' } : {})))),
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
