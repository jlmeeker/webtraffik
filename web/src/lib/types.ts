// Backend API contract. Every type tolerates extra, unknown fields — the server
// may add optional keys (asn, tags, ...) without a frontend release.

export interface ConnectionEvent {
  time: string;
  src_ip: string;
  dst_ip: string;
  dst_port: string; // string on the wire, e.g. "22" or "unknown"
  protocol?: string; // "tcp" | "udp" | "icmp"
  src_lat: number;
  src_lon: number;
  dst_lat: number;
  dst_lon: number;
  src_city?: string;
  dst_city?: string;
  src_cc?: string;
  dst_cc?: string;
  replay?: boolean;
  client_data?: string; // hex-encoded, optional / ephemeral
  asn?: string | number;
  tags?: string[];
  /** "session" = honeypot conversation captured, "probe" = no payload, "observed" = XDP only. */
  kind?: EventKind | string;
  class?: EventClass | string;
  /** Known research scanner name (e.g. "Shodan"). */
  scanner?: string;
  detail?: string;
  meta?: Record<string, unknown>;
  [extra: string]: unknown;
}

export type EventKind = 'session' | 'probe' | 'observed';
export type EventClass = 'exploit' | 'bruteforce' | 'scan' | 'research' | 'unknown';

export interface SelfInfo {
  ip: string;
  lat: number;
  lon: number;
  city: string;
  cc: string;
  [extra: string]: unknown;
}

export interface BanEntry {
  ip: string;
  port: string;
  service?: string;
  cc?: string;
  banned_at: string;
  expires_at: string;
  [extra: string]: unknown;
}

export interface ScannerEntry {
  ip: string;
  port_count: number;
  detected_at: string;
  expires_at: string;
  last_seen_at: string;
  [extra: string]: unknown;
}

export interface ServiceEntry {
  name: string;
  ports: number[];
  [extra: string]: unknown;
}

export interface Hop {
  n?: number;
  ip: string;
  rtt?: number;
  lat: number;
  lon: number;
  city?: string;
  cc?: string;
  accuracy_km?: number;
  [extra: string]: unknown;
}

export interface EBPFStats {
  enabled: boolean;
  mode: string;
  interface?: string;
  packets_passed: number;
  packets_dropped: number;
  bans_active: number;
  uptime_seconds?: number;
  [extra: string]: unknown;
}

export interface MetricSeries {
  labels: Record<string, string>;
  value: number;
}

export interface TimeBucket {
  bucket: string;
  value: number;
  unique_ips?: number;
  bans?: number;
}

export interface MetricsResponse {
  connections?: MetricSeries[];
  bans?: MetricSeries[];
  unique_ips?: number;
  time_buckets?: TimeBucket[];
  port_timeline?: Record<string, TimeBucket[]>;
  country_timeline?: Record<string, TimeBucket[]>;
  [extra: string]: unknown;
}

export interface HistoryFilters {
  country?: string;
  ip?: string;
  port?: string;
  service?: string;
  /** Free-text search query (see lib/query.ts for the grammar). */
  q?: string;
  kind?: string;
  class?: string;
  scanner?: string;
  proto?: string;
  tag?: string;
  asn?: string;
  limit?: number;
  offset?: number;
  date_from?: string; // ISO UTC
  date_to?: string; // ISO UTC
}

export interface GeoPoint {
  lat: number;
  lon: number;
  city?: string;
  cc?: string;
}

/** [lon, lat] tuple as used by d3-geo. */
export type LonLat = [number, number];

export interface TopItem {
  key: string;
  count: number;
  ips?: number;
  prev?: number;
  /** null/absent when prev == 0 (render "new"). */
  delta_pct?: number | null;
}

export interface TopResponse {
  by: string;
  hours: number;
  items: TopItem[];
}

export interface Campaign {
  id: string;
  label: string;
  ips?: string[];
  ip_count?: number;
  events?: number;
  ports?: number[];
  countries?: string[];
  tags?: string[];
  first_seen?: string;
  last_seen?: string;
}

export interface IntelInfo {
  ip?: string;
  rdns?: string;
  scanner?: string;
  greynoise?: string;
  abuse_score?: number;
  updated?: string;
}
