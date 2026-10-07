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
  [extra: string]: unknown;
}

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
