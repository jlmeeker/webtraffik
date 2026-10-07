import type {
  BanEntry,
  ConnectionEvent,
  EBPFStats,
  HistoryFilters,
  Hop,
  MetricsResponse,
  ScannerEntry,
  SelfInfo,
  ServiceEntry,
} from './types';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    message?: string,
  ) {
    super(message ?? `HTTP ${status} for ${url}`);
    this.name = 'ApiError';
  }
}

// Same-origin requests; the browser attaches HTTP Basic credentials itself.
const BASE_INIT: RequestInit = { credentials: 'same-origin' };

async function getJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, { ...BASE_INIT, ...init });
  if (!resp.ok) throw new ApiError(resp.status, url);
  return (await resp.json()) as T;
}

async function postJSON<T>(url: string, body: unknown): Promise<{ status: number; data: T | null }> {
  const resp = await fetch(url, {
    ...BASE_INIT,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let data: T | null = null;
  try {
    data = (await resp.json()) as T;
  } catch {
    data = null;
  }
  return { status: resp.status, data };
}

function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

export const api = {
  self: () => getJSON<SelfInfo>('/api/self'),
  history: (f: HistoryFilters) => getJSON<ConnectionEvent[]>(`/api/history${qs(f as Record<string, string | undefined>)}`),
  recent: () => getJSON<ConnectionEvent[]>('/api/recent'),
  banned: () => getJSON<BanEntry[]>('/api/banned'),
  scanners: () => getJSON<ScannerEntry[]>('/api/scanners'),
  services: () => getJSON<ServiceEntry[]>('/api/services'),
  ebpfStats: () => getJSON<EBPFStats>('/api/ebpf/stats'),
  metrics: (from?: string, to?: string) => getJSON<MetricsResponse>(`/api/metrics${qs({ from, to })}`),
  ban: (ip: string, port: string) => postJSON<{ status: string }>('/api/ban', { ip, port }),
  unban: (ip: string, port: string) => postJSON<{ status: string }>('/api/unban', { ip, port }),
};

export interface TracerouteHandlers {
  onHop: (hop: Hop) => void;
  onDone: () => void;
  onError: () => void;
}

/**
 * Opens the /api/traceroute SSE stream. Returns a function that closes it.
 * EventSource sends cookies/credentials on same-origin requests by default.
 */
export function openTraceroute(ip: string, handlers: TracerouteHandlers): () => void {
  const es = new EventSource(`/api/traceroute?ip=${encodeURIComponent(ip)}`);
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    es.close();
  };
  es.onmessage = (e: MessageEvent<string>) => {
    let hop: Hop;
    try {
      hop = JSON.parse(e.data) as Hop;
    } catch {
      return;
    }
    handlers.onHop(hop);
  };
  es.addEventListener('done', () => {
    close();
    handlers.onDone();
  });
  es.onerror = () => {
    if (closed) return;
    close();
    handlers.onError();
  };
  return close;
}
