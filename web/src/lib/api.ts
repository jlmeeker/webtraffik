import type {
  BanEntry,
  Campaign,
  ConnectionEvent,
  EBPFStats,
  HistoryFilters,
  Hop,
  IntelInfo,
  MetricsResponse,
  ScannerEntry,
  SelfInfo,
  ServiceEntry,
  TopResponse,
} from './types';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly url: string,
    message?: string,
    /** Response body text (the backend sends plain-text errors, e.g. a 400 for a bad query). */
    public readonly detail: string = '',
  ) {
    super(message ?? (detail || `HTTP ${status} for ${url}`));
    this.name = 'ApiError';
  }
}

// Same-origin requests; the browser attaches HTTP Basic credentials itself.
const BASE_INIT: RequestInit = { credentials: 'same-origin' };

async function getJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, { ...BASE_INIT, ...init });
  if (!resp.ok) {
    let detail = '';
    if (resp.status === 400) {
      try {
        detail = (await resp.text()).trim().slice(0, 300);
      } catch {
        detail = '';
      }
    }
    throw new ApiError(resp.status, url, undefined, detail);
  }
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
  history: (f: HistoryFilters) => getJSON<ConnectionEvent[]>(`/api/history${qs(f as Record<string, string | number | undefined>)}`),
  top: (by: string, hours: number, limit = 10) => getJSON<TopResponse>(`/api/top${qs({ by, hours, limit })}`),
  campaigns: (hours = 72, limit = 20) => getJSON<Campaign[]>(`/api/campaigns${qs({ hours, limit })}`),
  intel: (ip: string) => getJSON<IntelInfo>(`/api/intel${qs({ ip })}`),
  recent: () => getJSON<ConnectionEvent[]>('/api/recent'),
  banned: () => getJSON<BanEntry[]>('/api/banned'),
  scanners: () => getJSON<ScannerEntry[]>('/api/scanners'),
  services: () => getJSON<ServiceEntry[]>('/api/services'),
  ebpfStats: () => getJSON<EBPFStats>('/api/ebpf/stats'),
  metrics: (from?: string, to?: string) => getJSON<MetricsResponse>(`/api/metrics${qs({ from, to })}`),
  ban: (ip: string, port: string) => postJSON<{ status: string }>('/api/ban', { ip, port }),
  unban: (ip: string, port: string) => postJSON<{ status: string }>('/api/unban', { ip, port }),
};

/** True when an optional endpoint is not offered by this backend (feature hides itself). */
export function isUnsupported(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 405 || err.status === 501);
}

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
