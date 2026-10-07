import type { ConnectionEvent } from './types';

export type StreamStatus = 'connecting' | 'open' | 'reconnecting' | 'closed';

export interface LiveStreamOptions {
  /** Replay window sent as ?hours=N (1..24). */
  hours: number;
  onEvent: (ev: ConnectionEvent) => void;
  onStatus?: (s: StreamStatus, info: { attempt: number; delayMs: number }) => void;
  /** Called right before a (re)connect so the page can reset derived state. */
  onReset?: () => void;
  /** Build the WebSocket URL; overridable for tests. */
  urlFor?: (hours: number) => string;
  minBackoffMs?: number;
  maxBackoffMs?: number;
}

export function defaultWsUrl(hours: number): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}/ws?hours=${hours}`;
}

/** Exponential backoff with ±20% jitter, clamped to [min, max]. */
export function backoffDelay(attempt: number, minMs = 1000, maxMs = 30_000, rand: () => number = Math.random): number {
  const base = Math.min(maxMs, minMs * 2 ** Math.max(0, attempt - 1));
  const jitter = base * 0.2 * (rand() * 2 - 1);
  return Math.round(Math.min(maxMs, Math.max(minMs, base + jitter)));
}

/**
 * Auto-reconnecting WebSocket client for /ws.
 * Each ConnectionEvent is one JSON text frame; replayed history has replay:true.
 */
export class LiveStream {
  private ws: WebSocket | null = null;
  private attempt = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;
  private _status: StreamStatus = 'closed';
  hours: number;

  constructor(private readonly opts: LiveStreamOptions) {
    this.hours = opts.hours;
  }

  get status(): StreamStatus {
    return this._status;
  }

  private setStatus(s: StreamStatus, delayMs = 0): void {
    this._status = s;
    this.opts.onStatus?.(s, { attempt: this.attempt, delayMs });
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  /** Close for good (no reconnect). */
  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.closeSocket();
    this.setStatus('closed');
  }

  /** Change the replay window and reconnect immediately. */
  setHours(hours: number): void {
    if (hours === this.hours && this.ws && this.ws.readyState === WebSocket.OPEN) return;
    this.hours = hours;
    this.attempt = 0;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.closeSocket();
    this.connect();
  }

  private closeSocket(): void {
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null;
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    }
  }

  private connect(): void {
    if (this.stopped) return;
    this.opts.onReset?.();
    this.setStatus(this.attempt === 0 ? 'connecting' : 'reconnecting');
    const url = (this.opts.urlFor ?? defaultWsUrl)(this.hours);
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      if (ws !== this.ws) return;
      this.attempt = 0;
      this.setStatus('open');
    };
    ws.onmessage = (msg: MessageEvent<string>) => {
      if (ws !== this.ws) return; // stale socket
      let ev: ConnectionEvent;
      try {
        ev = JSON.parse(msg.data) as ConnectionEvent;
      } catch {
        return;
      }
      if (!ev || typeof ev !== 'object') return;
      this.opts.onEvent(ev);
    };
    ws.onclose = () => {
      if (ws !== this.ws) return;
      this.ws = null;
      this.scheduleReconnect();
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    this.attempt++;
    const delay = backoffDelay(this.attempt, this.opts.minBackoffMs, this.opts.maxBackoffMs);
    this.setStatus('reconnecting', delay);
    this.timer = setTimeout(() => {
      this.timer = null;
      this.connect();
    }, delay);
  }
}
