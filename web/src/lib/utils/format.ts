/** 1234 → "1.2K", 1.5e6 → "1.5M". */
export function fmtNum(n: number | null | undefined): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—';
  const abs = Math.abs(n);
  if (abs >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (abs >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (abs >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

function hms(totalSec: number): { h: number; m: number; s: number } {
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  return { h, m, s };
}

/** "2m 15s ago" relative to `now` (ms epoch). */
export function formatTimeAgo(iso: string, now: number = Date.now()): string {
  const ms = now - new Date(iso).getTime();
  if (Number.isNaN(ms)) return '';
  if (ms < 0) return 'just now';
  const { h, m, s } = hms(Math.floor(ms / 1000));
  if (h > 0) return `${h}h ${m}m ago`;
  if (m > 0) return `${m}m ${s}s ago`;
  return `${s}s ago`;
}

/** "1h 3m" until `iso`, or "expiring" once passed. */
export function formatTimeRemaining(iso: string, now: number = Date.now()): string {
  const ms = new Date(iso).getTime() - now;
  if (Number.isNaN(ms)) return '';
  if (ms <= 0) return 'expiring';
  const { h, m, s } = hms(Math.floor(ms / 1000));
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

/** Seconds → "45s" | "3m 2s" | "2h 5m". */
export function fmtUptime(sec: number | undefined | null): string {
  if (sec === undefined || sec === null || Number.isNaN(sec)) return '—';
  const s = Math.max(0, Math.floor(sec));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  const { h, m } = hms(s);
  return `${h}h ${m}m`;
}

/** Hex string → classic 16-byte hex+ASCII dump. */
export function hexPreview(hexStr: string | undefined | null): string {
  if (!hexStr) return '';
  const clean = hexStr.replace(/[^0-9a-fA-F]/g, '');
  const bytes: number[] = [];
  for (let i = 0; i + 1 < clean.length; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hexPart = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascPart = chunk.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
    lines.push(off.toString(16).padStart(4, '0') + '  ' + hexPart.padEnd(48) + '  ' + ascPart);
  }
  return lines.join('\n');
}

/** Date → "YYYY-MM-DDTHH:MM:SS" in local time (datetime-local input value). */
export function localDateTimeStr(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** datetime-local value → UTC ISO string ('' when invalid). */
export function localDateTimeToUTC(dt: string): string {
  if (!dt) return '';
  const d = new Date(dt);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

export function timeHMS(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString('en-US', { hour12: false });
}

export function dateShort(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function dateTimeFull(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d
    .toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
    .replace(',', '');
}

/** "City, CC" | city | cc | fallback. */
export function placeLabel(city: string | undefined, cc: string | undefined, fallback = ''): string {
  if (city && cc) return `${city}, ${cc}`;
  return city || cc || fallback;
}

export function ensureInt(v: string | number | null | undefined, min: number, max: number, dflt: number): number {
  const n = typeof v === 'number' ? v : parseInt(String(v ?? ''), 10);
  if (Number.isNaN(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}
