import { api } from './api';
import type { ServiceEntry } from './types';

/**
 * Small built-in fallback used only until /api/services answers (or if it
 * never does). The server registry is the source of truth.
 */
export const FALLBACK_PORT_NAMES: Readonly<Record<string, string>> = {
  '0': 'ICMP',
  '21': 'FTP',
  '22': 'SSH',
  '23': 'Telnet',
  '25': 'SMTP',
  '53': 'DNS',
  '80': 'HTTP',
  '110': 'POP3',
  '123': 'NTP',
  '143': 'IMAP',
  '443': 'HTTPS',
  '445': 'SMB',
  '1433': 'MSSQL',
  '3306': 'MySQL',
  '3389': 'RDP',
  '5432': 'PostgreSQL',
  '5900': 'VNC',
  '6379': 'Redis',
  '8080': 'HTTP proxy',
  '8443': 'HTTPS alt',
  '9200': 'Elasticsearch',
  '11211': 'Memcached',
  '27017': 'MongoDB',
};

/** Build a port→name map from the /api/services payload. */
export function buildPortMap(services: ServiceEntry[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const s of services) {
    if (!s || !Array.isArray(s.ports)) continue;
    for (const p of s.ports) {
      const key = String(p);
      // First name wins when two services claim the same port.
      if (!m.has(key)) m.set(key, s.name);
    }
  }
  return m;
}

export class ServiceRegistry {
  private portNames = new Map<string, string>(Object.entries(FALLBACK_PORT_NAMES));
  private servicePorts = new Map<string, Set<string>>();
  private entries: ServiceEntry[] = [];
  private loaded = false;
  readonly ready: Promise<void>;

  constructor(loader: () => Promise<ServiceEntry[]> = api.services) {
    this.ready = loader()
      .then((list) => this.load(list))
      .catch(() => {
        /* keep fallback */
      });
  }

  load(list: ServiceEntry[]): void {
    if (!Array.isArray(list)) return;
    this.entries = list
      .filter((s) => s && typeof s.name === 'string')
      .map((s) => ({ ...s, ports: [...(s.ports ?? [])].sort((a, b) => a - b) }))
      .sort((a, b) => a.name.localeCompare(b.name));
    const fresh = buildPortMap(this.entries);
    // Server values override fallback; fallback remains for unknown ports.
    for (const [k, v] of fresh) this.portNames.set(k, v);
    this.servicePorts.clear();
    for (const s of this.entries) this.servicePorts.set(s.name, new Set(s.ports.map(String)));
    this.loaded = true;
  }

  get isLoaded(): boolean {
    return this.loaded;
  }

  /** Human name for a port string, or '' when unknown. */
  name(port: string | number | undefined | null): string {
    if (port === undefined || port === null || port === '' || port === 'unknown') return '';
    return this.portNames.get(String(port)) ?? '';
  }

  /** Name or `port N` label. */
  label(port: string | number | undefined | null): string {
    const n = this.name(port);
    if (n) return n;
    if (port === undefined || port === null || port === '' || port === 'unknown') return 'unknown';
    return `port ${port}`;
  }

  list(): readonly ServiceEntry[] {
    return this.entries;
  }

  portsFor(serviceName: string): ReadonlySet<string> | undefined {
    return this.servicePorts.get(serviceName);
  }
}
