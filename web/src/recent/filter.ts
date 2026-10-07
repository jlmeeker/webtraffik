import type { ConnectionEvent } from '../lib/types';

/** Pure filter used by the page (unit-tested). */
export function filterRecent(
  events: ConnectionEvent[],
  opts: { onlyWithData: boolean; ports?: ReadonlySet<string> | undefined; limit: number },
): ConnectionEvent[] {
  let out = opts.onlyWithData ? events.filter((e) => Boolean(e.client_data)) : events.slice();
  if (opts.ports) out = out.filter((e) => opts.ports!.has(e.dst_port));
  if (out.length > opts.limit) out = out.slice(out.length - opts.limit);
  return out;
}
