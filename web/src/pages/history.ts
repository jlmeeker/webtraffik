import '../styles/theme.css';
import '../styles/charts.css';
import '../styles/history.css';

import { horizontalBars } from '../charts/bars';
import { meter, statTiles } from '../charts/tiles';
import { columns, lines, type Series } from '../charts/timeline';
import { chartTokens } from '../charts/base';
import { bucketsToPoints, countBy, summarize, sumByLabel, topN, topTimelineKeys } from '../history/aggregate';
import { api } from '../lib/api';
import { initChrome } from '../lib/chrome';
import { SlotAssigner } from '../lib/palette';
import { ServiceRegistry } from '../lib/services';
import { onThemeChange } from '../lib/theme';
import type { ConnectionEvent, EBPFStats, MetricsResponse } from '../lib/types';
import { $, el } from '../lib/utils/dom';
import { dateTimeFull, fmtNum, fmtUptime, localDateTimeStr, localDateTimeToUTC } from '../lib/utils/format';
import { getPref, setPref } from '../lib/utils/prefs';
import { modeLabel } from '../panels/ebpf';

const PREF_FROM = 'wt_hist_from';
const PREF_TO = 'wt_hist_to';

function main(): void {
  initChrome();
  const services = new ServiceRegistry();

  const form = $<HTMLFormElement>('#filter-panel');
  const fCountry = $<HTMLInputElement>('#f-country');
  const fIp = $<HTMLInputElement>('#f-ip');
  const fPort = $<HTMLInputElement>('#f-port');
  const fService = $<HTMLSelectElement>('#f-service');
  const fFrom = $<HTMLInputElement>('#f-date-from');
  const fTo = $<HTMLInputElement>('#f-date-to');
  const fPreset = $<HTMLSelectElement>('#f-preset');
  const btnQuery = $<HTMLButtonElement>('#btn-query');
  const btnClear = $<HTMLButtonElement>('#btn-clear');
  const loading = $('#loading-indicator');
  const summaryEl = $('#result-summary');
  const emptyState = $('#empty-state');
  const emptyText = $('#empty-text');
  const results = $('#results');

  // Port colours keep identity across charts (slot by first appearance).
  const portSlots = new SlotAssigner();
  const ccSlots = new SlotAssigner();

  let last: { metrics: MetricsResponse; events: ConnectionEvent[]; ebpf: EBPFStats | null } | null = null;

  void services.ready.then(() => {
    for (const s of services.list()) {
      fService.append(el('option', { value: s.name, text: `${s.name} (${s.ports.join(', ')})` }));
    }
  });

  function setDefaultDates(): void {
    const savedFrom = getPref(PREF_FROM);
    const savedTo = getPref(PREF_TO);
    if (savedFrom && savedTo) {
      fFrom.value = savedFrom;
      fTo.value = savedTo;
    } else {
      const now = new Date();
      fTo.value = localDateTimeStr(now);
      fFrom.value = localDateTimeStr(new Date(now.getTime() - 3_600_000));
    }
  }
  fFrom.addEventListener('change', () => {
    setPref(PREF_FROM, fFrom.value);
    fPreset.value = '';
  });
  fTo.addEventListener('change', () => {
    setPref(PREF_TO, fTo.value);
    fPreset.value = '';
  });
  fPreset.addEventListener('change', () => {
    const hours = parseInt(fPreset.value, 10);
    if (!hours) return;
    const now = new Date();
    fTo.value = localDateTimeStr(now);
    fFrom.value = localDateTimeStr(new Date(now.getTime() - hours * 3_600_000));
    setPref(PREF_FROM, fFrom.value);
    setPref(PREF_TO, fTo.value);
    void runQuery();
  });

  function showEmpty(text: string): void {
    emptyText.textContent = text;
    emptyState.style.display = 'flex';
    results.hidden = true;
  }

  async function runQuery(): Promise<void> {
    btnQuery.disabled = true;
    loading.classList.add('visible');
    summaryEl.textContent = '';
    summaryEl.className = '';
    results.classList.add('stale');

    const from = localDateTimeToUTC(fFrom.value);
    const to = localDateTimeToUTC(fTo.value);
    try {
      const [events, metrics, ebpf] = await Promise.all([
        api.history({
          country: fCountry.value.trim(),
          ip: fIp.value.trim(),
          port: fPort.value.trim(),
          service: fService.value,
          date_from: from,
          date_to: to,
        }),
        api.metrics(from || undefined, to || undefined),
        api.ebpfStats().catch(() => null),
      ]);
      await services.ready;
      last = { metrics, events: Array.isArray(events) ? events : [], ebpf };
      render();
    } catch (err) {
      summaryEl.textContent = `Error: ${err instanceof Error ? err.message : String(err)}`;
      summaryEl.className = 'error';
    } finally {
      btnQuery.disabled = false;
      loading.classList.remove('visible');
      results.classList.remove('stale');
    }
  }

  function render(): void {
    if (!last) return;
    const { metrics, events, ebpf } = last;
    const s = summarize(metrics, events);
    summaryEl.textContent = `${s.connections.toLocaleString()} connections · ~${s.uniqueIPs.toLocaleString()} unique IPs · ${s.bans.toLocaleString()} bans · ${s.rawEvents.toLocaleString()} raw events`;

    if (s.connections === 0 && events.length === 0) {
      showEmpty('No events matched the selected filters.');
      return;
    }
    emptyState.style.display = 'none';
    results.hidden = false;
    const t = chartTokens();

    statTiles($('#kpi-tiles'), [
      { label: 'Connections', value: fmtNum(s.connections) },
      { label: 'Unique IPs', value: `~${fmtNum(s.uniqueIPs)}`, hint: 'approximate across hours' },
      { label: 'Bans', value: fmtNum(s.bans), hint: s.bans > 0 ? `${s.autoBans} auto · ${s.manualBans} manual` : undefined, tone: s.bans > 0 ? 'critical' : 'default' },
      { label: 'Raw events', value: fmtNum(s.rawEvents), hint: 'rows returned' },
    ]);

    const tb = metrics.time_buckets ?? [];
    columns($('#chart-timeline'), bucketsToPoints(tb, 'value'), { label: 'Connections per hour', height: 220 });

    const ipsPts = bucketsToPoints(tb, 'unique_ips');
    const bansPts = bucketsToPoints(tb, 'bans');
    const hasIPs = ipsPts.some((p) => p.v > 0);
    const hasBans = bansPts.some((p) => p.v > 0);
    $('#card-unique-ips').hidden = !hasIPs;
    $('#card-bans').hidden = !hasBans;
    $('#row-ips-bans').hidden = !hasIPs && !hasBans;
    if (hasIPs) columns($('#chart-unique-ips'), ipsPts, { label: 'Unique IPs per hour', height: 180, color: t.series[2] });
    if (hasBans) columns($('#chart-bans'), bansPts, { label: 'Bans per hour', height: 180, color: t.critical });

    const portTotals = sumByLabel(metrics.connections, 'port');
    const ports = topN(portTotals, 15);
    for (const [p] of ports) portSlots.slot(p);
    horizontalBars(
      $('#chart-ports'),
      ports.map(([p, v]) => ({ label: `${p} ${services.name(p)}`.trim(), value: v, color: portSlots.color(p, t.series, t.other) })),
      { label: 'Top ports' },
    );

    const ccTotals = sumByLabel(metrics.connections, 'cc', 'XX');
    const ccs = topN(ccTotals, 15);
    for (const [c] of ccs) ccSlots.slot(c);
    horizontalBars(
      $('#chart-countries'),
      ccs.map(([c, v]) => ({ label: c, value: v })),
      { label: 'Top countries' },
    );

    const svcTotals = new Map<string, number>();
    for (const c of metrics.connections ?? []) {
      const k = c.labels?.service || services.label(c.labels?.port ?? '');
      svcTotals.set(k, (svcTotals.get(k) ?? 0) + (Number(c.value) || 0));
    }
    horizontalBars(
      $('#chart-services'),
      topN(svcTotals, 12).map(([k, v]) => ({ label: k, value: v })),
      { label: 'Top services' },
    );

    horizontalBars(
      $('#chart-ips'),
      topN(countBy(events, (e) => e.src_ip), 15).map(([ip, v]) => ({ label: ip, value: v })),
      { label: 'Top source IPs' },
    );

    // Per-port timeline (≤ 8 series, colour follows the port entity).
    const ptKeys = topTimelineKeys(metrics.port_timeline, 8);
    const cardPT = $('#card-port-timeline');
    cardPT.hidden = ptKeys.length <= 1;
    if (ptKeys.length > 1) {
      const series: Series[] = ptKeys.map((p) => ({
        key: p,
        label: `${p} ${services.name(p)}`.trim(),
        color: portSlots.color(p, t.series, t.other),
        points: bucketsToPoints(metrics.port_timeline?.[p]),
      }));
      lines($('#chart-port-timeline'), series, { label: 'Connections over time by port' });
    }

    const ctKeys = topTimelineKeys(metrics.country_timeline, 8);
    const cardCT = $('#card-country-timeline');
    cardCT.hidden = ctKeys.length <= 1;
    if (ctKeys.length > 1) {
      const series: Series[] = ctKeys.map((c) => ({
        key: c,
        label: c,
        color: ccSlots.color(c, t.series, t.other),
        points: bucketsToPoints(metrics.country_timeline?.[c]),
      }));
      lines($('#chart-country-timeline'), series, { label: 'Connections over time by country' });
    }

    renderEBPF(ebpf);
    renderTable(events);
  }

  function renderEBPF(stats: EBPFStats | null): void {
    const card = $('#card-ebpf');
    if (!stats || !stats.enabled) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const total = stats.packets_passed + stats.packets_dropped;
    const dropRatio = total > 0 ? stats.packets_dropped / total : 0;
    statTiles($('#ebpf-tiles'), [
      { label: 'Passed', value: fmtNum(stats.packets_passed) },
      { label: 'Dropped (banned)', value: fmtNum(stats.packets_dropped), tone: stats.packets_dropped > 0 ? 'critical' : 'default' },
    ]);
    meter($('#ebpf-meter'), dropRatio, { label: 'Dropped share of packets', valueText: `${(dropRatio * 100).toFixed(2)}%`, tone: 'critical' });
    const rows: Array<[string, string]> = [
      ['Mode', modeLabel(stats.mode)],
      ['Interface', stats.interface || '—'],
      ['Uptime', fmtUptime(stats.uptime_seconds)],
      ['Active bans', String(stats.bans_active)],
    ];
    $('#ebpf-kv').replaceChildren(
      ...rows.map(([k, v]) => el('div', { class: 'kv-row' }, [el('span', { class: 'kv-label', text: k }), el('span', { class: 'kv-value', text: v })])),
    );
  }

  function renderTable(events: ConnectionEvent[]): void {
    const tbody = $('#result-tbody');
    const frag = document.createDocumentFragment();
    for (const ev of events.slice(-200).reverse()) {
      frag.append(
        el('tr', {}, [
          el('td', { text: ev.time ? dateTimeFull(ev.time) : '' }),
          el('td', { class: 'hl', text: ev.src_ip }),
          el('td', { text: ev.src_city ?? '' }),
          el('td', { text: ev.src_cc ?? '' }),
          el('td', { class: 'hl', text: ev.dst_port }),
          el('td', { text: services.label(ev.dst_port) }),
          el('td', { text: ev.protocol ?? 'tcp' }),
        ]),
      );
    }
    tbody.replaceChildren(frag);
  }

  function clearFilters(): void {
    fCountry.value = '';
    fIp.value = '';
    fPort.value = '';
    fService.value = '';
    fPreset.value = '';
    setDefaultDates();
    last = null;
    showEmpty('Set filters above and press Query to explore connection history');
    summaryEl.textContent = '';
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    void runQuery();
  });
  btnClear.addEventListener('click', clearFilters);
  onThemeChange(() => {
    if (last) render();
  });
  let resizeTimer: ReturnType<typeof setTimeout> | null = null;
  window.addEventListener('resize', () => {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (last) render();
    }, 200);
  });

  setDefaultDates();
}

main();
