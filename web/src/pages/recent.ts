import '../styles/theme.css';
import '../styles/recent.css';
import '../styles/search.css';

import { api } from '../lib/api';
import { initChrome } from '../lib/chrome';
import { filterByQuery, hideObserved } from '../lib/match';
import { ServiceRegistry } from '../lib/services';
import type { ConnectionEvent } from '../lib/types';
import { $, el } from '../lib/utils/dom';
import { lsGet, lsSet } from '../lib/utils/prefs';
import { readUrlState, writeUrlState } from '../lib/urlstate';
import { dateShort, hexPreview } from '../lib/utils/format';
import { buildLogRow } from '../log';
import { filterRecent } from '../recent/filter';
import { SearchBox } from '../ui/searchbox';

const NOISE_PREF = 'wt_hide_observed';

function main(): void {
  initChrome();
  const services = new ServiceRegistry();

  const listEl = $('#event-list');
  const loadingEl = $('#loading');
  const emptyEl = $('#empty-state');
  const countEl = $('#event-count');
  const totalEl = $('#total-count');
  const refreshBtn = $<HTMLButtonElement>('#refresh-btn');
  const expandBtn = $<HTMLButtonElement>('#expand-all-btn');
  const serviceSel = $<HTMLSelectElement>('#filter-service');
  const limitSel = $<HTMLSelectElement>('#filter-limit');
  const dataChk = $<HTMLInputElement>('#filter-data');

  let allExpanded = false;
  let raw: ConnectionEvent[] = [];
  let hideNoise = lsGet(NOISE_PREF) !== '0';

  const searchbox = new SearchBox($('#searchbox'), {
    onSubmit: () => apply(),
    onChange: () => {
      writeUrlState({ q: searchbox.value });
      apply();
    },
    noiseToggle: {
      checked: hideNoise,
      onChange: (on) => {
        hideNoise = on;
        lsSet(NOISE_PREF, on ? '1' : '0');
        apply();
      },
    },
    getDynamicChips: () => {
      const count = (pick: (e: ConnectionEvent) => string[]) => {
        const m = new Map<string, number>();
        for (const e of raw) for (const v of pick(e)) m.set(v, (m.get(v) ?? 0) + 1);
        return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([k]) => k);
      };
      return { scanners: count((e) => (e.scanner ? [e.scanner] : [])), tags: count((e) => e.tags ?? []) };
    },
  });
  const initial = readUrlState(location.hash, location.search).q;
  if (initial) searchbox.setValue(initial);

  function buildRow(ev: ConnectionEvent): HTMLElement {
    const row = buildLogRow(ev, services, { withDate: dateShort(ev.time) });
    if (ev.client_data) {
      const hint = el('button', { class: 'log-data-hint', type: 'button', 'aria-expanded': 'false', text: 'data' });
      const block = el('pre', { class: 'log-client-data', text: hexPreview(ev.client_data) });
      hint.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = row.classList.toggle('expanded');
        hint.setAttribute('aria-expanded', String(open));
      });
      row.append(hint, block);
      if (allExpanded) {
        row.classList.add('expanded');
        hint.setAttribute('aria-expanded', 'true');
      }
    }
    return row;
  }

  function apply(): void {
    const svc = serviceSel.value;
    const searched = hideObserved(filterByQuery(raw, searchbox.value), hideNoise);
    const filtered = filterRecent(searched, {
      onlyWithData: dataChk.checked,
      ports: svc ? services.portsFor(svc) : undefined,
      limit: parseInt(limitSel.value, 10) || 1000,
    });
    countEl.textContent = String(filtered.length);
    totalEl.textContent = String(raw.length);
    if (filtered.length === 0) {
      emptyEl.hidden = false;
      emptyEl.textContent = raw.length === 0 ? 'No events in the ring buffer yet.' : 'No events match the current filter.';
      listEl.replaceChildren();
      return;
    }
    emptyEl.hidden = true;
    const frag = document.createDocumentFragment();
    for (let i = filtered.length - 1; i >= 0; i--) frag.append(buildRow(filtered[i]!));
    listEl.replaceChildren(frag);
  }

  async function fetchRecent(): Promise<void> {
    loadingEl.hidden = false;
    emptyEl.hidden = true;
    refreshBtn.disabled = true;
    try {
      const data = await api.recent();
      raw = Array.isArray(data) ? data : [];
      await services.ready;
      searchbox.refreshQuick();
      apply();
    } catch (err) {
      raw = [];
      listEl.replaceChildren();
      emptyEl.textContent = `Failed to load events: ${err instanceof Error ? err.message : String(err)}`;
      emptyEl.hidden = false;
    } finally {
      loadingEl.hidden = true;
      refreshBtn.disabled = false;
    }
  }

  void services.ready.then(() => {
    for (const s of services.list()) serviceSel.append(el('option', { value: s.name, text: s.name }));
  });

  refreshBtn.addEventListener('click', () => void fetchRecent());
  serviceSel.addEventListener('change', apply);
  limitSel.addEventListener('change', apply);
  dataChk.addEventListener('change', apply);
  expandBtn.addEventListener('click', () => {
    allExpanded = !allExpanded;
    expandBtn.textContent = allExpanded ? 'Collapse all data' : 'Expand all data';
    expandBtn.setAttribute('aria-pressed', String(allExpanded));
    for (const row of listEl.querySelectorAll<HTMLElement>('.log-entry')) {
      if (row.querySelector('.log-client-data')) {
        row.classList.toggle('expanded', allExpanded);
        row.querySelector('.log-data-hint')?.setAttribute('aria-expanded', String(allExpanded));
      }
    }
  });

  void fetchRecent();
}

if (typeof document !== 'undefined' && document.getElementById('event-list')) main();
