import { barPercents, campaignIpCount, normalizeCampaigns, normalizeTop, TOP_DIMS, TOP_HOURS, trend } from '../history/top';
import { api, isUnsupported } from '../lib/api';
import { kv, termsForTop, type Term } from '../lib/query';
import type { Campaign } from '../lib/types';
import { $, el } from '../lib/utils/dom';
import { fmtNum, formatTimeAgo } from '../lib/utils/format';

export interface InsightsActions {
  /** Apply search terms; `hours` is the Top window so the page can match its range. */
  applyTerms: (terms: Term[], hours?: number) => void;
}

const MAX_CAMPAIGN_IPS = 25;
const CAMPAIGN_HOURS = [
  { hours: 24, label: '24h' },
  { hours: 72, label: '72h' },
  { hours: 168, label: '7d' },
];

/**
 * "Top" (ranked dimensions with bars and trend) and "Campaigns" tabs. Each tab
 * hides itself when its endpoint is missing; the whole section hides when both are.
 */
export class InsightsPanel {
  private readonly root: HTMLElement;
  private readonly tabTop: HTMLButtonElement;
  private readonly tabCamp: HTMLButtonElement;
  private readonly panelTop: HTMLElement;
  private readonly panelCamp: HTMLElement;
  private readonly topList: HTMLElement;
  private readonly topMsg: HTMLElement;
  private readonly campList: HTMLElement;
  private readonly campMsg: HTMLElement;
  private readonly dimSel: HTMLSelectElement;
  private readonly campHoursSel: HTMLSelectElement;
  private hours = 24;
  private topSupported = true;
  private campSupported = true;
  private seq = { top: 0, camp: 0 };

  constructor(
    rootSelector: string,
    private readonly actions: InsightsActions,
  ) {
    this.root = $(rootSelector);
    this.tabTop = $<HTMLButtonElement>('#tab-top', this.root);
    this.tabCamp = $<HTMLButtonElement>('#tab-campaigns', this.root);
    this.panelTop = $('#panel-top', this.root);
    this.panelCamp = $('#panel-campaigns', this.root);
    this.topList = $('#top-list', this.root);
    this.topMsg = $('#top-msg', this.root);
    this.campList = $('#camp-list', this.root);
    this.campMsg = $('#camp-msg', this.root);
    this.dimSel = $<HTMLSelectElement>('#top-by', this.root);
    this.campHoursSel = $<HTMLSelectElement>('#camp-hours', this.root);

    for (const d of TOP_DIMS) this.dimSel.append(el('option', { value: d.id, text: d.label }));
    for (const h of CAMPAIGN_HOURS) this.campHoursSel.append(el('option', { value: String(h.hours), text: h.label }));
    this.dimSel.value = 'asns';
    this.campHoursSel.value = '72';

    const seg = $('#top-hours', this.root);
    for (const h of TOP_HOURS) {
      const b = el('button', { class: 'btn seg', type: 'button', 'aria-pressed': String(h.hours === this.hours), 'data-hours': String(h.hours), text: h.label });
      b.addEventListener('click', () => {
        this.hours = h.hours;
        for (const x of seg.querySelectorAll('button')) x.setAttribute('aria-pressed', String(x === b));
        void this.loadTop();
      });
      seg.append(b);
    }

    this.dimSel.addEventListener('change', () => void this.loadTop());
    this.campHoursSel.addEventListener('change', () => void this.loadCampaigns());
    this.tabTop.addEventListener('click', () => this.select('top'));
    this.tabCamp.addEventListener('click', () => this.select('campaigns'));
    const keyNav = (e: KeyboardEvent) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight' && e.key !== 'Home' && e.key !== 'End') return;
      const tabs = [this.tabTop, this.tabCamp].filter((t) => !t.hidden);
      const i = tabs.indexOf(e.currentTarget as HTMLButtonElement);
      if (i === -1 || tabs.length < 2) return;
      e.preventDefault();
      const next = e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      const tab = tabs[next]!;
      tab.focus();
      this.select(tab === this.tabTop ? 'top' : 'campaigns');
    };
    this.tabTop.addEventListener('keydown', keyNav);
    this.tabCamp.addEventListener('keydown', keyNav);
  }

  start(): void {
    void this.loadTop();
    void this.loadCampaigns();
  }

  private select(which: 'top' | 'campaigns'): void {
    const top = which === 'top';
    this.tabTop.setAttribute('aria-selected', String(top));
    this.tabCamp.setAttribute('aria-selected', String(!top));
    this.tabTop.tabIndex = top ? 0 : -1;
    this.tabCamp.tabIndex = top ? -1 : 0;
    this.panelTop.hidden = !top;
    this.panelCamp.hidden = top;
  }

  private refreshVisibility(): void {
    this.tabTop.hidden = !this.topSupported;
    this.tabCamp.hidden = !this.campSupported;
    this.root.hidden = !this.topSupported && !this.campSupported;
    if (!this.topSupported && this.campSupported) this.select('campaigns');
    else if (this.topSupported && !this.campSupported) this.select('top');
  }

  // ── Top ───────────────────────────────────────────────────────────────────

  private async loadTop(): Promise<void> {
    const my = ++this.seq.top;
    const by = this.dimSel.value;
    this.topMsg.textContent = 'Loading…';
    this.topList.setAttribute('aria-busy', 'true');
    try {
      const data = await api.top(by, this.hours, 10);
      if (my !== this.seq.top) return;
      this.renderTop(by, normalizeTop(data));
    } catch (err) {
      if (my !== this.seq.top) return;
      if (isUnsupported(err)) {
        this.topSupported = false;
        this.refreshVisibility();
        return;
      }
      this.topList.replaceChildren();
      this.topMsg.textContent = `Could not load: ${err instanceof Error ? err.message : String(err)}`;
    } finally {
      if (my === this.seq.top) this.topList.removeAttribute('aria-busy');
    }
    this.refreshVisibility();
  }

  private renderTop(by: string, items: ReturnType<typeof normalizeTop>): void {
    this.topMsg.textContent = items.length === 0 ? 'Nothing recorded in this window.' : '';
    const widths = barPercents(items);
    const rows = items.map((it, i) => {
      const t = trend(it);
      const row = el('button', { class: 'top-row', type: 'button' });
      const bar = el('span', { class: 'top-bar', 'aria-hidden': 'true' });
      bar.style.width = `${widths[i]}%`;
      row.append(
        bar,
        el('span', { class: 'top-rank', 'aria-hidden': 'true', text: String(i + 1) }),
        el('span', { class: 'top-key', title: it.key, text: it.key }),
        el('span', { class: 'top-count', text: fmtNum(it.count) }),
        el('span', { class: 'top-ips', title: 'Unique source IPs', text: it.ips !== undefined ? `${fmtNum(it.ips)} IPs` : '' }),
        el('span', { class: `top-trend ${t.dir}`, title: it.prev !== undefined ? `Previous period: ${fmtNum(it.prev)}` : '', text: t.text }),
      );
      row.setAttribute(
        'aria-label',
        `${it.key}: ${fmtNum(it.count)} events${it.ips !== undefined ? `, ${fmtNum(it.ips)} unique IPs` : ''}${t.aria ? `, ${t.aria}` : ''}. Apply as search filter.`,
      );
      row.addEventListener('click', () => this.actions.applyTerms(termsForTop(by, it.key), this.hours));
      return el('li', {}, [row]);
    });
    this.topList.replaceChildren(...rows);
  }

  // ── Campaigns ─────────────────────────────────────────────────────────────

  private async loadCampaigns(): Promise<void> {
    const my = ++this.seq.camp;
    this.campMsg.textContent = 'Loading…';
    try {
      const data = await api.campaigns(parseInt(this.campHoursSel.value, 10) || 72, 20);
      if (my !== this.seq.camp) return;
      this.renderCampaigns(normalizeCampaigns(data));
    } catch (err) {
      if (my !== this.seq.camp) return;
      if (isUnsupported(err)) {
        this.campSupported = false;
        this.refreshVisibility();
        return;
      }
      this.campList.replaceChildren();
      this.campMsg.textContent = `Could not load: ${err instanceof Error ? err.message : String(err)}`;
    }
    this.refreshVisibility();
  }

  private renderCampaigns(list: Campaign[]): void {
    this.campMsg.textContent = list.length === 0 ? 'No campaigns detected in this window.' : '';
    this.campList.replaceChildren(...list.map((c, i) => this.campaignItem(c, i)));
  }

  private campaignItem(c: Campaign, idx: number): HTMLElement {
    const bodyId = `camp-body-${idx}`;
    const head = el('button', { class: 'camp-head', type: 'button', 'aria-expanded': 'false', 'aria-controls': bodyId });
    const ipTotal = campaignIpCount(c);
    head.append(
      el('span', { class: 'camp-caret', 'aria-hidden': 'true', text: '▸' }),
      el('span', { class: 'camp-label', title: c.label, text: c.label }),
      el('span', { class: 'camp-stat', text: `${fmtNum(ipTotal)} IPs` }),
      el('span', { class: 'camp-stat', text: `${fmtNum(c.events ?? 0)} events` }),
      el('span', { class: 'camp-meta', text: [(c.ports ?? []).slice(0, 6).join(', '), (c.countries ?? []).join(' ')].filter(Boolean).join(' · ') }),
      el('span', { class: 'camp-meta', text: c.last_seen ? `last ${formatTimeAgo(c.last_seen)}` : '' }),
    );

    const body = el('div', { id: bodyId, class: 'camp-body' });
    body.hidden = true;
    const detail = el('dl', { class: 'camp-dl' });
    const add = (k: string, v: string) => {
      if (v) detail.append(el('dt', { text: k }), el('dd', { text: v }));
    };
    add('Ports', (c.ports ?? []).join(', '));
    add('Countries', (c.countries ?? []).join(', '));
    add('Tags', (c.tags ?? []).join(', '));
    add('First seen', c.first_seen ? new Date(c.first_seen).toLocaleString() : '');
    add('Last seen', c.last_seen ? new Date(c.last_seen).toLocaleString() : '');
    body.append(detail);

    const ips = c.ips ?? [];
    const shown = ips.slice(0, MAX_CAMPAIGN_IPS);
    if (shown.length > 0) {
      const ipList = el('ul', { class: 'camp-ips', 'aria-label': `IPs in campaign ${c.label}` });
      for (const ip of shown) {
        const b = el('button', { class: 'chip', type: 'button', title: `Search ip:${ip}`, text: ip });
        b.addEventListener('click', () => this.actions.applyTerms([kv('ip', ip)]));
        ipList.append(el('li', {}, [b]));
      }
      body.append(ipList);
      const more = ipTotal - shown.length;
      const apply = el('button', { class: 'btn primary', type: 'button', text: `Search ${shown.length === 1 ? 'this IP' : `these ${shown.length} IPs`}` });
      apply.addEventListener('click', () => this.actions.applyTerms(shown.map((ip) => kv('ip', ip))));
      body.append(apply);
      if (more > 0) body.append(el('span', { class: 'camp-more', text: `${fmtNum(more)} more not listed` }));
    } else {
      body.append(el('p', { class: 'camp-more', text: 'No IP list available for this campaign.' }));
    }

    head.addEventListener('click', () => {
      const open = body.hidden;
      body.hidden = !open;
      head.setAttribute('aria-expanded', String(open));
    });
    return el('li', { class: 'camp' }, [head, body]);
  }
}
