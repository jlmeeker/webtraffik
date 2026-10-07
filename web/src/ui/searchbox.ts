import {
  addTerm,
  applySuggestion,
  CLASS_VALUES,
  KEY_HINTS,
  KIND_VALUES,
  kv,
  parseQuery,
  QUERY_KEYS,
  removeTerm,
  serializeTerm,
  suggestAt,
  toggleTerm,
  type SuggestResult,
  type Term,
} from '../lib/query';
import { deleteView, loadViews, storeViews, upsertView, type SavedView } from '../lib/views';
import { el } from '../lib/utils/dom';

export interface SearchBoxOptions {
  /** Run the search (Enter, chip click, saved view). */
  onSubmit: (q: string) => void;
  /** Called on every edit (live validation / URL sync). */
  onChange?: (q: string) => void;
  /** Dynamic quick-filter values, usually derived from the loaded events. */
  getDynamicChips?: () => { scanners: string[]; tags: string[] };
  /** Optional "hide XDP-only noise" checkbox shown beside the box. */
  noiseToggle?: { checked: boolean; onChange: (on: boolean) => void };
  placeholder?: string;
}

const MAX_DYNAMIC = 8;

/**
 * Search input with key/value autocomplete (ARIA combobox), inline syntax help,
 * removable filter chips, quick-filter toggles and localStorage saved views.
 * One instance per page (ids are fixed).
 */
export class SearchBox {
  readonly input: HTMLInputElement;
  private readonly list: HTMLUListElement;
  private readonly errorEl: HTMLElement;
  private readonly helpEl: HTMLElement;
  private readonly helpBtn: HTMLButtonElement;
  private readonly chipsEl: HTMLElement;
  private readonly quickEl: HTMLElement;
  private readonly viewsEl: HTMLElement;
  private readonly viewName: HTMLInputElement;
  private readonly viewMsg: HTMLElement;
  private suggest: SuggestResult = { start: 0, end: 0, items: [] };
  private active = -1;
  private views: SavedView[] = loadViews();

  constructor(
    readonly root: HTMLElement,
    private readonly opts: SearchBoxOptions,
  ) {
    root.classList.add('searchbox');
    this.input = el('input', {
      id: 'sb-input',
      class: 'input sb-input',
      type: 'text',
      role: 'combobox',
      'aria-autocomplete': 'list',
      'aria-expanded': 'false',
      'aria-controls': 'sb-list',
      'aria-describedby': 'sb-error',
      autocomplete: 'off',
      autocapitalize: 'off',
      spellcheck: 'false',
      placeholder: opts.placeholder ?? 'port:22 cc:CN -tag:scanner:zgrab "login failed"',
    });
    this.list = el('ul', { id: 'sb-list', class: 'sb-list', role: 'listbox', 'aria-label': 'Suggestions' });
    this.list.hidden = true;
    this.errorEl = el('div', { id: 'sb-error', class: 'sb-error', role: 'alert' });
    this.errorEl.hidden = true;
    this.helpEl = this.buildHelp();
    this.helpEl.hidden = true;
    this.helpBtn = el('button', { class: 'btn ghost', type: 'button', 'aria-expanded': 'false', 'aria-controls': 'sb-help', text: 'Syntax' });
    this.chipsEl = el('div', { class: 'sb-chips', role: 'group', 'aria-label': 'Active filters' });
    this.quickEl = el('div', { class: 'sb-quick', role: 'group', 'aria-label': 'Quick filters' });
    this.viewName = el('input', { class: 'input sb-view-name', type: 'text', maxlength: '60', placeholder: 'View name', 'aria-label': 'Name for the saved view' });
    this.viewMsg = el('span', { class: 'sb-view-msg', role: 'status' });
    this.viewsEl = el('div', { class: 'sb-view-list', role: 'list', 'aria-label': 'Saved views' });

    const label = el('label', { class: 'visually-hidden', for: 'sb-input', text: 'Search events' });
    const combo = el('div', { class: 'sb-combo' }, [this.input, this.list]);
    const row = el('div', { class: 'sb-row' }, [label, combo]);
    const goBtn = el('button', { class: 'btn primary sb-go', type: 'button', text: 'Search' });
    row.append(goBtn, this.helpBtn);
    if (opts.noiseToggle) row.append(this.buildNoiseToggle(opts.noiseToggle));

    const saveBtn = el('button', { class: 'btn', type: 'button', text: 'Save view' });
    const viewsRow = el('div', { class: 'sb-views' }, [el('span', { class: 'sb-label', text: 'Saved views' }), this.viewName, saveBtn, this.viewMsg, this.viewsEl]);

    root.append(row, this.errorEl, this.helpEl, this.chipsEl, this.quickEl, viewsRow);

    this.input.addEventListener('input', () => this.onInput());
    this.input.addEventListener('keydown', (e) => this.onKey(e));
    this.input.addEventListener('blur', () => setTimeout(() => this.closeList(), 120));
    this.input.addEventListener('click', () => this.refreshSuggest());
    goBtn.addEventListener('click', () => this.submit());
    this.helpBtn.addEventListener('click', () => {
      const open = this.helpEl.hidden;
      this.helpEl.hidden = !open;
      this.helpBtn.setAttribute('aria-expanded', String(open));
    });
    saveBtn.addEventListener('click', () => this.saveView());
    this.viewName.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        this.saveView();
      }
    });

    this.renderChips();
    this.renderQuick();
    this.renderViews();
  }

  get value(): string {
    return this.input.value.trim();
  }

  /** Replace the query text. `submit` also runs the search. */
  setValue(q: string, submit = false): void {
    this.input.value = q;
    this.setError(null);
    this.closeList();
    this.afterEdit();
    if (submit) this.submit();
  }

  setError(msg: string | null): void {
    this.errorEl.hidden = !msg;
    this.errorEl.textContent = msg ?? '';
    this.input.setAttribute('aria-invalid', msg ? 'true' : 'false');
  }

  /** Rebuild quick filters after new events were loaded. */
  refreshQuick(): void {
    this.renderQuick();
  }

  /** Add (or ensure) a term and run the search. */
  applyTerms(terms: readonly Term[]): void {
    let q = this.input.value;
    for (const t of terms) q = addTerm(q, t);
    this.setValue(q, true);
  }

  focus(): void {
    this.input.focus();
  }

  // ── internals ─────────────────────────────────────────────────────────────

  private submit(): void {
    this.closeList();
    const q = this.value;
    const { error } = parseQuery(q);
    this.setError(error);
    if (error) return;
    this.opts.onSubmit(q);
  }

  private afterEdit(): void {
    this.renderChips();
    this.renderQuick();
    this.opts.onChange?.(this.value);
  }

  private onInput(): void {
    // Hide a stale server error as soon as the user edits.
    if (!this.errorEl.hidden) this.setError(null);
    this.refreshSuggest();
    this.afterEdit();
  }

  private refreshSuggest(): void {
    const caret = this.input.selectionStart ?? this.input.value.length;
    this.suggest = suggestAt(this.input.value, caret);
    this.active = -1;
    this.renderList();
  }

  private renderList(): void {
    const items = this.suggest.items;
    this.list.replaceChildren();
    items.forEach((s, i) => {
      const li = el('li', { id: `sb-opt-${i}`, class: 'sb-opt', role: 'option', 'aria-selected': String(i === this.active) }, [
        el('span', { class: 'sb-opt-label', text: s.label }),
        el('span', { class: 'sb-opt-hint', text: s.hint }),
      ]);
      li.addEventListener('mousedown', (e) => {
        e.preventDefault();
        this.pick(i);
      });
      this.list.append(li);
    });
    const open = items.length > 0;
    this.list.hidden = !open;
    this.input.setAttribute('aria-expanded', String(open));
    if (this.active >= 0) this.input.setAttribute('aria-activedescendant', `sb-opt-${this.active}`);
    else this.input.removeAttribute('aria-activedescendant');
  }

  private closeList(): void {
    this.suggest = { start: 0, end: 0, items: [] };
    this.active = -1;
    this.renderList();
  }

  private pick(i: number): void {
    const s = this.suggest.items[i];
    if (!s) return;
    const r = applySuggestion(this.input.value, this.suggest, s);
    this.input.value = r.text;
    this.input.setSelectionRange(r.caret, r.caret);
    this.input.focus();
    this.onInput();
  }

  private onKey(e: KeyboardEvent): void {
    const n = this.suggest.items.length;
    if (e.key === 'ArrowDown' && n > 0) {
      e.preventDefault();
      this.active = (this.active + 1) % n;
      this.renderList();
    } else if (e.key === 'ArrowUp' && n > 0) {
      e.preventDefault();
      this.active = (this.active - 1 + n) % n;
      this.renderList();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (this.active >= 0) this.pick(this.active);
      else this.submit();
    } else if (e.key === 'Tab' && this.active >= 0) {
      e.preventDefault();
      this.pick(this.active);
    } else if (e.key === 'Escape' && n > 0) {
      e.preventDefault();
      this.closeList();
    }
  }

  private buildHelp(): HTMLElement {
    const rows = QUERY_KEYS.map((k) => el('div', { class: 'sb-help-row' }, [el('code', { text: `${k}:` }), el('span', { text: KEY_HINTS[k] })]));
    return el('div', { id: 'sb-help', class: 'sb-help' }, [
      el('p', {
        text: 'Separate terms with spaces; all terms must match. Use key:value, a leading - to exclude (-cc:US), and "double quotes" for phrases or values with spaces. Bare words match detail, ASN org, city and metadata.',
      }),
      el('div', { class: 'sb-help-grid' }, rows),
      el('p', { class: 'sb-help-eg' }, [
        'Example: ',
        el('code', { text: 'port:22 -cc:US since:24h "root password"' }),
      ]),
    ]);
  }

  private buildNoiseToggle(cfg: NonNullable<SearchBoxOptions['noiseToggle']>): HTMLElement {
    const box = el('input', { type: 'checkbox', id: 'filter-noise' });
    box.checked = cfg.checked;
    box.addEventListener('change', () => cfg.onChange(box.checked));
    return el('label', { class: 'check sb-noise', title: 'Hide connections that were only seen by XDP (kind:observed)' }, [box, ' hide XDP-only noise']);
  }

  private renderChips(): void {
    const { terms } = parseQuery(this.input.value);
    this.chipsEl.hidden = terms.length === 0;
    this.chipsEl.replaceChildren(
      ...terms.map((t) => {
        const text = serializeTerm(t);
        const chip = el('button', { class: `chip${t.neg ? ' neg' : ''}`, type: 'button', 'aria-label': `Remove filter ${text}` }, [
          el('span', { class: 'chip-text', text }),
          el('span', { class: 'chip-x', 'aria-hidden': 'true', text: '×' }),
        ]);
        chip.addEventListener('click', () => {
          this.input.value = removeTerm(this.input.value, t);
          this.afterEdit();
          this.submit();
        });
        return chip;
      }),
    );
  }

  private quickGroup(title: string, key: 'kind' | 'class' | 'scanner' | 'tag', values: readonly string[]): HTMLElement | null {
    if (values.length === 0) return null;
    const { terms } = parseQuery(this.input.value);
    const group = el('span', { class: 'sb-qgroup', role: 'group', 'aria-label': title }, [el('span', { class: 'sb-label', text: title })]);
    for (const v of values) {
      const t = kv(key, v);
      const on = terms.some((x) => x.key === key && !x.neg && x.value.toLowerCase() === v.toLowerCase());
      const b = el('button', { class: 'chip toggle', type: 'button', 'aria-pressed': String(on), text: v });
      b.addEventListener('click', () => {
        this.input.value = toggleTerm(this.input.value, t);
        this.afterEdit();
        this.submit();
      });
      group.append(b);
    }
    return group;
  }

  private renderQuick(): void {
    const dyn = this.opts.getDynamicChips?.() ?? { scanners: [], tags: [] };
    const groups = [
      this.quickGroup('Kind', 'kind', KIND_VALUES),
      this.quickGroup('Class', 'class', CLASS_VALUES),
      this.quickGroup('Scanner', 'scanner', dyn.scanners.slice(0, MAX_DYNAMIC)),
      this.quickGroup('Tag', 'tag', dyn.tags.slice(0, MAX_DYNAMIC)),
    ].filter((g): g is HTMLElement => g !== null);
    this.quickEl.replaceChildren(...groups);
  }

  private saveView(): void {
    const name = this.viewName.value.trim();
    const q = this.value;
    if (!name) {
      this.viewMsg.textContent = 'Enter a name first.';
      this.viewName.focus();
      return;
    }
    if (!q) {
      this.viewMsg.textContent = 'Nothing to save: the search is empty.';
      return;
    }
    this.views = upsertView(this.views, { name, q });
    const ok = storeViews(this.views);
    this.viewMsg.textContent = ok ? `Saved "${name}".` : 'Saved for this page only: browser storage is unavailable.';
    this.viewName.value = '';
    this.renderViews();
  }

  private renderViews(): void {
    this.viewsEl.replaceChildren(
      ...this.views.map((v) => {
        const apply = el('button', { class: 'chip view-apply', type: 'button', title: v.q, text: v.name });
        apply.addEventListener('click', () => this.setValue(v.q, true));
        const del = el('button', { class: 'chip view-del', type: 'button', 'aria-label': `Delete saved view ${v.name}`, text: '×' });
        del.addEventListener('click', () => {
          this.views = deleteView(this.views, v.name);
          storeViews(this.views);
          this.viewMsg.textContent = `Deleted "${v.name}".`;
          this.renderViews();
        });
        return el('span', { class: 'sb-view', role: 'listitem' }, [apply, del]);
      }),
    );
  }
}
