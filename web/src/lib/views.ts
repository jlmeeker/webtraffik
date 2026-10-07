// Saved search views: name + query, kept in localStorage (per browser only).

export interface SavedView {
  name: string;
  q: string;
}

export const VIEWS_KEY = 'wt_saved_views';
export const MAX_VIEWS = 30;

/** Defensive parse of whatever is in storage. */
export function parseViews(raw: string | null): SavedView[] {
  if (!raw) return [];
  try {
    const data: unknown = JSON.parse(raw);
    if (!Array.isArray(data)) return [];
    const out: SavedView[] = [];
    for (const v of data) {
      if (v && typeof v === 'object' && typeof (v as SavedView).name === 'string' && typeof (v as SavedView).q === 'string') {
        const name = (v as SavedView).name.trim().slice(0, 60);
        if (name) out.push({ name, q: (v as SavedView).q });
      }
    }
    return out.slice(0, MAX_VIEWS);
  } catch {
    return [];
  }
}

/** Insert or replace by (case-insensitive) name. */
export function upsertView(views: readonly SavedView[], v: SavedView): SavedView[] {
  const name = v.name.trim().slice(0, 60);
  if (!name) return views.slice();
  const rest = views.filter((x) => x.name.toLowerCase() !== name.toLowerCase());
  return [...rest, { name, q: v.q }].slice(-MAX_VIEWS);
}

export function deleteView(views: readonly SavedView[], name: string): SavedView[] {
  return views.filter((x) => x.name !== name);
}

export function loadViews(): SavedView[] {
  try {
    return parseViews(localStorage.getItem(VIEWS_KEY));
  } catch {
    return [];
  }
}

/** Returns false when storage is unavailable. */
export function storeViews(views: readonly SavedView[]): boolean {
  try {
    localStorage.setItem(VIEWS_KEY, JSON.stringify(views));
    return true;
  } catch {
    return false;
  }
}
