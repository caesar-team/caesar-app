import { t } from "../i18n.js";

/**
 * What to tell the viewer about the link after this page opened it. `viewsLeftBefore` is
 * what the meta reported before the blob download (the blob response carries no count);
 * null means unlimited, so there is nothing to say. `spent` is shown only when that
 * download took the last view.
 */
export function viewsNote(viewsLeftBefore: number | null, spent: string): string | null {
  if (viewsLeftBefore === null) {
    return null;
  }
  const left = viewsLeftBefore - 1;
  return left > 0 ? t("view.views_left", { n: left }) : spent;
}
