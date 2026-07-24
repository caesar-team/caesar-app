/**
 * Attachment sniffing. Kept free of the Markdown pipeline on purpose: `View` needs these
 * to decide *whether* to render, and importing them must not drag the unified stack into
 * the main bundle — that lives behind a lazy chunk (see `components/MarkdownBody.tsx`).
 */

export function isMarkdown(name: string, mime: string): boolean {
  return mime === "text/markdown" || mime === "text/x-markdown" || /\.(md|markdown)$/i.test(name);
}

export function isPDF(name: string, mime: string): boolean {
  return mime === "application/pdf" || /\.pdf$/i.test(name);
}
