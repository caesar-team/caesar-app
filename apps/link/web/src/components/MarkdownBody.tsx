import { renderMarkdown } from "../lib/markdown.js";

/**
 * Split out so `React.lazy` can code-split it: the unified/remark/rehype pipeline is
 * ~47 kB gzipped and only a Markdown attachment needs it. Text and PDF shares never load
 * this chunk. Exported by name — the lazy() call maps it to `default` at the import site.
 */
export function MarkdownBody({ source }: { source: string }) {
  return <>{renderMarkdown(source)}</>;
}
