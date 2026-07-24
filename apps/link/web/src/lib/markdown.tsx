import type { CSSProperties, ReactNode } from "react";
import { Fragment, jsx, jsxs } from "react/jsx-runtime";
import rehypeReact from "rehype-react";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";
import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import remarkRehype from "remark-rehype";
import { unified } from "unified";

/**
 * Markdown rendering for shared attachments — CommonMark + GFM via the unified pipeline.
 *
 * The content is authored by whoever created the link. From the recipient's side it is
 * untrusted input, and this page holds both the decrypted plaintext and the data key (in
 * `location.hash`), so script running here could exfiltrate both. Two deliberate choices
 * follow from that:
 *
 * - **No `rehype-raw`.** Without `allowDangerousHtml`, `remark-rehype` drops raw HTML
 *   nodes outright, so `<img onerror=…>` in the source never becomes an element.
 * - **No HTML string.** `rehype-react` produces React elements directly, so there is no
 *   `dangerouslySetInnerHTML` anywhere in the path. `rehype-sanitize` still runs as the
 *   belt to that suspenders, and its schema is what rejects `javascript:`/`data:` hrefs.
 */

const styles: Record<string, CSSProperties> = {
  h1: { fontSize: 19, fontWeight: 650, margin: "0 0 10px", letterSpacing: "-.02em" },
  h2: { fontSize: 16, fontWeight: 600, margin: "18px 0 8px", letterSpacing: "-.01em" },
  h3: { fontSize: 14.5, fontWeight: 600, margin: "16px 0 6px" },
  p: { margin: "0 0 10px", lineHeight: 1.62, wordBreak: "break-word" },
  hr: { border: 0, borderTop: "1px solid var(--line)", margin: "16px 0" },
  list: { margin: "0 0 10px", paddingLeft: 20, lineHeight: 1.62 },
  li: { margin: "2px 0" },
  pre: {
    margin: "0 0 12px",
    padding: "10px 12px",
    borderRadius: 10,
    background: "var(--surface-2)",
    border: "1px solid var(--line)",
    overflowX: "auto",
    fontSize: 12.5,
    lineHeight: 1.5,
  },
  code: {
    background: "var(--surface-2)",
    border: "1px solid var(--line)",
    borderRadius: 5,
    padding: "1px 5px",
    fontSize: "0.92em",
  },
  quote: {
    margin: "0 0 10px",
    padding: "2px 0 2px 12px",
    borderLeft: "2px solid var(--line)",
    color: "var(--fg-2)",
  },
  tableWrap: { overflowX: "auto", margin: "0 0 12px" },
  table: { borderCollapse: "collapse", fontSize: 13.5, width: "100%" },
  cell: { border: "1px solid var(--line)", padding: "6px 10px", textAlign: "left" },
  th: {
    border: "1px solid var(--line)",
    padding: "6px 10px",
    textAlign: "left",
    fontWeight: 600,
    background: "var(--surface-2)",
  },
};

/** `defaultSchema` already restricts href protocols; keep it and drop attributes we style. */
const schema = {
  ...defaultSchema,
  attributes: {
    ...defaultSchema.attributes,
    // We set target/rel ourselves in the anchor component below.
    a: [...(defaultSchema.attributes?.a ?? [])].filter(
      (attr) => attr !== "target" && attr !== "rel"
    ),
  },
};

type Props = { children?: ReactNode };

const components = {
  h1: (p: Props) => <h1 style={styles.h1}>{p.children}</h1>,
  h2: (p: Props) => <h2 style={styles.h2}>{p.children}</h2>,
  h3: (p: Props) => <h3 style={styles.h3}>{p.children}</h3>,
  h4: (p: Props) => <h3 style={styles.h3}>{p.children}</h3>,
  p: (p: Props) => <p style={styles.p}>{p.children}</p>,
  hr: () => <hr style={styles.hr} />,
  ul: (p: Props) => <ul style={styles.list}>{p.children}</ul>,
  ol: (p: Props) => <ol style={styles.list}>{p.children}</ol>,
  li: (p: Props) => <li style={styles.li}>{p.children}</li>,
  blockquote: (p: Props) => <blockquote style={styles.quote}>{p.children}</blockquote>,
  pre: (p: Props) => (
    <pre className="mono" style={styles.pre}>
      {p.children}
    </pre>
  ),
  code: (p: Props) => (
    <code className="mono" style={styles.code}>
      {p.children}
    </code>
  ),
  table: (p: Props) => (
    <div style={styles.tableWrap}>
      <table style={styles.table}>{p.children}</table>
    </div>
  ),
  th: (p: Props) => <th style={styles.th}>{p.children}</th>,
  td: (p: Props) => <td style={styles.cell}>{p.children}</td>,
  a: (p: Props & { href?: string }) =>
    p.href === undefined ? (
      // rehype-sanitize strips the href of an unsafe protocol (javascript:, data:…) but
      // leaves the element. Render the label as text rather than a dead anchor.
      <span>{p.children}</span>
    ) : (
      <a href={p.href} target="_blank" rel="noopener noreferrer nofollow">
        {p.children}
      </a>
    ),
};

const processor = unified()
  .use(remarkParse)
  .use(remarkGfm)
  // No allowDangerousHtml: raw HTML in the source is dropped rather than passed through.
  .use(remarkRehype)
  .use(rehypeSanitize, schema)
  .use(rehypeReact, { Fragment, jsx, jsxs, components });

export function renderMarkdown(source: string): ReactNode {
  return processor.processSync(source).result as ReactNode;
}
