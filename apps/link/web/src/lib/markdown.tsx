import type { CSSProperties, ReactNode } from "react";

/**
 * Minimal Markdown renderer for shared attachments.
 *
 * Deliberately **not** a Markdown library. The content comes from whoever created the
 * link — from the recipient's point of view it is untrusted input, and this page holds
 * both the decrypted plaintext and the data key (in `location.hash`). A renderer that
 * produced an HTML string would put an XSS hole exactly where it hurts most.
 *
 * This builds React elements instead, so markup in the source can never become markup on
 * the page: it is escaped by React by construction. Link targets are additionally limited
 * to http/https/mailto so `javascript:` cannot slip through.
 *
 * Supported: ATX headings, `---`, fenced and inline code, bold, italic, links, unordered
 * and ordered lists, blockquotes, paragraphs. Anything else renders as plain text.
 */

const SAFE_SCHEME = /^(https?:|mailto:)/i;

const styles: Record<string, CSSProperties> = {
  h1: { fontSize: 19, fontWeight: 650, margin: "0 0 10px", letterSpacing: "-.02em" },
  h2: { fontSize: 16, fontWeight: 600, margin: "18px 0 8px", letterSpacing: "-.01em" },
  h3: { fontSize: 14.5, fontWeight: 600, margin: "16px 0 6px" },
  p: { margin: "0 0 10px", lineHeight: 1.62, wordBreak: "break-word" },
  hr: { border: 0, borderTop: "1px solid var(--line)", margin: "16px 0" },
  ul: { margin: "0 0 10px", paddingLeft: 20, lineHeight: 1.62 },
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
};

/** Splits a line into bold / italic / code / link runs. Order matters: code wins first. */
function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const pattern =
    /(`[^`]+`)|(\*\*[^*]+\*\*)|(__[^_]+__)|(\*[^*\n]+\*)|(_[^_\n]+_)|(\[[^\]]+\]\([^)\s]+\))/g;
  const out: ReactNode[] = [];
  let last = 0;
  let match = pattern.exec(text);
  let index = 0;

  while (match !== null) {
    if (match.index > last) out.push(text.slice(last, match.index));
    const token = match[0];
    const key = `${keyPrefix}-i${index++}`;

    if (token.startsWith("`")) {
      out.push(
        <code key={key} className="mono" style={styles.code}>
          {token.slice(1, -1)}
        </code>
      );
    } else if (token.startsWith("**") || token.startsWith("__")) {
      out.push(<strong key={key}>{token.slice(2, -2)}</strong>);
    } else if (token.startsWith("[")) {
      const split = token.indexOf("](");
      const label = token.slice(1, split);
      const href = token.slice(split + 2, -1);
      out.push(
        SAFE_SCHEME.test(href) ? (
          <a key={key} href={href} target="_blank" rel="noopener noreferrer nofollow">
            {label}
          </a>
        ) : (
          // Unsafe or relative scheme: show the label, drop the target entirely.
          <span key={key}>{label}</span>
        )
      );
    } else {
      out.push(<em key={key}>{token.slice(1, -1)}</em>);
    }

    last = match.index + token.length;
    match = pattern.exec(text);
  }

  if (last < text.length) out.push(text.slice(last));
  return out;
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: a block parser is one dispatch over line kinds; splitting it would only hide the shared paragraph/list state it mutates
export function renderMarkdown(source: string): ReactNode {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let paragraph: string[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;
  let key = 0;

  const flushParagraph = () => {
    if (paragraph.length === 0) return;
    const text = paragraph.join(" ");
    blocks.push(
      <p key={`p${key}`} style={styles.p}>
        {renderInline(text, `p${key++}`)}
      </p>
    );
    paragraph = [];
  };

  const flushList = () => {
    if (list === null) return;
    const { ordered, items } = list;
    const Tag = ordered ? "ol" : "ul";
    blocks.push(
      <Tag key={`l${key}`} style={styles.ul}>
        {items.map((item, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: list items have no stable id
          <li key={i} style={styles.li}>
            {renderInline(item, `l${key}-${i}`)}
          </li>
        ))}
      </Tag>
    );
    key++;
    list = null;
  };

  const flushAll = () => {
    flushParagraph();
    flushList();
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    // Fenced code: consume verbatim until the closing fence.
    if (line.trimStart().startsWith("```")) {
      flushAll();
      const body: string[] = [];
      i++;
      while (i < lines.length && !(lines[i] ?? "").trimStart().startsWith("```")) {
        body.push(lines[i] ?? "");
        i++;
      }
      blocks.push(
        <pre key={`c${key++}`} className="mono" style={styles.pre}>
          {body.join("\n")}
        </pre>
      );
      continue;
    }

    if (line.trim() === "") {
      flushAll();
      continue;
    }

    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      flushAll();
      blocks.push(<hr key={`h${key++}`} style={styles.hr} />);
      continue;
    }

    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flushAll();
      const level = Math.min(heading[1]?.length ?? 1, 3);
      const Tag = (["h1", "h2", "h3"] as const)[level - 1] ?? "h3";
      blocks.push(
        <Tag key={`t${key}`} style={styles[Tag]}>
          {renderInline(heading[2] ?? "", `t${key++}`)}
        </Tag>
      );
      continue;
    }

    const quote = /^\s*>\s?(.*)$/.exec(line);
    if (quote) {
      flushAll();
      blocks.push(
        <blockquote key={`q${key}`} style={styles.quote}>
          {renderInline(quote[1] ?? "", `q${key++}`)}
        </blockquote>
      );
      continue;
    }

    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet || numbered) {
      flushParagraph();
      const ordered = numbered !== null;
      const item = (bullet?.[1] ?? numbered?.[1] ?? "").trim();
      if (list === null || list.ordered !== ordered) {
        flushList();
        list = { ordered, items: [] };
      }
      list.items.push(item);
      continue;
    }

    flushList();
    paragraph.push(line.trim());
  }

  flushAll();
  return blocks;
}

/** True when an attachment should be rendered as Markdown rather than offered as a file. */
export function isMarkdown(name: string, mime: string): boolean {
  return mime === "text/markdown" || mime === "text/x-markdown" || /\.(md|markdown)$/i.test(name);
}

export function isPDF(name: string, mime: string): boolean {
  return mime === "application/pdf" || /\.pdf$/i.test(name);
}
