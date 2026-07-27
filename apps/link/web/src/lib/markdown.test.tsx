import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { isMarkdown, isPDF } from "./attachmentType.js";
import { renderMarkdown } from "./markdown.js";

// renderMarkdown returns a node array; wrap it so renderToStaticMarkup has a single root.
const html = (source: string) => renderToStaticMarkup(<div>{renderMarkdown(source)}</div>);

describe("markdown rendering", () => {
  test("renders headings, bold and rules", () => {
    const out = html("# Session\n\n**Date:** today\n\n---\n");
    expect(out).toContain("<h1");
    expect(out).toContain("Session");
    expect(out).toContain("<strong>Date:</strong>");
    expect(out).toContain("<hr");
  });

  test("renders lists and code", () => {
    const out = html("- one\n- two\n\n`inline`\n\n```\nblock\n```\n");
    expect(out).toContain("<ul");
    expect(out).toContain("<li");
    expect(out).toContain("<code");
    expect(out).toContain("<pre");
    expect(out).toContain("block");
  });

  test("keeps paragraphs separate", () => {
    expect(html("a\n\nb").match(/<p/g)?.length).toBe(2);
  });

  // The reason for moving off the hand-written renderer: real documents use GFM.
  test("renders GFM tables", () => {
    const out = html("| Time | Who |\n| --- | --- |\n| 00:00 | You |\n");
    expect(out).toContain("<table");
    expect(out).toContain("<th");
    expect(out).toContain("<td");
    expect(out).toContain("00:00");
  });

  test("renders nested lists", () => {
    const out = html("- outer\n  - inner\n");
    expect(out).toContain("inner");
    expect((out.match(/<ul/g) ?? []).length).toBeGreaterThan(1);
  });

  test("handles emphasis inside words without mangling", () => {
    expect(html("snake_case_name")).toContain("snake_case_name");
  });
});

// The content is authored by whoever created the link, and this page holds the decrypted
// plaintext *and* the key (in location.hash). Markup in the source must never become
// markup on the page.
describe("untrusted input", () => {
  // remark-rehype runs without allowDangerousHtml, so raw HTML nodes are dropped rather
  // than escaped into text — stricter than escaping, and nothing reaches the DOM.
  test("raw HTML is dropped, not executed", () => {
    const out = html("<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>");
    expect(out).not.toContain("<script");
    expect(out).not.toContain("<img");
    expect(out).not.toContain("onerror");
  });

  test("inline HTML in a paragraph is dropped but the prose survives", () => {
    const out = html("hello <b onmouseover=alert(1)>there</b> friend");
    expect(out).not.toContain("<b ");
    expect(out).not.toContain("onmouseover");
    expect(out).toContain("hello");
    expect(out).toContain("friend");
  });

  test("javascript: links are not linked, label kept", () => {
    const out = html("[click](javascript:alert(1))");
    expect(out).not.toContain("javascript:");
    expect(out).not.toContain("href");
    expect(out).toContain("click");
  });

  test("data: links are not linked", () => {
    const out = html("[x](data:text/html;base64,PHNjcmlwdD4=)");
    expect(out).not.toContain("href");
    expect(out).not.toContain("data:text/html");
  });

  test("http(s) and mailto links survive, with rel hardening", () => {
    const out = html("[ok](https://example.com) [mail](mailto:a@b.c)");
    expect(out).toContain('href="https://example.com"');
    expect(out).toContain('href="mailto:a@b.c"');
    expect(out).toContain('rel="noopener noreferrer nofollow"');
  });

  test("html inside code fences stays inert text", () => {
    const out = html("```\n<script>x</script>\n```");
    expect(out).not.toContain("<script>");
    expect(out).toContain("&lt;script&gt;");
  });
});

describe("attachment type detection", () => {
  test("markdown by mime or extension", () => {
    expect(isMarkdown("a.md", "application/octet-stream")).toBe(true);
    expect(isMarkdown("transcript", "text/markdown")).toBe(true);
    expect(isMarkdown("a.txt", "text/plain")).toBe(false);
  });

  test("pdf by mime or extension", () => {
    expect(isPDF("a.pdf", "application/octet-stream")).toBe(true);
    expect(isPDF("x", "application/pdf")).toBe(true);
    expect(isPDF("a.md", "text/markdown")).toBe(false);
  });
});
