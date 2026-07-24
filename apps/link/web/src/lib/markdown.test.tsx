import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { isMarkdown, isPDF, renderMarkdown } from "./markdown.js";

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
});

// The content is authored by whoever created the link, and this page holds the decrypted
// plaintext *and* the key (in location.hash). Markup in the source must never become
// markup on the page.
describe("untrusted input", () => {
  test("raw HTML is escaped, not executed", () => {
    const out = html("<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>");
    expect(out).not.toContain("<script>");
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;script&gt;");
  });

  test("javascript: links lose their target", () => {
    const out = html("[click](javascript:alert(1))");
    expect(out).not.toContain("javascript:");
    expect(out).not.toContain("<a ");
    expect(out).toContain("click");
  });

  test("data: links lose their target", () => {
    const out = html("[x](data:text/html;base64,PHNjcmlwdD4=)");
    expect(out).not.toContain("<a ");
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
