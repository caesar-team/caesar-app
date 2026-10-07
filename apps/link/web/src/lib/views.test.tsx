import { describe, expect, test } from "bun:test";
import type { SharedFile } from "@caesar/link-sdk";
import { renderToStaticMarkup } from "react-dom/server";

// i18n resolves the language from localStorage at import time, and Bun has none.
globalThis.localStorage = { getItem: () => "en" } as unknown as Storage;
const { AttachmentPreview, FileNote } = await import("../components/AttachmentPreview.js");
const { viewsNote } = await import("./views.js");

const SPENT = "This link is now spent.";
const md: SharedFile = {
  name: "notes.md",
  mime: "text/markdown",
  data: new TextEncoder().encode("# hi"),
};
const preview = (viewsLeft: number | null) =>
  renderToStaticMarkup(<AttachmentPreview file={md} viewsLeft={viewsLeft} onDownload={() => {}} />);
const fileList = (viewsLeft: number | null) =>
  renderToStaticMarkup(<FileNote viewsLeft={viewsLeft} />);

// viewsLeft is what the meta reported *before* the open downloaded the blob.
describe("file share note", () => {
  test("unlimited views: never claims the link is spent", () => {
    expect(preview(null)).not.toContain(SPENT);
    expect(fileList(null)).not.toContain(SPENT);
  });

  test("last view: says the link is spent", () => {
    expect(preview(1)).toContain(SPENT);
    expect(fileList(1)).toContain(SPENT);
  });

  test("views remaining: says how many, not spent", () => {
    expect(fileList(3)).toContain("Views left: 2.");
    expect(fileList(3)).not.toContain(SPENT);
    expect(preview(3)).toContain("Views left: 2.");
  });
});

describe("viewsNote", () => {
  test("unlimited says nothing", () => {
    expect(viewsNote(null, "gone")).toBeNull();
  });

  test("last view returns the caller's spent text", () => {
    expect(viewsNote(1, "gone")).toBe("gone");
  });

  test("remaining views are counted after this open", () => {
    expect(viewsNote(5, "gone")).toBe("Views left: 4.");
  });
});
