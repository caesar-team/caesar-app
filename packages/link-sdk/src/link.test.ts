import { describe, expect, test } from "bun:test";
import { buildShareUrl, parseShareUrl } from "./link.js";

describe("buildShareUrl", () => {
  test("joins a bare origin with exactly one /s/", () => {
    expect(buildShareUrl("https://host", "abc123", "k.AAAA")).toBe("https://host/s/abc123#k.AAAA");
  });

  test("normalizes a single trailing slash on the base", () => {
    expect(buildShareUrl("https://host/", "abc123", "k.AAAA")).toBe("https://host/s/abc123#k.AAAA");
  });

  test("preserves a subpath base", () => {
    expect(buildShareUrl("https://host/link", "abc123", "p.BBBB")).toBe(
      "https://host/link/s/abc123#p.BBBB"
    );
  });
});

describe("parseShareUrl", () => {
  test("extracts id and fragment and strips the leading #", () => {
    expect(parseShareUrl("https://host/s/abc123#k.AAAA")).toEqual({
      id: "abc123",
      fragment: "k.AAAA",
    });
  });

  test("round-trips with buildShareUrl", () => {
    const url = buildShareUrl("https://host/link", "xyz789", "p.CCCC");
    expect(parseShareUrl(url)).toEqual({ id: "xyz789", fragment: "p.CCCC" });
  });

  test("throws when there is no fragment", () => {
    expect(() => parseShareUrl("https://host/s/abc123")).toThrow();
  });

  test("throws when the path has no /s/<id> segment", () => {
    expect(() => parseShareUrl("https://host/other/abc123#k.AAAA")).toThrow();
  });
});
