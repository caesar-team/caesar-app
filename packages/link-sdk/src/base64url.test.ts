import { describe, expect, test } from "bun:test";
import { fromBase64Url, toBase64Url } from "./base64url.js";

describe("base64url", () => {
  test("roundtrips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255, 62, 63]);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
  });

  test("emits no padding and no +/ characters", () => {
    const s = toBase64Url(new Uint8Array([251, 255, 254]));
    expect(s).not.toMatch(/[=+/]/);
  });

  test("rejects invalid input", () => {
    expect(() => fromBase64Url("not base64url!!")).toThrow();
  });
});
