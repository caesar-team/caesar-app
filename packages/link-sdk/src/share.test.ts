import { describe, expect, test } from "bun:test";
import { createShare, openShare } from "./share.js";

describe("share bundle", () => {
  test("link-only roundtrip", async () => {
    const bundle = await createShare({ type: "text", data: new TextEncoder().encode("s3cret") });
    expect(bundle.kdf).toBeUndefined();
    const payload = await openShare({
      blob: bundle.blob,
      fragment: bundle.fragment,
    });
    expect(new TextDecoder().decode(payload.data)).toBe("s3cret");
  });

  test("password roundtrip and wrong-password failure", async () => {
    const bundle = await createShare(
      { type: "file", name: "a.bin", data: new Uint8Array([9, 9, 9]) },
      { password: "hunter2" }
    );
    expect(bundle.kdf?.kdf).toBe("scrypt");
    const payload = await openShare({
      blob: bundle.blob,
      fragment: bundle.fragment,
      password: "hunter2",
      kdf: bundle.kdf,
    });
    expect(payload.name).toBe("a.bin");
    await expect(
      openShare({ blob: bundle.blob, fragment: bundle.fragment, password: "nope", kdf: bundle.kdf })
    ).rejects.toThrow();
  }, 60000);
});
