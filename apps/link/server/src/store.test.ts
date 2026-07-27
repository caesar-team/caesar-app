import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type CreateInput, ShareStore } from "./store";

const NOW = 1_000_000_000_000;
const SECOND = 1000;
const DAY = 24 * 3600 * SECOND;
const RETENTION_MS = 30 * DAY;

let dataDir: string;
let store: ShareStore;

function makeInput(overrides: Partial<CreateInput> = {}): CreateInput {
  return {
    blob: new Uint8Array([1, 2, 3, 4]),
    meta: JSON.stringify({ iv: "abc" }),
    ttlSeconds: 3600,
    views: null,
    now: NOW,
    ...overrides,
  };
}

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), "link-store-"));
  store = new ShareStore(":memory:", dataDir);
});

afterEach(() => {
  store.close();
  rmSync(dataDir, { recursive: true, force: true });
});

describe("ShareStore", () => {
  test("create then getMeta returns the record", () => {
    const { id, deleteToken } = store.create(
      makeInput({ views: 5, meta: JSON.stringify({ iv: "xyz" }) })
    );
    expect(id).toBeString();
    expect(deleteToken).toBeString();
    expect(id.length).toBeGreaterThan(0);
    expect(deleteToken.length).toBeGreaterThan(0);

    const rec = store.getMeta(id, NOW);
    expect(rec).not.toBeNull();
    expect(rec?.id).toBe(id);
    expect(rec?.size).toBe(4);
    expect(rec?.meta).toBe(JSON.stringify({ iv: "xyz" }));
    expect(rec?.viewsLeft).toBe(5);
    expect(rec?.expiresAt).toBe(NOW + 3600 * SECOND);
    expect(rec?.createdAt).toBe(NOW);
  });

  test("one-time share: first consume returns bytes, second returns null and cleans up", () => {
    const { id } = store.create(makeInput({ views: 1, blob: new Uint8Array([9, 8, 7]) }));
    const blobPath = join(dataDir, "blobs", id);
    expect(existsSync(blobPath)).toBe(true);

    const first = store.consumeBlob(id, NOW);
    expect(first).not.toBeNull();
    expect(Array.from(first as Uint8Array)).toEqual([9, 8, 7]);

    const second = store.consumeBlob(id, NOW);
    expect(second).toBeNull();
    expect(store.getMeta(id, NOW)).toBeNull();
    expect(existsSync(blobPath)).toBe(false);
  });

  test("multi-view share: consumes down to zero then cleans up", () => {
    const { id } = store.create(makeInput({ views: 2, blob: new Uint8Array([5, 5]) }));
    const blobPath = join(dataDir, "blobs", id);

    expect(store.consumeBlob(id, NOW)).not.toBeNull();
    expect(store.getMeta(id, NOW)?.viewsLeft).toBe(1); // decremented, not deleted
    expect(existsSync(blobPath)).toBe(true);

    expect(store.consumeBlob(id, NOW)).not.toBeNull(); // last view
    expect(store.getMeta(id, NOW)).toBeNull();
    expect(existsSync(blobPath)).toBe(false);
  });

  test("orphaned row (blob file missing) is treated as gone, not a crash", () => {
    const { id } = store.create(makeInput({ views: 5 }));
    // Simulate a filesystem inconsistency: row exists, blob file removed.
    rmSync(join(dataDir, "blobs", id), { force: true });
    expect(store.consumeBlob(id, NOW)).toBeNull();
    // the inconsistent row is cleaned up
    expect(store.getMeta(id, NOW)).toBeNull();
  });

  test("unlimited share: consume many times always returns bytes", () => {
    const { id } = store.create(makeInput({ views: null, blob: new Uint8Array([42]) }));
    for (let i = 0; i < 5; i++) {
      const bytes = store.consumeBlob(id, NOW);
      expect(bytes).not.toBeNull();
      expect(Array.from(bytes as Uint8Array)).toEqual([42]);
    }
    // still present with unlimited views
    expect(store.getMeta(id, NOW)?.viewsLeft).toBeNull();
  });

  test("expired share: getMeta and consumeBlob return null and clean up", () => {
    const { id } = store.create(makeInput({ ttlSeconds: 60, views: 5 }));
    const blobPath = join(dataDir, "blobs", id);
    const later = NOW + 61 * SECOND;

    expect(store.getMeta(id, later)).toBeNull();
    expect(existsSync(blobPath)).toBe(false);

    // recreate to test consumeBlob path independently
    const created = store.create(makeInput({ ttlSeconds: 60, views: 5 }));
    const path2 = join(dataDir, "blobs", created.id);
    expect(store.consumeBlob(created.id, NOW + 61 * SECOND)).toBeNull();
    expect(existsSync(path2)).toBe(false);
  });

  test("remove: correct token true and file gone, wrong token false, missing false", () => {
    const { id, deleteToken } = store.create(makeInput());
    const blobPath = join(dataDir, "blobs", id);

    expect(store.remove(id, "wrong-token")).toBe(false);
    expect(existsSync(blobPath)).toBe(true);
    expect(store.getMeta(id, NOW)).not.toBeNull();

    expect(store.remove(id, deleteToken)).toBe(true);
    expect(existsSync(blobPath)).toBe(false);
    expect(store.getMeta(id, NOW)).toBeNull();

    expect(store.remove("does-not-exist", deleteToken)).toBe(false);
  });

  test("sweep deletes only expired rows and returns the count", () => {
    const expired1 = store.create(makeInput({ ttlSeconds: 60 }));
    const expired2 = store.create(makeInput({ ttlSeconds: 120 }));
    const live = store.create(makeInput({ ttlSeconds: 100000 }));

    const later = NOW + 1000 * SECOND;
    const count = store.sweep(later);
    expect(count).toBe(2);

    expect(store.getMeta(expired1.id, NOW)).toBeNull();
    expect(store.getMeta(expired2.id, NOW)).toBeNull();
    expect(existsSync(join(dataDir, "blobs", expired1.id))).toBe(false);
    expect(existsSync(join(dataDir, "blobs", expired2.id))).toBe(false);

    expect(store.getMeta(live.id, NOW)).not.toBeNull();
    expect(existsSync(join(dataDir, "blobs", live.id))).toBe(true);
  });

  // Retention is a promise about *stored bytes*, so it cannot be conditional on a row's
  // own expiry: a record written by an older build (or a corrupted expires_at) could
  // otherwise sit on disk forever. The sweep therefore also drops anything created
  // longer than the retention window ago, whatever its expiry says.
  test("sweep drops rows older than the retention window even when unexpired", () => {
    const legacy = store.create(makeInput({ ttlSeconds: 400 * 24 * 3600 }));
    const recent = store.create(makeInput({ ttlSeconds: 400 * 24 * 3600, now: NOW + 29 * DAY }));

    const sweptAt = NOW + 31 * DAY;
    expect(store.getMeta(legacy.id, sweptAt)).not.toBeNull();

    const count = store.sweep(sweptAt, RETENTION_MS);
    expect(count).toBe(1);
    expect(store.getMeta(legacy.id, sweptAt)).toBeNull();
    expect(existsSync(join(dataDir, "blobs", legacy.id))).toBe(false);

    expect(store.getMeta(recent.id, sweptAt)).not.toBeNull();
  });

  test("sweep removes orphaned blob files older than the retention window", () => {
    const orphan = join(dataDir, "blobs", "orphan-from-a-crash");
    writeFileSync(orphan, new Uint8Array([9, 9, 9]));
    utimesSync(orphan, new Date(NOW), new Date(NOW));

    const fresh = join(dataDir, "blobs", "orphan-just-written");
    writeFileSync(fresh, new Uint8Array([1]));
    utimesSync(fresh, new Date(NOW + 31 * DAY), new Date(NOW + 31 * DAY));

    store.sweep(NOW + 31 * DAY, RETENTION_MS);

    expect(existsSync(orphan)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
  });
});
