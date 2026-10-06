import { describe, expect, test } from "bun:test";
import { type Config, loadConfig } from "./config";

const RETENTION_SECONDS = 30 * 24 * 3600;

describe("loadConfig", () => {
  test("returns defaults when env is empty", () => {
    const config: Config = loadConfig({});
    expect(config.port).toBe(3000);
    expect(config.dataDir).toBe("./data");
    expect(config.maxBlobSize).toBe(104857600);
    expect(config.rateLimitMax).toBe(30);
    expect(config.rateLimitWindowMs).toBe(3600000);
    expect(config.minTtl).toBe(60);
    expect(config.maxTtl).toBe(2592000);
    expect(config.trustProxy).toBe(false);
    expect(config.maxMetaSize).toBe(16384);
  });

  test("parses overrides into numbers", () => {
    const config = loadConfig({
      PORT: "8080",
      DATA_DIR: "/srv/data",
      MAX_BLOB_SIZE: "2048",
      RATE_LIMIT_MAX: "5",
      RATE_LIMIT_WINDOW_MS: "1000",
      MAX_TTL: "600",
      TRUST_PROXY: "true",
      MAX_META_SIZE: "512",
    });
    expect(config.port).toBe(8080);
    expect(config.dataDir).toBe("/srv/data");
    expect(config.maxBlobSize).toBe(2048);
    expect(config.rateLimitMax).toBe(5);
    expect(config.rateLimitWindowMs).toBe(1000);
    expect(config.maxTtl).toBe(600);
    expect(config.minTtl).toBe(60);
    expect(config.trustProxy).toBe(true);
    expect(config.maxMetaSize).toBe(512);
  });

  test("throws when a numeric env var is non-numeric", () => {
    expect(() => loadConfig({ MAX_BLOB_SIZE: "not-a-number" })).toThrow();
  });

  test("trustProxy parses '1' as true and other values as false", () => {
    expect(loadConfig({ TRUST_PROXY: "1" }).trustProxy).toBe(true);
    expect(loadConfig({ TRUST_PROXY: "false" }).trustProxy).toBe(false);
    expect(loadConfig({ TRUST_PROXY: "yes" }).trustProxy).toBe(false);
  });

  test("clientIpHeader is unset by default and when blank", () => {
    expect(loadConfig({}).clientIpHeader).toBeUndefined();
    expect(loadConfig({ CLIENT_IP_HEADER: "  " }).clientIpHeader).toBeUndefined();
  });

  test("clientIpHeader is trimmed and lowercased", () => {
    expect(loadConfig({ CLIENT_IP_HEADER: " CF-Connecting-IP " }).clientIpHeader).toBe(
      "cf-connecting-ip"
    );
  });
});

// Retention is the product promise ("nothing older than 30 days"); a TTL above it would
// let a share outlive the guarantee, so the config refuses to start rather than silently
// truncating someone's intent.
test("rejects a MAX_TTL above the retention ceiling", () => {
  expect(() => loadConfig({ MAX_TTL: String(RETENTION_SECONDS + 1) })).toThrow(/retention/i);
});

test("accepts a MAX_TTL at the ceiling", () => {
  expect(loadConfig({ MAX_TTL: String(RETENTION_SECONDS) }).maxTtl).toBe(RETENTION_SECONDS);
});

test("defaults to the 30 day ceiling", () => {
  const config = loadConfig({});
  expect(config.maxTtl).toBe(RETENTION_SECONDS);
  expect(config.retentionSeconds).toBe(RETENTION_SECONDS);
});
