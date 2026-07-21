import { describe, expect, test } from "bun:test";
import { type Config, loadConfig } from "./config";

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
  });

  test("parses overrides into numbers", () => {
    const config = loadConfig({
      PORT: "8080",
      DATA_DIR: "/srv/data",
      MAX_BLOB_SIZE: "2048",
      RATE_LIMIT_MAX: "5",
      RATE_LIMIT_WINDOW_MS: "1000",
      MAX_TTL: "600",
    });
    expect(config.port).toBe(8080);
    expect(config.dataDir).toBe("/srv/data");
    expect(config.maxBlobSize).toBe(2048);
    expect(config.rateLimitMax).toBe(5);
    expect(config.rateLimitWindowMs).toBe(1000);
    expect(config.maxTtl).toBe(600);
    expect(config.minTtl).toBe(60);
  });

  test("throws when a numeric env var is non-numeric", () => {
    expect(() => loadConfig({ MAX_BLOB_SIZE: "not-a-number" })).toThrow();
  });
});
