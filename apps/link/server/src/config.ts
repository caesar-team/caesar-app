export interface Config {
  port: number;
  dataDir: string;
  maxBlobSize: number;
  rateLimitMax: number;
  rateLimitWindowMs: number;
  minTtl: number;
  maxTtl: number;
  trustProxy: boolean;
  maxMetaSize: number;
  /** Directory of the built web SPA to serve; undefined = API only */
  webDir?: string;
}

function parseBoolEnv(value: string | undefined): boolean {
  return value === "true" || value === "1";
}

function parseIntEnv(value: string | undefined, name: string, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid ${name}: expected an integer, got "${value}"`);
  }
  return parsed;
}

export function loadConfig(env: Record<string, string | undefined>): Config {
  return {
    port: parseIntEnv(env.PORT, "PORT", 3000),
    dataDir: env.DATA_DIR ?? "./data",
    maxBlobSize: parseIntEnv(env.MAX_BLOB_SIZE, "MAX_BLOB_SIZE", 104857600),
    rateLimitMax: parseIntEnv(env.RATE_LIMIT_MAX, "RATE_LIMIT_MAX", 30),
    rateLimitWindowMs: parseIntEnv(env.RATE_LIMIT_WINDOW_MS, "RATE_LIMIT_WINDOW_MS", 3600000),
    minTtl: 60,
    maxTtl: parseIntEnv(env.MAX_TTL, "MAX_TTL", 2592000),
    trustProxy: parseBoolEnv(env.TRUST_PROXY),
    maxMetaSize: parseIntEnv(env.MAX_META_SIZE, "MAX_META_SIZE", 16384),
    webDir: env.WEB_DIR,
  };
}
