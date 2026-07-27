import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { ShareStore } from "./store.js";

const HOUR_MS = 3600_000;

const config = loadConfig(process.env);
const store = new ShareStore(`${config.dataDir}/link.db`, config.dataDir);
const app = createApp(store, config);

// Run once at boot too: a server that was down over a retention boundary must not wait
// an hour before honouring it.
store.sweep(Date.now(), config.retentionSeconds * 1000);

const sweepTimer = setInterval(
  () => store.sweep(Date.now(), config.retentionSeconds * 1000),
  HOUR_MS
);
sweepTimer.unref();

Bun.serve({
  port: config.port,
  maxRequestBodySize: config.maxBlobSize + 1_048_576,
  fetch: app.fetch,
});

// biome-ignore lint/suspicious/noConsoleLog: server startup banner
console.log(`link-server listening on port ${config.port}`);
