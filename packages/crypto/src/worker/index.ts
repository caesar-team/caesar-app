/**
 * Crypto WebWorker Wrapper
 * Type-safe interface for communicating with crypto worker
 */

import { type Remote, wrap } from "comlink";
import type { CryptoWorkerApi } from "./crypto.worker.js";

let workerInstance: Worker | null = null;
let cryptoApi: Remote<CryptoWorkerApi> | null = null;

/**
 * Initialize the crypto worker
 * @returns Remote API for crypto operations
 */
export function initCryptoWorker(): Remote<CryptoWorkerApi> {
  if (cryptoApi) {
    return cryptoApi;
  }

  // Create worker instance
  workerInstance = new Worker(new URL("./crypto.worker.ts", import.meta.url), {
    type: "module",
  });

  // Wrap with Comlink for type-safe communication
  cryptoApi = wrap<CryptoWorkerApi>(workerInstance);

  return cryptoApi;
}

/**
 * Terminate the crypto worker
 */
export function terminateCryptoWorker(): void {
  if (workerInstance) {
    workerInstance.terminate();
    workerInstance = null;
    cryptoApi = null;
  }
}

/**
 * Get the crypto worker API (initializes if needed)
 * @returns Remote API for crypto operations
 */
export function getCryptoWorker(): Remote<CryptoWorkerApi> {
  if (!cryptoApi) {
    return initCryptoWorker();
  }
  return cryptoApi;
}

// Re-export the worker API type
export type { CryptoWorkerApi };
