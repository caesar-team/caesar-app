import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const fromHere = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  base: "/",
  plugins: [react()],
  resolve: {
    // Force a single React instance. Source-aliasing the workspace packages pulls
    // modules from other package dirs into the graph; without dedupe React/react-dom
    // can resolve to two copies, giving a null hook dispatcher ("reading useState").
    dedupe: ["react", "react-dom"],
    // Bundle the workspace crypto/sdk from TS source. Their built dist references
    // the crypto Web Worker by a source-relative path (crypto.worker.ts) that only
    // exists in src, so source-aliasing lets Vite resolve and bundle the worker.
    alias: {
      "@caesar/link-sdk": fromHere("../../../packages/link-sdk/src/index.ts"),
      "@caesar/crypto": fromHere("../../../packages/crypto/src/index.ts"),
    },
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:3000",
        changeOrigin: true,
      },
    },
  },
});
