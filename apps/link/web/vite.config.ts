import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { VitePWA } from "vite-plugin-pwa";

const fromHere = (p: string) => fileURLToPath(new URL(p, import.meta.url));

const pwa = VitePWA({
  injectRegister: false,
  manifest: false,
  workbox: {
    globPatterns: ["**/*.{js,css,html}"],
    globIgnores: ["**/PdfBody-*.js", "**/pdfWorker-*.js", "**/MarkdownBody-*.js"],
    directoryIndex: null,
    navigateFallback: null,
    cleanupOutdatedCaches: true,
    runtimeCaching: [
      {
        urlPattern: ({ request, url }) =>
          request.mode === "navigate" &&
          !url.pathname.startsWith("/api/") &&
          !url.pathname.startsWith("/s/"),
        handler: "NetworkOnly",
        options: { precacheFallback: { fallbackURL: "/index.html" } },
      },
      {
        urlPattern: ({ url }) => url.pathname === "/branding.json",
        handler: "NetworkFirst",
        options: { cacheName: "branding" },
      },
      {
        urlPattern: ({ request, url, sameOrigin }) =>
          sameOrigin &&
          request.destination === "image" &&
          !url.pathname.startsWith("/api/") &&
          !url.pathname.startsWith("/s/"),
        handler: "StaleWhileRevalidate",
        options: {
          cacheName: "images",
          expiration: { maxEntries: 20 },
          cacheableResponse: { statuses: [200] },
        },
      },
      {
        urlPattern: ({ url, sameOrigin }) => sameOrigin && url.pathname.startsWith("/assets/"),
        handler: "CacheFirst",
        options: {
          cacheName: "lazy-assets",
          expiration: { maxEntries: 20, maxAgeSeconds: 30 * 24 * 3600 },
          cacheableResponse: { statuses: [200] },
        },
      },
      {
        urlPattern: ({ url }) => url.origin === "https://fonts.googleapis.com",
        handler: "StaleWhileRevalidate",
        options: { cacheName: "google-fonts-css" },
      },
      {
        urlPattern: ({ url }) => url.origin === "https://fonts.gstatic.com",
        handler: "CacheFirst",
        options: {
          cacheName: "google-fonts",
          expiration: { maxEntries: 20, maxAgeSeconds: 365 * 24 * 3600 },
          cacheableResponse: { statuses: [0, 200] },
        },
      },
    ],
  },
});

export default defineConfig({
  base: "/",
  plugins: [react(), pwa],
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
