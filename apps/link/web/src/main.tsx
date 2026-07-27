import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { loadBranding } from "./lib/branding.js";
import "./styles.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("Root element #root not found");
}

// Apply white-label branding before the first paint, then mount.
await loadBranding();

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);
