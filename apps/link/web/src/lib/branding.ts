/**
 * White-label branding. Loaded from /branding.json at boot (falls back to defaults),
 * so an operator can re-skin the app by volume-mounting a branding.json — no rebuild.
 * The primary color is applied by overriding the --primary CSS variables, so every
 * component that uses var(--primary) re-themes automatically.
 */
export interface Branding {
  name: string;
  primary?: string;
  primaryDark?: string;
  logo: string;
  logoDark: string;
}

const DEFAULTS: Branding = {
  name: "Link",
  primary: "#7c5cff",
  primaryDark: "#9179ff",
  logo: "/link-mark.png",
  logoDark: "/link-mark-dark.png",
};

let branding: Branding = DEFAULTS;

export function getBranding(): Branding {
  return branding;
}

function rgba(hex: string, alpha: number): string {
  const h = hex.replace("#", "");
  const full =
    h.length === 3
      ? h
          .split("")
          .map((c) => c + c)
          .join("")
      : h;
  const r = Number.parseInt(full.slice(0, 2), 16);
  const g = Number.parseInt(full.slice(2, 4), 16);
  const b = Number.parseInt(full.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function applyPrimary(b: Branding): void {
  const light = b.primary ?? DEFAULTS.primary;
  const dark = b.primaryDark ?? light;
  if (light === undefined || dark === undefined) {
    return;
  }
  const style = document.createElement("style");
  style.textContent = [
    `:root{--primary:${light};--primary-soft:${rgba(light, 0.1)}}`,
    `:root[data-theme="dark"]{--primary:${dark};--primary-soft:${rgba(dark, 0.16)}}`,
    `@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--primary:${dark};--primary-soft:${rgba(dark, 0.16)}}}`,
  ].join("\n");
  document.head.appendChild(style);
}

export async function loadBranding(): Promise<void> {
  try {
    const res = await fetch("/branding.json");
    if (res.ok) {
      branding = { ...DEFAULTS, ...(await res.json()) };
    }
  } catch {
    // keep defaults when branding.json is absent or invalid
  }
  applyPrimary(branding);
  document.title = `${branding.name} — Share a secret`;
}
