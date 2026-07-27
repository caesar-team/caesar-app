import type { ReactNode } from "react";
import { getLang, setLang, t } from "../i18n.js";
import { getBranding } from "../lib/branding.js";

export function Header() {
  const brand = getBranding();
  return (
    <header className="app-header">
      <div className="brand">
        <picture>
          <source srcSet={brand.logoDark} media="(prefers-color-scheme: dark)" />
          <img className="brand-mark" src={brand.logo} alt="" width={28} height={28} />
        </picture>
        <span className="brand-name">{brand.name}</span>
      </div>
      <span className="brand-badge">
        <span className="dot dot-ok" />
        {t("badge.encrypted")}
      </span>
    </header>
  );
}

function LangToggle() {
  const lang = getLang();
  const other = lang === "en" ? "ru" : "en";
  return (
    <button
      type="button"
      onClick={() => setLang(other)}
      className="lang-toggle"
      aria-label="Switch language"
    >
      {other.toUpperCase()}
    </button>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell">
      <div className="app-card">
        <Header />
        <main className="app-main">{children}</main>
        <footer className="app-footer">
          <span>{t("footer.zk")}</span>
          <LangToggle />
        </footer>
      </div>
    </div>
  );
}
