import type { SharePayload, SharedFile } from "@caesar/link-sdk";
import { type CSSProperties, useEffect, useState } from "react";
import { Shell } from "../components/Layout.js";
import { t } from "../i18n.js";
import { ApiError, type MetaResult } from "../lib/api.js";
import { fetchAndOpen, fetchMeta, isPasswordProtected } from "../lib/share.js";

type State = "loading" | "password" | "wrong" | "gate" | "text" | "file" | "unavailable" | "error";

const dec = (b: Uint8Array) => new TextDecoder().decode(b);

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

const viewPrimary: CSSProperties = {
  width: "100%",
  height: 50,
  borderRadius: 999,
  background: "var(--primary)",
  color: "#fff",
  fontSize: 15,
  fontWeight: 600,
  boxShadow: "0 6px 20px var(--primary-soft)",
  border: 0,
};

const lockIcon = (
  <span style={{ display: "inline-block", position: "relative", width: 22, height: 21 }}>
    <span
      style={{
        position: "absolute",
        top: 0,
        left: "50%",
        transform: "translateX(-50%)",
        width: 13,
        height: 11,
        border: "2.5px solid currentColor",
        borderBottom: "none",
        borderRadius: "7px 7px 0 0",
      }}
    />
    <span
      style={{
        position: "absolute",
        bottom: 0,
        left: "50%",
        transform: "translateX(-50%)",
        width: 22,
        height: 15,
        background: "currentColor",
        borderRadius: 5,
      }}
    />
  </span>
);

function downloadFile(f: SharedFile) {
  const blob = new Blob([f.data as BlobPart], {
    type: f.mime || "application/octet-stream",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = f.name || "download";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: multi-state viewer; states are split into early returns
export function View() {
  const [state, setState] = useState<State>("loading");
  const [meta, setMeta] = useState<MetaResult | null>(null);
  const [payload, setPayload] = useState<SharePayload | null>(null);
  const [pw, setPw] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const url = window.location.href;

  // biome-ignore lint/correctness/useExhaustiveDependencies: run once on mount to fetch metadata
  useEffect(() => {
    let live = true;
    // biome-ignore lint/complexity/noExcessiveCognitiveComplexity: linear load-and-branch on mount
    (async () => {
      try {
        const { meta: m } = await fetchMeta(url);
        if (!live) return;
        setMeta(m);
        if (isPasswordProtected(url)) {
          setState("password");
        } else if (m.viewsLeft === 1) {
          setState("gate");
        } else {
          // multi/unlimited link-only share: reveal directly
          await revealWith(m);
        }
      } catch (e) {
        if (!live) return;
        setState(e instanceof ApiError && e.notFound ? "unavailable" : "error");
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  async function revealWith(m: MetaResult, password?: string) {
    const opened = await fetchAndOpen(url, m, password);
    setPayload(opened);
    setState(opened.type === "file" ? "file" : "text");
  }

  async function onReveal() {
    if (!meta) return;
    setBusy(true);
    try {
      await revealWith(meta);
    } catch (e) {
      setState(e instanceof ApiError && e.notFound ? "unavailable" : "error");
    } finally {
      setBusy(false);
    }
  }

  async function onUnlock() {
    if (!meta || !pw.trim()) return;
    setBusy(true);
    try {
      await revealWith(meta, pw);
    } catch (e) {
      // 404 → the share is gone; anything else (incl. GCM failure) → wrong password.
      setState(e instanceof ApiError && e.notFound ? "unavailable" : "wrong");
    } finally {
      setBusy(false);
    }
  }

  async function copyText() {
    if (payload?.type !== "text") return;
    await navigator.clipboard.writeText(dec(payload.data));
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  if (state === "loading") {
    return (
      <Shell>
        <div style={{ textAlign: "center", color: "var(--fg-2)" }}>{t("view.decrypting")}</div>
      </Shell>
    );
  }

  if (state === "password" || state === "wrong") {
    const wrong = state === "wrong";
    return (
      <Shell>
        <div
          className="anim"
          style={{ width: "100%", maxWidth: 400, margin: "0 auto", textAlign: "center" }}
        >
          <div
            style={{
              width: 56,
              height: 56,
              margin: "0 auto 18px",
              borderRadius: 18,
              background: wrong ? "var(--warn-soft)" : "var(--primary-soft)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: wrong ? "var(--warn)" : "var(--primary)",
              fontSize: wrong ? 22 : undefined,
            }}
          >
            {wrong ? "✕" : lockIcon}
          </div>
          <h2
            style={{
              fontSize: 21,
              fontWeight: 600,
              margin: "0 0 6px",
              color: "var(--fg)",
              letterSpacing: "-.02em",
            }}
          >
            {wrong ? t("view.pw_wrong") : t("view.pw_required")}
          </h2>
          <p style={{ fontSize: 13.5, color: "var(--fg-2)", margin: "0 0 20px", lineHeight: 1.5 }}>
            {wrong ? t("view.pw_wrong_sub") : t("view.pw_required_sub")}
          </p>
          {!wrong && (
            <>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  background: "var(--surface-2)",
                  border: "1px solid var(--line)",
                  borderRadius: 14,
                  padding: "0 6px 0 14px",
                  marginBottom: 12,
                }}
              >
                <input
                  value={pw}
                  onChange={(e) => setPw(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && onUnlock()}
                  type={showPw ? "text" : "password"}
                  placeholder={t("view.password")}
                  className="mono"
                  aria-label={t("view.password")}
                  style={{
                    flex: 1,
                    background: "none",
                    border: 0,
                    padding: "14px 0",
                    fontSize: 14,
                    color: "var(--fg)",
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPw((s) => !s)}
                  aria-label={showPw ? t("create.hide") : t("create.show")}
                  style={{ color: "var(--fg-2)", fontSize: 12, padding: 8 }}
                >
                  {showPw ? t("create.hide") : t("create.show")}
                </button>
              </div>
              <button
                type="button"
                onClick={onUnlock}
                disabled={busy || pw.trim().length === 0}
                style={{ ...viewPrimary, opacity: busy || !pw.trim() ? 0.6 : 1 }}
              >
                {busy ? t("view.unlocking") : t("view.unlock")}
              </button>
            </>
          )}
          <p
            style={{
              fontSize: 12,
              color: wrong ? "var(--warn)" : "var(--fg-2)",
              margin: "14px 0 0",
              lineHeight: 1.45,
            }}
          >
            {wrong ? t("view.pw_spent") : t("view.pw_hint")}
          </p>
        </div>
      </Shell>
    );
  }

  if (state === "gate") {
    return (
      <Shell>
        <div
          className="anim"
          style={{ width: "100%", maxWidth: 420, margin: "0 auto", textAlign: "center" }}
        >
          <div
            style={{
              width: 62,
              height: 62,
              margin: "0 auto 20px",
              borderRadius: 20,
              background: "var(--primary-soft)",
              color: "var(--primary)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {lockIcon}
          </div>
          <h2
            style={{
              fontSize: 22,
              fontWeight: 600,
              margin: "0 0 8px",
              color: "var(--fg)",
              letterSpacing: "-.02em",
              lineHeight: 1.2,
            }}
          >
            {t("view.gate_title")}
          </h2>
          <p style={{ fontSize: 14, color: "var(--fg-2)", margin: "0 0 24px", lineHeight: 1.55 }}>
            {t("view.gate_sub")}
          </p>
          <button
            type="button"
            onClick={onReveal}
            disabled={busy}
            style={{ ...viewPrimary, opacity: busy ? 0.6 : 1 }}
          >
            {busy ? t("view.revealing") : t("view.reveal")}
          </button>
          <p style={{ fontSize: 12, color: "var(--fg-2)", margin: "14px 0 0" }}>
            {t("view.gate_note")}
          </p>
        </div>
      </Shell>
    );
  }

  if (state === "text" && payload?.type === "text") {
    return (
      <Shell>
        <div className="anim" style={{ width: "100%", maxWidth: 520, margin: "0 auto" }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 12,
            }}
          >
            <h2
              style={{
                fontSize: 18,
                fontWeight: 600,
                margin: 0,
                color: "var(--fg)",
                letterSpacing: "-.02em",
              }}
            >
              {t("view.decrypted")}
            </h2>
            <span
              style={{
                fontSize: 11.5,
                color: "var(--ok)",
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--ok)" }} />
              {t("view.in_browser")}
            </span>
          </div>
          <div
            style={{
              background: "var(--surface-2)",
              border: "1px solid var(--line)",
              borderRadius: 16,
              padding: "18px 18px 14px",
            }}
          >
            <p
              className="mono"
              style={{
                fontSize: 14,
                lineHeight: 1.6,
                color: "var(--fg)",
                margin: "0 0 14px",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {dec(payload.data)}
            </p>
            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                borderTop: "1px solid var(--line-2)",
                paddingTop: 12,
              }}
            >
              <button
                type="button"
                onClick={copyText}
                style={{
                  padding: "8px 16px",
                  borderRadius: 999,
                  fontSize: 13,
                  fontWeight: 600,
                  background: copied ? "var(--ok)" : "var(--surface)",
                  border: "1px solid var(--line)",
                  color: copied ? "#fff" : "var(--fg)",
                }}
              >
                {copied ? t("view.copied") : t("view.copy_text")}
              </button>
            </div>
          </div>
          <p
            style={{ fontSize: 12, color: "var(--fg-2)", margin: "14px 0 0", textAlign: "center" }}
          >
            {t("view.destroyed")}
          </p>
        </div>
      </Shell>
    );
  }

  if (state === "file" && payload?.type === "file") {
    const files = payload.files;
    const multi = files.length > 1;
    return (
      <Shell>
        <div className="anim" style={{ width: "100%", maxWidth: 460, margin: "0 auto" }}>
          <h2
            style={{
              fontSize: 18,
              fontWeight: 600,
              margin: "0 0 12px",
              color: "var(--fg)",
              letterSpacing: "-.02em",
              textAlign: "center",
            }}
          >
            {multi
              ? t("view.files_ready").replace("{n}", String(files.length))
              : t("view.file_ready")}
          </h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {files.map((f, i) => {
              const ext = (f.name.split(".").pop() ?? "").slice(0, 4).toUpperCase() || "FILE";
              return (
                <div
                  key={`${f.name}-${f.data.length}-${i}`}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 16,
                    background: "var(--surface-2)",
                    border: "1px solid var(--line)",
                    borderRadius: 18,
                    padding: 20,
                  }}
                >
                  <div
                    className="mono"
                    style={{
                      width: 52,
                      height: 62,
                      borderRadius: 10,
                      background: "var(--primary-soft)",
                      border: "1px solid var(--line)",
                      display: "flex",
                      alignItems: "flex-end",
                      justifyContent: "center",
                      paddingBottom: 8,
                      fontSize: 11,
                      color: "var(--primary)",
                      fontWeight: 600,
                      flex: "none",
                    }}
                  >
                    {ext}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize: 15.5,
                        color: "var(--fg)",
                        fontWeight: 500,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                    >
                      {f.name}
                    </div>
                    <div
                      className="mono"
                      style={{ fontSize: 12.5, color: "var(--fg-2)", marginTop: 3 }}
                    >
                      {formatBytes(f.data.length)} · {t("view.decrypted_suffix")}
                    </div>
                  </div>
                  {multi && (
                    <button
                      type="button"
                      onClick={() => downloadFile(f)}
                      aria-label={t("view.download")}
                      style={{
                        color: "var(--primary)",
                        width: 40,
                        height: 40,
                        borderRadius: 999,
                        border: "1px solid var(--line)",
                        flex: "none",
                        fontSize: 16,
                      }}
                    >
                      ↓
                    </button>
                  )}
                </div>
              );
            })}
          </div>
          <button
            type="button"
            onClick={() => {
              for (const f of files) downloadFile(f);
            }}
            style={{ ...viewPrimary, marginTop: 20 }}
          >
            {multi ? t("view.download_all") : t("view.download")}
          </button>
          <p
            style={{
              fontSize: 12,
              color: "var(--fg-2)",
              margin: "14px 0 0",
              textAlign: "center",
              lineHeight: 1.5,
            }}
          >
            {t("view.file_note")}
          </p>
        </div>
      </Shell>
    );
  }

  // unavailable / error
  return (
    <Shell>
      <div
        className="anim"
        style={{ width: "100%", maxWidth: 400, margin: "0 auto", textAlign: "center" }}
      >
        <div
          style={{
            width: 56,
            height: 56,
            margin: "0 auto 18px",
            borderRadius: 18,
            background: "var(--surface-2)",
            border: "1px solid var(--line)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--fg-2)",
            fontSize: 24,
          }}
        >
          ∅
        </div>
        <h2
          style={{
            fontSize: 21,
            fontWeight: 600,
            margin: "0 0 8px",
            color: "var(--fg)",
            letterSpacing: "-.02em",
          }}
        >
          {t("view.unavailable")}
        </h2>
        <p style={{ fontSize: 14, color: "var(--fg-2)", margin: "0 0 22px", lineHeight: 1.55 }}>
          {t("view.unavailable_sub")}
        </p>
        <a
          href="/"
          style={{
            display: "inline-block",
            padding: "12px 22px",
            borderRadius: 999,
            background: "var(--surface-2)",
            border: "1px solid var(--line)",
            color: "var(--fg)",
            fontSize: 14,
            fontWeight: 500,
          }}
        >
          {t("view.create_own")}
        </a>
      </div>
    </Shell>
  );
}
