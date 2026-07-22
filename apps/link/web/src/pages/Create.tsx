import type { SharePayload } from "@caesar/link-sdk";
import { type CSSProperties, useEffect, useRef, useState } from "react";
import { Shell } from "../components/Layout.js";
import { t } from "../i18n.js";
import { type CreatePhase, type CreatedShare, createAndUpload } from "../lib/share.js";

type Mode = "text" | "file";
type ViewsMode = "once" | "count" | "unlimited";
type Phase = "idle" | CreatePhase | "success" | "error";

const EXPIRY_SECONDS: Record<string, number> = {
  "1h": 3600,
  "24h": 86400,
  "7d": 604800,
  "30d": 2592000,
};

const PW_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";

function generatePassword(len = 20): string {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  for (const b of bytes) {
    out += PW_ALPHABET[b % PW_ALPHABET.length];
  }
  return out;
}

function passwordStrength(pw: string): 0 | 1 | 2 | 3 {
  if (!pw) {
    return 0;
  }
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^A-Za-z0-9]/.test(pw)) classes++;
  const score = (pw.length >= 16 ? 2 : pw.length >= 10 ? 1 : 0) + (classes >= 3 ? 1 : 0);
  return Math.min(3, Math.max(1, score)) as 1 | 2 | 3;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function randomCipher(): string {
  const hex = "0123456789abcdef";
  const line = () => Array.from({ length: 48 }, () => hex[Math.floor(Math.random() * 16)]).join("");
  return `${line()}\n${line()}\n${line()}`;
}

const surfaceInput: CSSProperties = {
  width: "100%",
  background: "var(--surface-2)",
  border: "1px solid var(--line)",
  borderRadius: 16,
  padding: "15px 16px",
  fontSize: 15,
  lineHeight: 1.55,
  color: "var(--fg)",
};

function segStyle(active: boolean): CSSProperties {
  return {
    height: 4,
    flex: 1,
    borderRadius: 999,
    background: active ? "var(--primary)" : "var(--line)",
  };
}

function pill(active: boolean): CSSProperties {
  return {
    padding: "7px 14px",
    borderRadius: 999,
    fontSize: 13.5,
    fontWeight: 500,
    color: active ? "var(--surface)" : "var(--fg-2)",
    background: active ? "var(--primary)" : "transparent",
  };
}

function viewPill(active: boolean): CSSProperties {
  return {
    flex: 1,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "0 4px",
    borderRadius: 9,
    fontSize: 13.5,
    fontWeight: 500,
    color: active ? "var(--fg)" : "var(--fg-2)",
    background: active ? "var(--surface)" : "transparent",
    border: active ? "1px solid var(--line)" : "1px solid transparent",
  };
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: multi-state composer UI; states are split into sub-views below
export function Create() {
  const [mode, setMode] = useState<Mode>("text");
  const [text, setText] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [dragging, setDragging] = useState(false);
  const [expiry, setExpiry] = useState("24h");
  const [viewsMode, setViewsMode] = useState<ViewsMode>("once");
  const [viewCount, setViewCount] = useState(2);
  const [pwEnabled, setPwEnabled] = useState(true);
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<CreatedShare | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<"link" | "pw" | null>(null);
  const [cipher, setCipher] = useState("");
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  // ramp the progress bar while encrypting / uploading
  useEffect(() => {
    if (phase === "encrypting" || phase === "uploading") {
      setProgress(phase === "encrypting" ? 4 : 62);
      if (phase === "encrypting") {
        setCipher(randomCipher());
      }
      timer.current = setInterval(() => {
        setProgress((p) => (p < 92 ? p + Math.max(1, Math.round((92 - p) / 8)) : p));
      }, 90);
    } else if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
    return () => {
      if (timer.current) {
        clearInterval(timer.current);
        timer.current = null;
      }
    };
  }, [phase]);

  const strength = passwordStrength(password);
  const strengthLabel = [
    "",
    t("create.strength_1"),
    t("create.strength_2"),
    t("create.strength_3"),
  ][strength];
  const createDisabled =
    phase !== "idle" ||
    (mode === "text" ? text.trim().length === 0 : files.length === 0) ||
    (pwEnabled && password.length === 0);

  function enablePw() {
    const next = !pwEnabled;
    setPwEnabled(next);
    if (next && !password) {
      setPassword(generatePassword());
    }
  }

  async function onCreate() {
    setError(null);
    try {
      let payload: SharePayload;
      if (mode === "file" && files.length > 0) {
        payload = {
          type: "file",
          files: await Promise.all(
            files.map(async (f) => ({
              name: f.name,
              mime: f.type || "application/octet-stream",
              data: new Uint8Array(await f.arrayBuffer()),
            }))
          ),
        };
      } else {
        payload = { type: "text", data: new TextEncoder().encode(text) };
      }
      const views = viewsMode === "once" ? 1 : viewsMode === "count" ? viewCount : null;
      const created = await createAndUpload(payload, {
        ttlSeconds: EXPIRY_SECONDS[expiry] ?? 86400,
        views,
        ...(pwEnabled ? { password } : {}),
        onPhase: (p) => setPhase(p),
      });
      setProgress(100);
      setResult(created);
      setPhase("success");
    } catch (e) {
      setError(e instanceof Error ? e.message : t("create.err_generic"));
      setPhase("error");
    }
  }

  function reset() {
    setPhase("idle");
    setResult(null);
    setProgress(0);
    setText("");
    setFiles([]);
    setPassword(pwEnabled ? generatePassword() : "");
  }

  async function copy(value: string, which: "link" | "pw") {
    await navigator.clipboard.writeText(value);
    setCopied(which);
    setTimeout(() => setCopied(null), 1600);
  }

  if (phase === "encrypting") {
    return (
      <Shell>
        <div
          className="anim"
          style={{ width: "100%", maxWidth: 440, margin: "0 auto", textAlign: "center" }}
        >
          <div
            style={{
              width: 66,
              height: 66,
              margin: "0 auto 22px",
              position: "relative",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <div
              style={{
                position: "absolute",
                inset: 0,
                borderRadius: "50%",
                border: "2px solid var(--primary-soft)",
                borderTopColor: "var(--primary)",
                animation: "spin 1s linear infinite",
              }}
            />
          </div>
          <h2
            style={{
              fontSize: 20,
              fontWeight: 600,
              margin: "0 0 6px",
              color: "var(--fg)",
              letterSpacing: "-.02em",
            }}
          >
            {t("create.encrypting")}
          </h2>
          <p style={{ fontSize: 13.5, color: "var(--fg-2)", margin: "0 0 18px", lineHeight: 1.5 }}>
            {t("create.encrypting_sub")}
          </p>
          <pre
            className="mono"
            style={{
              textAlign: "left",
              fontSize: 11,
              lineHeight: 1.5,
              color: "var(--fg-2)",
              background: "var(--surface-2)",
              border: "1px solid var(--line-2)",
              borderRadius: 12,
              padding: 13,
              overflow: "hidden",
              margin: "0 0 16px",
              letterSpacing: ".5px",
              opacity: 0.85,
            }}
          >
            {cipher}
          </pre>
          <Bar value={progress} />
          <div className="mono" style={{ fontSize: 11.5, color: "var(--fg-2)", marginTop: 8 }}>
            {t("create.encrypted_pct", { n: progress })}
          </div>
        </div>
      </Shell>
    );
  }

  if (phase === "uploading") {
    return (
      <Shell>
        <div
          className="anim"
          style={{ width: "100%", maxWidth: 440, margin: "0 auto", textAlign: "center" }}
        >
          <div
            style={{
              width: 66,
              height: 66,
              margin: "0 auto 22px",
              borderRadius: 20,
              background: "var(--primary-soft)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 26,
              color: "var(--primary)",
              animation: "floaty 1.6s ease-in-out infinite",
            }}
          >
            ↑
          </div>
          <h2
            style={{
              fontSize: 20,
              fontWeight: 600,
              margin: "0 0 6px",
              color: "var(--fg)",
              letterSpacing: "-.02em",
            }}
          >
            {t("create.uploading")}
          </h2>
          <p style={{ fontSize: 13.5, color: "var(--fg-2)", margin: "0 0 20px", lineHeight: 1.5 }}>
            {t("create.uploading_sub")}
          </p>
          <Bar value={progress} />
          <div className="mono" style={{ fontSize: 11.5, color: "var(--fg-2)", marginTop: 8 }}>
            {t("create.uploading_pct", { n: progress })}
          </div>
        </div>
      </Shell>
    );
  }

  if (phase === "success" && result) {
    const hashAt = result.url.indexOf("#");
    const linkBase = hashAt >= 0 ? result.url.slice(0, hashAt) : result.url;
    const linkFrag = hashAt >= 0 ? result.url.slice(hashAt) : "";
    return (
      <Shell>
        <div className="anim" style={{ width: "100%", maxWidth: 520, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 22 }}>
            <div
              style={{
                width: 58,
                height: 58,
                margin: "0 auto 14px",
                borderRadius: "50%",
                background: "var(--primary-soft)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                animation: "pop .5s cubic-bezier(.2,.8,.3,1.2) both",
                fontSize: 26,
                color: "var(--primary)",
              }}
            >
              ✓
            </div>
            <h2
              style={{
                fontSize: 22,
                fontWeight: 600,
                margin: "0 0 4px",
                color: "var(--fg)",
                letterSpacing: "-.02em",
              }}
            >
              {t("create.ready")}
            </h2>
          </div>

          <div style={{ fontSize: 12.5, color: "var(--fg-2)", marginBottom: 7 }}>
            {t("create.share_link")}
          </div>
          <div style={{ display: "flex", gap: 8, marginBottom: 6 }}>
            <div
              className="mono"
              style={{
                flex: 1,
                minWidth: 0,
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
                borderRadius: 12,
                padding: "12px 14px",
                fontSize: 13,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              <span style={{ color: "var(--fg)" }}>{linkBase}</span>
              <span style={{ color: "var(--primary)" }}>{linkFrag}</span>
            </div>
            <button type="button" onClick={() => copy(result.url, "link")} style={copyBtn}>
              {copied === "link" ? t("create.copied") : t("create.copy")}
            </button>
          </div>
          <p
            style={{
              fontSize: 11.5,
              color: "var(--fg-2)",
              margin: "0 0 20px",
              display: "flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <span className="mono" style={{ color: "var(--primary)" }}>
              #
            </span>
            {t("create.key_note")}
          </p>

          {result.password && (
            <div
              style={{
                border: "1px solid var(--warn-soft)",
                background: "var(--warn-soft)",
                borderRadius: 16,
                padding: "15px 16px",
                marginBottom: 20,
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 10,
                  color: "var(--warn)",
                  fontSize: 13,
                  fontWeight: 600,
                }}
              >
                <span
                  style={{
                    width: 17,
                    height: 17,
                    borderRadius: "50%",
                    background: "var(--warn)",
                    color: "var(--surface)",
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: 11,
                    fontWeight: 700,
                    flex: "none",
                  }}
                >
                  !
                </span>
                {t("create.pw_separate")}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <div
                  className="mono"
                  style={{
                    flex: 1,
                    minWidth: 0,
                    background: "var(--surface)",
                    border: "1px solid var(--line)",
                    borderRadius: 12,
                    padding: "12px 14px",
                    fontSize: 14,
                    color: "var(--fg)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {result.password}
                </div>
                <button
                  type="button"
                  onClick={() => copy(result.password ?? "", "pw")}
                  style={copyBtn}
                >
                  {copied === "pw" ? t("create.copied") : t("create.copy")}
                </button>
              </div>
              <p
                style={{
                  fontSize: 12,
                  color: "var(--warn)",
                  margin: "10px 0 0",
                  lineHeight: 1.45,
                  opacity: 0.9,
                }}
              >
                {t("create.pw_separate_note")}
              </p>
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "center" }}>
            <button
              type="button"
              onClick={reset}
              style={{
                background: "var(--surface-2)",
                border: "1px solid var(--line)",
                color: "var(--fg)",
                borderRadius: 999,
                padding: "11px 20px",
                fontSize: 14,
                fontWeight: 500,
              }}
            >
              {t("create.another")}
            </button>
          </div>
        </div>
      </Shell>
    );
  }

  // idle (composer)
  return (
    <Shell>
      <div className="anim" style={{ width: "100%", maxWidth: 520, margin: "0 auto" }}>
        <h1 className="hero-title">{t("create.title")}</h1>
        <p className="hero-sub" style={{ margin: "0 0 22px" }}>
          {t("create.subtitle_1")}
          <em>{t("create.subtitle_is")}</em>
          {t("create.subtitle_2")}
        </p>

        <div
          style={{
            display: "inline-flex",
            background: "var(--surface-2)",
            border: "1px solid var(--line-2)",
            borderRadius: 999,
            padding: 4,
            marginBottom: 14,
          }}
        >
          <button type="button" onClick={() => setMode("text")} style={pill(mode === "text")}>
            {t("create.text")}
          </button>
          <button type="button" onClick={() => setMode("file")} style={pill(mode === "file")}>
            {t("create.file")}
          </button>
        </div>

        {mode === "text" ? (
          <>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={5}
              placeholder={t("create.text_placeholder")}
              aria-label={t("create.title")}
              style={{ ...surfaceInput, minHeight: 132 }}
            />
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginTop: 7,
                fontSize: 11.5,
                color: "var(--fg-2)",
              }}
            >
              <span>{t("create.text_hint")}</span>
              <span className="mono">{text.length}</span>
            </div>
          </>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {files.map((f, i) => (
              <div
                key={`${f.name}-${f.size}-${i}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  background: "var(--surface-2)",
                  border: "1px solid var(--line)",
                  borderRadius: 16,
                  padding: "15px 16px",
                }}
              >
                <div
                  className="mono"
                  style={{
                    width: 42,
                    height: 50,
                    borderRadius: 8,
                    background: "var(--primary-soft)",
                    border: "1px solid var(--line)",
                    display: "flex",
                    alignItems: "flex-end",
                    justifyContent: "center",
                    paddingBottom: 6,
                    fontSize: 10,
                    color: "var(--primary)",
                    fontWeight: 600,
                    flex: "none",
                  }}
                >
                  {(f.name.split(".").pop() ?? "").slice(0, 4).toUpperCase()}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 14.5,
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
                    style={{ fontSize: 12, color: "var(--fg-2)", marginTop: 2 }}
                  >
                    {formatBytes(f.size)}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setFiles((prev) => prev.filter((_, j) => j !== i))}
                  aria-label={t("create.remove_file")}
                  style={{
                    color: "var(--fg-2)",
                    width: 32,
                    height: 32,
                    borderRadius: 999,
                    border: "1px solid var(--line)",
                    flex: "none",
                    fontSize: 14,
                  }}
                >
                  ✕
                </button>
              </div>
            ))}
            <label
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                if (e.dataTransfer.files.length > 0) {
                  setFiles((prev) => [...prev, ...Array.from(e.dataTransfer.files)]);
                }
              }}
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              style={{
                display: "block",
                textAlign: "center",
                cursor: "pointer",
                background: dragging ? "var(--primary-soft)" : "var(--surface-2)",
                border: `1.5px dashed ${dragging ? "var(--primary)" : "var(--line)"}`,
                borderRadius: 16,
                padding: files.length > 0 ? "18px 16px" : "30px 16px",
              }}
            >
              <input
                type="file"
                multiple
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    setFiles((prev) => [...prev, ...Array.from(e.target.files as FileList)]);
                  }
                  e.target.value = "";
                }}
                style={{ position: "absolute", width: 1, height: 1, opacity: 0 }}
                aria-label={t("create.drag")}
              />
              <div
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: 14,
                  background: "var(--primary-soft)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  margin: "0 auto 12px",
                  fontSize: 20,
                  color: "var(--primary)",
                }}
              >
                ↑
              </div>
              <div style={{ fontSize: 15, color: "var(--fg)", fontWeight: 500 }}>
                {t("create.drag")}
              </div>
              <div style={{ fontSize: 13, color: "var(--fg-2)", marginTop: 3 }}>
                {t("create.browse_1")}
                <span style={{ color: "var(--primary)", fontWeight: 500 }}>
                  {t("create.browse_link")}
                </span>
                {t("create.browse_2")}
              </div>
            </label>
          </div>
        )}

        <div style={{ marginTop: 20, display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 150 }}>
              <div style={{ fontSize: 12.5, color: "var(--fg-2)", marginBottom: 7 }}>
                {t("create.expires")}
              </div>
              <div style={{ position: "relative" }}>
                <select
                  value={expiry}
                  onChange={(e) => setExpiry(e.target.value)}
                  aria-label={t("create.expires")}
                  style={{
                    width: "100%",
                    height: 44,
                    background: "var(--surface-2)",
                    border: "1px solid var(--line)",
                    borderRadius: 12,
                    padding: "0 32px 0 13px",
                    fontSize: 14,
                    color: "var(--fg)",
                  }}
                >
                  <option value="1h">{t("create.exp_1h")}</option>
                  <option value="24h">{t("create.exp_24h")}</option>
                  <option value="7d">{t("create.exp_7d")}</option>
                  <option value="30d">{t("create.exp_30d")}</option>
                </select>
                <span
                  style={{
                    position: "absolute",
                    right: 12,
                    top: "50%",
                    transform: "translateY(-50%)",
                    pointerEvents: "none",
                    color: "var(--fg-2)",
                    fontSize: 10,
                  }}
                >
                  ▾
                </span>
              </div>
            </div>
            <div style={{ flex: 1, minWidth: 150 }}>
              <div style={{ fontSize: 12.5, color: "var(--fg-2)", marginBottom: 7 }}>
                {t("create.views")}
              </div>
              <div
                style={{
                  display: "flex",
                  gap: 6,
                  height: 44,
                  background: "var(--surface-2)",
                  border: "1px solid var(--line)",
                  borderRadius: 12,
                  padding: 4,
                }}
              >
                <button
                  type="button"
                  onClick={() => setViewsMode("once")}
                  style={viewPill(viewsMode === "once")}
                >
                  {t("create.views_once")}
                </button>
                <button
                  type="button"
                  onClick={() => setViewsMode("count")}
                  style={viewPill(viewsMode === "count")}
                >
                  {t("create.views_number")}
                </button>
                <button
                  type="button"
                  onClick={() => setViewsMode("unlimited")}
                  style={viewPill(viewsMode === "unlimited")}
                >
                  ∞
                </button>
              </div>
            </div>
          </div>

          {viewsMode === "count" && (
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: -4 }}>
              <span style={{ fontSize: 13, color: "var(--fg-2)" }}>
                {t("create.destroy_after")}
              </span>
              <div
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 2,
                  background: "var(--surface-2)",
                  border: "1px solid var(--line)",
                  borderRadius: 999,
                  padding: 3,
                }}
              >
                <button
                  type="button"
                  onClick={() => setViewCount((v) => Math.max(2, v - 1))}
                  aria-label="−"
                  style={{
                    width: 30,
                    height: 30,
                    borderRadius: 999,
                    color: "var(--fg)",
                    fontSize: 16,
                  }}
                >
                  −
                </button>
                <span
                  className="mono"
                  style={{ minWidth: 30, textAlign: "center", fontSize: 14, color: "var(--fg)" }}
                >
                  {viewCount}
                </span>
                <button
                  type="button"
                  onClick={() => setViewCount((v) => Math.min(99, v + 1))}
                  aria-label="+"
                  style={{
                    width: 30,
                    height: 30,
                    borderRadius: 999,
                    color: "var(--fg)",
                    fontSize: 16,
                  }}
                >
                  +
                </button>
              </div>
              <span style={{ fontSize: 13, color: "var(--fg-2)" }}>{t("create.views_word")}</span>
            </div>
          )}

          <div style={{ borderTop: "1px solid var(--line-2)", paddingTop: 16 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
              }}
            >
              <div>
                <div style={{ fontSize: 14, color: "var(--fg)", fontWeight: 500 }}>
                  {t("create.pw_title")}
                </div>
                <div style={{ fontSize: 12.5, color: "var(--fg-2)", marginTop: 2 }}>
                  {t("create.pw_sub")}
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={pwEnabled}
                onClick={enablePw}
                aria-label={t("create.pw_title")}
                style={{
                  width: 44,
                  height: 26,
                  borderRadius: 999,
                  background: pwEnabled ? "var(--primary)" : "var(--line)",
                  padding: 3,
                  flex: "none",
                  transition: "background .2s",
                }}
              >
                <span
                  style={{
                    display: "block",
                    width: 20,
                    height: 20,
                    borderRadius: "50%",
                    background: "#fff",
                    transform: pwEnabled ? "translateX(18px)" : "none",
                    transition: "transform .2s",
                  }}
                />
              </button>
            </div>

            {pwEnabled && (
              <div className="anim" style={{ marginTop: 13 }}>
                <div style={{ display: "flex", gap: 8, alignItems: "stretch" }}>
                  <div
                    style={{
                      flex: 1,
                      position: "relative",
                      display: "flex",
                      alignItems: "center",
                      background: "var(--surface-2)",
                      border: "1px solid var(--line)",
                      borderRadius: 12,
                      padding: "0 6px 0 13px",
                    }}
                  >
                    <input
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      type={showPw ? "text" : "password"}
                      placeholder={t("create.pw_placeholder")}
                      className="mono"
                      aria-label={t("view.password")}
                      style={{
                        flex: 1,
                        background: "none",
                        border: 0,
                        padding: "12px 0",
                        fontSize: 14,
                        color: "var(--fg)",
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPw((s) => !s)}
                      aria-label={showPw ? t("create.hide") : t("create.show")}
                      style={{
                        color: "var(--fg-2)",
                        fontSize: 12,
                        padding: "6px 8px",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {showPw ? t("create.hide") : t("create.show")}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => setPassword(generatePassword())}
                    title={t("create.generate")}
                    style={{
                      flex: "none",
                      background: "var(--primary-soft)",
                      color: "var(--primary)",
                      border: "1px solid var(--line)",
                      borderRadius: 12,
                      padding: "0 14px",
                      fontSize: 13,
                      fontWeight: 500,
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                    }}
                  >
                    {t("create.generate")}
                  </button>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 9 }}>
                  <div style={{ display: "flex", gap: 4, flex: 1 }}>
                    <span style={segStyle(strength >= 1)} />
                    <span style={segStyle(strength >= 2)} />
                    <span style={segStyle(strength >= 3)} />
                  </div>
                  <span style={{ fontSize: 11.5, color: "var(--fg-2)" }}>{strengthLabel}</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {error && (
          <p
            style={{ color: "var(--warn)", fontSize: 13, margin: "14px 0 0", textAlign: "center" }}
          >
            {error}
          </p>
        )}

        <button
          type="button"
          onClick={onCreate}
          disabled={createDisabled}
          style={{
            width: "100%",
            marginTop: 18,
            background: "var(--primary)",
            color: "#fff",
            border: 0,
            borderRadius: 14,
            padding: "15px 0",
            fontSize: 15,
            fontWeight: 600,
            opacity: createDisabled ? 0.5 : 1,
            cursor: createDisabled ? "not-allowed" : "pointer",
          }}
        >
          {t("create.submit")}
        </button>
        <p
          style={{ textAlign: "center", fontSize: 11.5, color: "var(--fg-2)", margin: "11px 0 0" }}
        >
          {t("create.fragment_note_1")}
          <span className="mono">#fragment</span>
          {t("create.fragment_note_2")}
        </p>
      </div>
    </Shell>
  );
}

function Bar({ value }: { value: number }) {
  return (
    <div
      style={{
        height: 8,
        borderRadius: 999,
        background: "var(--surface-2)",
        overflow: "hidden",
        border: "1px solid var(--line-2)",
      }}
    >
      <div
        style={{
          height: "100%",
          width: `${value}%`,
          background: "var(--primary)",
          borderRadius: 999,
          transition: "width .1s linear",
        }}
      />
    </div>
  );
}

const copyBtn: CSSProperties = {
  flex: "none",
  background: "var(--primary)",
  color: "#fff",
  borderRadius: 12,
  padding: "0 16px",
  fontSize: 13,
  fontWeight: 600,
};
