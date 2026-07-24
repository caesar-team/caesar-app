import type { SharedFile } from "@caesar/link-sdk";
import { type CSSProperties, Suspense, lazy, useEffect, useMemo, useState } from "react";
import { t } from "../i18n.js";
import { isPDF } from "../lib/attachmentType.js";

// The Markdown pipeline is the heaviest thing in the app; keep it out of the main bundle.
const MarkdownBody = lazy(() =>
  import("./MarkdownBody.js").then((m) => ({ default: m.MarkdownBody }))
);

/** `%PDF-`, optionally after the leading junk some generators emit. */
function hasPDFSignature(data: Uint8Array): boolean {
  const head = new TextDecoder("latin1").decode(data.subarray(0, 1024));
  return head.includes("%PDF-");
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

const card: CSSProperties = {
  background: "var(--surface-2)",
  border: "1px solid var(--line)",
  borderRadius: 16,
  padding: "18px 18px 14px",
};

/**
 * Renders a Markdown or PDF attachment inline instead of making the recipient download a
 * file just to read it. Download stays available for both.
 */
export function AttachmentPreview({
  file,
  onDownload,
}: {
  file: SharedFile;
  onDownload: () => void;
}) {
  // Trust the bytes, not the sender's labelling: only a real %PDF- signature gets the
  // PDF treatment. Anything else falls back to the Markdown/text body, so a file merely
  // *named* .pdf can never pick the branch that embeds it as a document.
  const claimsPDF = isPDF(file.name, file.mime);
  const pdf = claimsPDF && hasPDFSignature(file.data);
  // Named .pdf but not actually one: refuse to preview rather than decoding the bytes as
  // text and rendering binary noise as Markdown.
  const unpreviewable = claimsPDF && !pdf;
  const [copied, setCopied] = useState(false);

  // Blob URLs leak until revoked; tie the lifetime to this component.
  const objectURL = useMemo(() => {
    if (!pdf) return null;
    // The type is ours, not the sender's: Chrome honours it for blob URLs, so the bytes
    // are handed to the built-in PDF viewer and can never be interpreted as HTML.
    return URL.createObjectURL(new Blob([file.data as BlobPart], { type: "application/pdf" }));
  }, [pdf, file.data]);

  useEffect(() => {
    return () => {
      if (objectURL) URL.revokeObjectURL(objectURL);
    };
  }, [objectURL]);

  const text = useMemo(
    () => (claimsPDF ? "" : new TextDecoder().decode(file.data)),
    [claimsPDF, file.data]
  );

  async function copyText() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="anim" style={{ width: "100%", maxWidth: 640, margin: "0 auto" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          marginBottom: 12,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <h2
            style={{
              fontSize: 18,
              fontWeight: 600,
              margin: 0,
              color: "var(--fg)",
              letterSpacing: "-.02em",
              whiteSpace: "nowrap",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {file.name}
          </h2>
          <div className="mono" style={{ fontSize: 12, color: "var(--fg-2)", marginTop: 3 }}>
            {formatBytes(file.data.length)} · {t("view.decrypted_suffix")}
          </div>
        </div>
        <span
          style={{
            fontSize: 11.5,
            color: "var(--ok)",
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            flex: "none",
          }}
        >
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--ok)" }} />
          {t("view.in_browser")}
        </span>
      </div>

      {pdf && objectURL ? (
        // No `sandbox` attribute on purpose. Chrome refuses to run its built-in PDF viewer
        // inside a sandboxed frame — measured: `sandbox=""` and `sandbox="allow-scripts"`
        // both render nothing at all, which is why this previewed as a broken document.
        // Safety comes from the payload instead: the bytes start with %PDF-, and the blob
        // MIME we set forces the PDF viewer, so there is no HTML parsing path to abuse.
        <iframe
          src={objectURL}
          title={file.name}
          style={{
            width: "100%",
            height: 520,
            border: "1px solid var(--line)",
            borderRadius: 16,
            background: "var(--surface-2)",
          }}
        />
      ) : unpreviewable ? (
        <div style={{ ...card, color: "var(--fg-2)", fontSize: 13.5, textAlign: "center" }}>
          {t("view.no_preview")}
        </div>
      ) : (
        <div style={{ ...card, color: "var(--fg)", fontSize: 14 }}>
          <Suspense fallback={<div style={{ color: "var(--fg-2)" }}>{t("view.decrypting")}</div>}>
            <MarkdownBody source={text} />
          </Suspense>
        </div>
      )}

      <div style={{ display: "flex", gap: 10, marginTop: 14 }}>
        <button type="button" onClick={onDownload} style={primary}>
          {t("view.download")}
        </button>
        {!claimsPDF && (
          <button type="button" onClick={copyText} style={secondary}>
            {copied ? t("view.copied") : t("view.copy_text")}
          </button>
        )}
      </div>

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
  );
}

const primary: CSSProperties = {
  flex: 1,
  height: 46,
  borderRadius: 999,
  background: "var(--primary)",
  color: "#fff",
  fontSize: 14.5,
  fontWeight: 600,
  border: 0,
};

const secondary: CSSProperties = {
  flex: 1,
  height: 46,
  borderRadius: 999,
  background: "transparent",
  color: "var(--fg)",
  fontSize: 14.5,
  fontWeight: 500,
  border: "1px solid var(--line)",
};
