import { useEffect, useMemo, useRef, useState } from "react";
import { Document, Page, pdfjs } from "react-pdf";
import { t } from "../i18n.js";
import PdfWorker from "../lib/pdfWorker.ts?worker";

// Parsing runs in a worker, off the main thread and out of the page's context. The worker
// is bundled as one of our own chunks (see lib/pdfWorker.ts), so nothing is fetched from a
// third-party origin and there is no CDN to go down.
pdfjs.GlobalWorkerOptions.workerPort = new PdfWorker();

/**
 * Renders a shared PDF as plain page images.
 *
 * The browser's own viewer would work, but it arrives with a toolbar, a sidebar and zoom
 * controls that have nothing to do with reading one shared document — and its availability
 * varies by browser. Drawing the pages ourselves keeps the viewer looking like the rest of
 * the app and behaves the same everywhere.
 *
 * The document also comes from whoever created the link, so: no annotation layer (that is
 * where link and JavaScript actions live) and `isEvalSupported: false`.
 */
export function PdfBody({ data }: { data: Uint8Array }) {
  const [pages, setPages] = useState(0);
  const [failed, setFailed] = useState(false);
  const [width, setWidth] = useState(0);
  const host = useRef<HTMLDivElement>(null);

  // react-pdf re-fetches whenever this identity changes, so keep it stable.
  const file = useMemo(() => ({ data }), [data]);
  const options = useMemo(() => ({ isEvalSupported: false }), []);

  useEffect(() => {
    const element = host.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry) setWidth(entry.contentRect.width);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  if (failed) {
    return <div style={{ color: "var(--fg-2)", fontSize: 13.5 }}>{t("view.no_preview")}</div>;
  }

  return (
    <div ref={host} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <Document
        file={file}
        options={options}
        onLoadSuccess={({ numPages }) => setPages(numPages)}
        onLoadError={() => setFailed(true)}
        loading={<div style={{ color: "var(--fg-2)" }}>{t("view.decrypting")}</div>}
        error={<div style={{ color: "var(--fg-2)" }}>{t("view.no_preview")}</div>}
      >
        {Array.from({ length: pages }, (_, i) => (
          <Page
            key={`page-${i + 1}`}
            pageNumber={i + 1}
            width={width || undefined}
            renderAnnotationLayer={false}
            renderTextLayer={false}
            loading=""
            // Pages are white sheets on a dark page; round them so they sit in the layout.
            canvasBackground="#ffffff"
            className="pdf-page"
          />
        ))}
      </Document>
    </div>
  );
}
