// Entry point for the pdf.js worker chunk. It exists so the bundler sees a *local* module
// to turn into a worker (`?worker`), while the bare specifier resolves normally in here —
// Rolldown will not apply `?worker`/`?url` to a bare specifier directly.
import "pdfjs-dist/build/pdf.worker.min.mjs";
