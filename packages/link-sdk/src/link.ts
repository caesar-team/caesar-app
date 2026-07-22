/**
 * Builds a share URL of the form `<baseUrl>/s/<id>#<fragment>`. The fragment is
 * the zero-knowledge secret and, living after `#`, is never sent to the server.
 */
export function buildShareUrl(baseUrl: string, id: string, fragment: string): string {
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  return `${base}/s/${id}#${fragment}`;
}

/**
 * Parses a share URL, returning the share id and the fragment (with the leading
 * `#` stripped). Throws if the fragment is missing or the path has no `/s/<id>`.
 */
export function parseShareUrl(url: string): { id: string; fragment: string } {
  const parsed = new URL(url);
  const fragment = parsed.hash.slice(1);
  if (fragment === "") throw new Error(`Share URL has no fragment: ${url}`);
  const segments = parsed.pathname.split("/");
  const sIndex = segments.indexOf("s");
  const id = segments[sIndex + 1];
  if (sIndex === -1 || id === undefined || id === "") {
    throw new Error(`Share URL has no /s/<id> segment: ${url}`);
  }
  return { id, fragment };
}
