import { readFile, stat } from "node:fs/promises";
import { extname, normalize, resolve } from "node:path";
import type { AssetServer } from "../src/runtime";

/**
 * Serve built assets from disk, mirroring the Cloudflare assets config:
 * "/" maps to index.html, and extensionless paths fall back to the SPA shell
 * the same way `not_found_handling: "single-page-application"` does on
 * Cloudflare (so /admin and /admin/ are routable). Paths with an extension
 * (hashed assets, fonts) 404 when missing instead of returning HTML.
 */
export function fileAssetServer(root: string): AssetServer {
  const rootPath = resolve(root);
  const index = resolve(rootPath, "index.html");
  const notFound = () => new Response("not found", { status: 404 });
  return {
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      let pathname = decodeURIComponent(url.pathname);
      // Directory-style paths ("/", "/admin/") map to index.html directly.
      const directoryLike = pathname.endsWith("/");
      if (directoryLike) pathname += "index.html";
      // Prevent path traversal: resolve then confirm the result stays under root.
      const target = resolve(rootPath, "." + normalize(pathname));
      if (target !== rootPath && !target.startsWith(rootPath + "/")) return notFound();
      try {
        const info = await stat(target);
        if (info.isFile()) {
          const body = await readFile(target);
          return new Response(body, { status: 200, headers: { "content-type": contentType(target) } });
        }
      } catch {
        // fall through to the SPA fallback below
      }
      const lastSegment = pathname.split("/").pop() ?? "";
      if (!directoryLike && lastSegment.includes(".")) return notFound();
      try {
        const body = await readFile(index);
        return new Response(body, { status: 200, headers: { "content-type": contentType(index) } });
      } catch {
        return notFound();
      }
    },
  };
}

function contentType(path: string): string {
  switch (extname(path)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".ico":
      return "image/x-icon";
    case ".woff2":
      return "font/woff2";
    default:
      return "application/octet-stream";
  }
}
