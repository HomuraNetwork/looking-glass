import { Env } from "./config";
import { json, methodNotAllowed, notFound } from "./http";
import { fetchNexttraceRelease, type NexttraceReleaseAsset } from "./nexttrace-release";

const ALLOWED = /^hlg-iperf3-linux-(amd64|arm64)$/;
const LICENSE_URL = "/THIRD_PARTY_LICENSES.txt";
interface Entry { tool: string; arch: string; sha256: string; size_bytes: number }

export async function handleDepsRequest(request: Request, env: Env, getRelease: () => Promise<NexttraceReleaseAsset[]> = fetchNexttraceRelease): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") return methodNotAllowed();
  const url = new URL(request.url);
  const name = url.pathname.slice("/deps/".length);
  if (!env.ASSETS) return json({ error: "assets_required" }, { status: 503 });

  if (name === "manifest.json") {
    let data: { tools?: Record<string, Entry | null> } = {};
    try {
      const response = await env.ASSETS.fetch(new Request(new URL("/_deps/manifest.json", url.origin)));
      if (response.ok && !response.headers.get("content-type")?.includes("text/html")) {
        data = (await response.json()) as { tools?: Record<string, Entry | null> };
      }
    } catch {
      // Bundled dependencies are optional when running the local controller.
    }

    const entries = data?.tools && typeof data.tools === "object" && !Array.isArray(data.tools) ? data.tools : {};
    const files = Object.entries(entries)
      .filter(([file, entry]) => ALLOWED.test(file) && entry?.tool === "iperf3" && /^(amd64|arm64)$/.test(entry.arch) && /^[a-f0-9]{64}$/i.test(entry.sha256) && Number.isSafeInteger(entry.size_bytes) && entry.size_bytes > 0)
      .map(([file, entry]) => ({ name: file, tool: entry!.tool, arch: entry!.arch, sha256: entry!.sha256, size: entry!.size_bytes, url: `/deps/${file}`, license_url: LICENSE_URL }));

    let upstream: NexttraceReleaseAsset[] = [];
    try {
      upstream = await getRelease();
    } catch (error) {
      console.error("NextTrace latest release metadata is unavailable", error);
    }
    const validUpstream = upstream.length === 2
      && new Set(upstream.map((entry) => entry.arch)).size === 2
      && upstream.every((entry) => (entry.arch === "amd64" || entry.arch === "arm64")
        && entry.tool === "nexttrace"
        && entry.name === `nexttrace_linux_${entry.arch}`
        && /^v\d+(?:\.\d+){1,3}$/.test(entry.version)
        && /^[a-f0-9]{64}$/i.test(entry.sha256)
        && Number.isSafeInteger(entry.size) && entry.size > 0);
    if (!validUpstream) upstream = [];
    if (files.length === 0 && upstream.length === 0) return depsUnavailable();

    const result = json({
      version: 2,
      static: files,
      upstream: upstream.map((entry) => ({ ...entry, url: `https://github.com/nxtrace/NTrace-core/releases/download/${entry.version}/${entry.name}` })),
    }, { headers: { "cache-control": "no-store" } });
    return request.method === "HEAD" ? new Response(null, { status: 200, headers: result.headers }) : result;
  }

  if (!ALLOWED.test(name)) return notFound();
  const response = await env.ASSETS.fetch(new Request(new URL(`/_deps/${name}`, url.origin), { method: request.method }));
  if (!response.ok || response.headers.get("content-type")?.includes("text/html")) return notFound();
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  headers.set("content-type", "application/octet-stream");
  headers.set("link", `<${LICENSE_URL}>; rel="license"`);
  return new Response(request.method === "HEAD" ? null : response.body, { status: 200, headers });
}

function depsUnavailable(): Response {
  return json({ error: "deps_unavailable" }, { status: 503 });
}
