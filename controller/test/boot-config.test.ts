import { describe, expect, it } from "vitest";
import type { Env } from "../src/config";
import worker from "../src/index";

// injectBootConfig uses HTMLRewriter, which only exists in the Workers
// runtime. This minimal polyfill records what the handlers append/set so the
// tests can assert on the transformed HTML.
interface PolyfillElement {
  appended: string[];
  setInnerContent(value: string): void;
  append(html: string): void;
}

class HTMLRewriterPolyfill {
  private handlers: Array<{ selector: string; handler: unknown }> = [];
  on(selector: string, handler: unknown): this {
    this.handlers.push({ selector, handler });
    return this;
  }
  transform(response: Response): Response {
    const handlers = this.handlers;
    const stream = new ReadableStream({
      async start(controller) {
        const originalHTML = await response.text();
        let html = originalHTML;
        const element: PolyfillElement = {
          appended: [],
          setInnerContent(value: string) {
            html = html.replace(/<title>[\s\S]*?<\/title>/, `<title>${value}</title>`);
          },
          append(injected: string) {
            element.appended.push(injected);
          },
        };
        for (const { handler } of handlers) {
          (handler as { element(el: PolyfillElement): void }).element(element);
        }
        controller.enqueue(new TextEncoder().encode(html.replace("</head>", `${element.appended.join("")}</head>`)));
        controller.close();
      },
    });
    return new Response(stream, { headers: response.headers });
  }
}
(globalThis as { HTMLRewriter?: unknown }).HTMLRewriter = HTMLRewriterPolyfill;

// The SPA HTML is served from the ASSETS binding with injectBootConfig
// rewriting the <head>; a fake asset response exercises that pipeline without
// the real static build.
const HTML_PAGE = `<!doctype html><html><head><title>placeholder</title></head><body><div id="app"></div></body></html>`;

function assetsFake(): Fetcher {
  return {
    fetch: () => Promise.resolve(new Response(HTML_PAGE, { headers: { "content-type": "text/html; charset=utf-8" } })),
  } as unknown as Fetcher;
}

const env = {} as Env;

const REQUIRED_TABLES = [
  "nodes", "node_profiles", "enroll_tokens", "certificate_bundles",
  "node_certificate_bundles", "iperf_sessions", "rate_limits", "download_links",
  "operation_audit", "audit_logs", "admin_users", "admin_sessions", "used_totp_codes",
  "project_settings", "runtime_secrets", "node_init_tokens", "node_tokens",
  "acme_pending_orders", "node_events",
];

/**
 * D1 stub tailored to the boot-config path: the sqlite_master probe reports a
 * complete schema, project_settings returns the given rows, and everything
 * else (runtime_secrets etc.) reads as empty.
 */
function bootConfigD1(settings: Array<{ key: string; value_json: string }>): D1Database {
  return {
    prepare: (sql: string) => {
      const result = {
        async all<T>() {
          if (sql.includes("sqlite_master")) {
            return { results: REQUIRED_TABLES.map((name) => ({ name })), success: true, meta: {} } as unknown as D1Result<T>;
          }
          if (sql.includes("FROM project_settings")) {
            return { results: settings, success: true, meta: {} } as unknown as D1Result<T>;
          }
          return { results: [], success: true, meta: {} } as unknown as D1Result<T>;
        },
        async first<T>() {
          return null as T | null;
        },
      };
      return {
        bind: () => result,
        ...result,
      };
    },
  } as unknown as D1Database;
}

async function fetchPage(url: string, settings: Array<{ key: string; value_json: string }> = []): Promise<Response> {
  return worker.fetch(new Request(url), { ...env, DB: bootConfigD1(settings), ASSETS: assetsFake() });
}

async function head(response: Response): Promise<string> {
  const html = await response.text();
  return html.slice(0, html.indexOf("</head>"));
}

describe("injectBootConfig branding escaping", () => {
  it("marks dynamic HTML as non-cacheable", async () => {
    const response = await fetchPage("http://worker.test/");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("drops a favicon_url that is not https:// or site-relative", async () => {
    const response = await fetchPage("http://worker.test/", [
      { key: "PUBLIC_FAVICON_URL", value_json: JSON.stringify('"><script>alert(1)</script>') },
    ]);
    expect(response.status).toBe(200);
    const headHTML = await head(response);
    expect(headHTML).not.toContain("<link rel=\"icon\"");
    // The payload may still travel inside the inert JSON boot config, but it
    // must not appear as an emitted HTML attribute value.
    expect(headHTML).not.toContain('href=""><script');
    expect(headHTML).not.toContain("<script>alert(1)");
  });

  it("escapes a hostile favicon_url that still passes the URL prefix check", async () => {
    const response = await fetchPage("http://worker.test/", [
      { key: "PUBLIC_FAVICON_URL", value_json: JSON.stringify("https://cdn.example.test/a.png?x=\" onerror=\"alert(1)") },
    ]);
    const headHTML = await head(response);
    expect(headHTML).toContain('href="https://cdn.example.test/a.png?x=&quot; onerror=&quot;alert(1)"');
  });

  it("escapes quotes in meta_description and meta_keywords", async () => {
    const response = await fetchPage("http://worker.test/", [
      { key: "PUBLIC_META_DESCRIPTION", value_json: JSON.stringify('desc "with quotes" <b>bold</b>') },
      { key: "PUBLIC_META_KEYWORDS", value_json: JSON.stringify("kw & <tag>") },
    ]);
    const headHTML = await head(response);
    expect(headHTML).toContain('content="desc &quot;with quotes&quot; &lt;b&gt;bold&lt;/b&gt;"');
    expect(headHTML).toContain('content="kw &amp; &lt;tag&gt;"');
    expect(headHTML.match(/<meta name="description"/g)).toHaveLength(1);
  });

  it("emits a default description when none is configured", async () => {
    const response = await fetchPage("http://worker.test/");
    const headHTML = await head(response);
    expect(headHTML).toContain('name="description" content="Network diagnostics for Looking Glass nodes: ping, MTR, traceroute, RTT probes, download tests, and iPerf3."');
    expect(headHTML.match(/<meta name="description"/g)).toHaveLength(1);
  });

  it("builds og:url from the request URL escaped, so hostile query input cannot inject", async () => {
    const response = await fetchPage("http://worker.test/?q=abc&x=1");
    const headHTML = await head(response);
    expect(headHTML).toMatch(/<meta property="og:url" content="http:\/\/worker\.test\/\?q=abc&amp;x=1">/);
    expect(headHTML).not.toContain("<script>alert(1)");
  });

  it("drops og/twitter image URLs with disallowed schemes instead of emitting them", async () => {
    const response = await fetchPage("http://worker.test/", [
      { key: "PUBLIC_OG_IMAGE_URL", value_json: JSON.stringify("javascript:alert(1)") },
      { key: "PUBLIC_TWITTER_IMAGE_URL", value_json: JSON.stringify("data:image/svg+xml,<svg onload=alert(1)>") },
      // Protocol-relative URLs point off-site despite the leading slash.
      { key: "PUBLIC_FAVICON_URL", value_json: JSON.stringify("//evil.example.test/favicon.ico") },
    ]);
    const headHTML = await head(response);
    expect(headHTML).not.toContain('property="og:image"');
    expect(headHTML).not.toContain('name="twitter:image"');
    expect(headHTML).not.toContain('rel="icon"');
  });

  it("keeps legitimate https and relative image URLs", async () => {
    const response = await fetchPage("http://worker.test/", [
      { key: "PUBLIC_FAVICON_URL", value_json: JSON.stringify("/favicon.ico") },
      { key: "PUBLIC_OG_IMAGE_URL", value_json: JSON.stringify("https://cdn.example.test/og.png") },
      { key: "PUBLIC_TWITTER_IMAGE_URL", value_json: JSON.stringify("/twitter.png") },
    ]);
    const headHTML = await head(response);
    expect(headHTML).toContain('href="/favicon.ico"');
    expect(headHTML).toContain('content="https://cdn.example.test/og.png"');
    expect(headHTML).toContain('content="/twitter.png"');
  });
});
