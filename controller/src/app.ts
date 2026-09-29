import { Env, ServiceConfigError } from "./config";
import { renewManagedCertificates } from "./acme";
import { nudgeExpiringCertificateNodes } from "./cert-renewal";
import { availabilityProbeEnabled, probeNodeAvailability, sweepStaleNodes } from "./availability";
import { handleAgentArtifact, handleAgentDownload, handleAgentUpdate } from "./agent-download";
import { handleDepsRequest } from "./deps-download";
import { handleAdminCertificates, handleAdminDNSSettings, handleAdminNodeCheck, handleAdminNodeDNS, handleAdminNodeEvents, handleAdminNodeInitToken, handleAdminNodeReorder, handleAdminNodes, handleAdminProjectSettings, handleAdminRuntimeSecrets } from "./admin-api";
import { databaseReady, dbInitRequiredResponse, handleAdminDatabaseInit, inspectDatabase } from "./db-bootstrap";
import {
  handleAdminLogin,
  handleAdminLogout,
  handleAdminSession,
  handleAdminSetup,
  handleAdminUserPassword,
  handleAdminUsers,
  handleAdminUserTotpReset,
  handleAdminUserTotpSetup,
} from "./admin-auth";
import { handleAdminNodeInit } from "./admin-init";
import { handleClientInfo } from "./client-info";
import { handleAdminNodeCertificate, handleNodeControlCertAck, handleNodeControlCertBundle } from "./certificates";
import { listNodes } from "./db";
import { handleEnroll } from "./enroll";
import { json, methodNotAllowed, notFound, RequestError } from "./http";
import { handleIperfSession, handleIperfSessionClose, handleIperfSessionWebSocket } from "./iperf";
import { handleJobWebSocketProxy, handleLiveJobWebSocket, liveJobDebugEnabled } from "./job-proxy";
import { workerDebug, workerError, workerLog, workerWarn } from "./log";
import { runRetentionCleanup } from "./retention";
import { handleNodeControlConfig, handleNodeControlKeyset, handleNodeControlSync } from "./node-control";
import { getPublicBrandingConfig, getStringProjectSetting, type PublicBrandingConfig } from "./project-settings";
import { getRuntimeSecret } from "./runtime-secrets";
import { handleJobToken, handleDownloadToken, handleDownloadTokenExtend, handleLiveSession } from "./tokens";
import { themeStyleTag } from "./theme";
import type { HTMLTransform, SocketRuntime, TcpRuntime } from "./runtime";

/**
 * Runtime capabilities the request path needs beyond the Web platform. The
 * Cloudflare entry supplies WebSocketPair + HTMLRewriter; the local entry
 * supplies `ws` + a string transform.
 */
export interface AppRuntime {
  sockets: SocketRuntime;
  transformHTML(response: Response, transform: HTMLTransform): Promise<Response>;
  /**
   * One-shot outbound TCP queries (ASN enrichment). Optional: a runtime without
   * it simply skips enrichment rather than failing the job.
   */
  tcp?: TcpRuntime;
  /**
   * Schedule background work that must outlive the response (Cloudflare:
   * ctx.waitUntil; local: fire-and-forget). Optional; callers that omit it
   * simply skip background follow-ups.
   */
  waitUntil?(task: Promise<unknown>): void;
}

/**
 * Single cron pass. Retention deletes are idempotent/bounded, renewal is gated
 * by certificate freshness, and availability writes only on flips, so running
 * every pass on the same schedule is safe and simple.
 */
export async function runScheduledPass(env: Env): Promise<void> {
  try {
    const deleted = await runRetentionCleanup(env.DB);
    workerLog("retention.complete", { ...deleted });
  } catch (error) {
    workerLog("retention.error", { error: error instanceof Error ? error.message : "retention_failed" });
  }
  // Each step is isolated: a transient ACME outage must not skip this pass's
  // certificate nudges or the availability sweep, and vice versa.
  try {
    await renewManagedCertificates(env);
  } catch (error) {
    workerWarn("cert.renew_error", { error: error instanceof Error ? error.message : "renewal_failed" });
  }
  // After renewal, nudge nodes whose certificate is nearing expiry so they pull
  // the new bundle promptly rather than waiting for the healthy poll.
  try {
    await nudgeExpiringCertificateNodes(env);
  } catch (error) {
    workerWarn("cert.nudge_error", { error: error instanceof Error ? error.message : "nudge_failed" });
  }
  await runAvailabilityPass(env);
}

/**
 * Availability pass: probe reachable nodes and sweep for stale ones. Safe to
 * run anytime (state is only written on flips), so it runs as part of the
 * single cron pass.
 */
async function runAvailabilityPass(env: Env): Promise<void> {
  try {
    if (await availabilityProbeEnabled(env.DB)) {
      await probeNodeAvailability(env);
    }
    await sweepStaleNodes(env);
  } catch (error) {
    workerWarn("availability.probe_error", { error: error instanceof Error ? error.message : "probe_failed" });
  }
}

const FALLBACK_PUBLIC_CONFIG = {
  branding: {
    site_name: "Looking Glass",
    logo_text: "LG",
    logo_image_url: null,
    brand_name: "",
    show_brand_name: false,
    nav_items: [{ label: "Looking Glass", href: "/", active: true }],
    theme: "homura",
    page_title: null,
    favicon_url: null,
    page_title_mode: "site_only" as const,
    meta_description: null,
    meta_keywords: null,
    og_image_url: null,
    twitter_image_url: null,
  },
  challenge: {
    provider: "turnstile" as const,
    site_key: "",
    required: false,
  },
  debug: { streams: false },
};

export async function buildPublicConfig(env: Env) {
  if (!env.DB) {
    return FALLBACK_PUBLIC_CONFIG;
  }
  if (!databaseReady(await inspectDatabase(env.DB))) {
    return FALLBACK_PUBLIC_CONFIG;
  }
  const [branding, turnstileSecret, turnstileSiteKey, streams] = await Promise.all([
    getPublicBrandingConfig(env.DB),
    getRuntimeSecret(env.DB, "TURNSTILE_SECRET_KEY"),
    getStringProjectSetting(env.DB, "TURNSTILE_SITE_KEY"),
    liveJobDebugEnabled(env.DB),
  ]);
  return {
    branding,
    challenge: {
      provider: "turnstile" as const,
      site_key: turnstileSiteKey || "",
      required: Boolean(turnstileSecret),
    },
    debug: { streams },
  };
}

// Inline the public config into the served HTML so the SPA paints the correct
// branding on first render instead of flashing the built-in defaults, and set a
// branding-derived <title>. Branding values still come from D1 project_settings.
export function buildPageTitle(branding: PublicBrandingConfig): string {
  const { site_name, brand_name, page_title, page_title_mode } = branding;
  if (page_title_mode === "custom" && page_title) return page_title;
  if (page_title_mode === "site_brand" && brand_name) return `${site_name} - ${brand_name}`;
  if (page_title_mode === "brand_site" && brand_name) return `${brand_name} ${site_name}`;
  return site_name;
}

// Escape a value for safe interpolation into a double-quoted HTML attribute.
// Branding values come from admin-editable D1 project settings, so any value
// that reaches the HTML must be escaped here regardless of other validation.
export function escapeHTMLAttr(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * URL fields are additionally protocol-validated: only https:// absolute URLs
 * or site-relative paths ("/...") are allowed. Anything else (javascript:,
 * data:, unknown schemes) drops the tag entirely rather than emitting a
 * mangled attribute.
 */
export function safeHTMLURL(value: string | null | undefined): string | null {
  if (!value) return null;
  // Protocol-relative URLs ("//evil.com") resolve against the page scheme
  // and point off-site, so a leading "/" only counts when it is a single
  // slash (site-relative path).
  if (value.startsWith("https://") || (value.startsWith("/") && !value.startsWith("//"))) return value;
  return null;
}

const DEFAULT_PUBLIC_META_DESCRIPTION =
  "Network diagnostics for Looking Glass nodes: ping, MTR, traceroute, RTT probes, download tests, and iPerf3.";

/**
 * Build the head/title injection from the public config. Runtime-neutral: the
 * Cloudflare entry applies it with HTMLRewriter and the local entry with a
 * string transform, both producing the same output for our own HTML shell.
 */
export function buildHTMLTransform(config: Awaited<ReturnType<typeof buildPublicConfig>>, requestUrl: string): HTMLTransform {
  const branding = config.branding;
  const title = buildPageTitle(branding);
  const description = branding.meta_description?.trim() || DEFAULT_PUBLIC_META_DESCRIPTION;
  const bootJson = JSON.stringify(config).replace(/</g, "\\u003c");
  const styleTag = themeStyleTag(branding.theme);
  const faviconURL = safeHTMLURL(branding.favicon_url);
  const faviconLink = faviconURL ? `<link rel="icon" type="image/x-icon" href="${escapeHTMLAttr(faviconURL)}">` : "";

  const metaTags: string[] = [];
  metaTags.push(`<meta name="description" content="${escapeHTMLAttr(description)}">`);
  if (branding.meta_keywords) {
    metaTags.push(`<meta name="keywords" content="${escapeHTMLAttr(branding.meta_keywords)}">`);
  }

  // Open Graph
  metaTags.push(`<meta property="og:title" content="${escapeHTMLAttr(title)}">`);
  metaTags.push(`<meta property="og:description" content="${escapeHTMLAttr(description)}">`);
  const ogImageURL = safeHTMLURL(branding.og_image_url);
  if (ogImageURL) {
    metaTags.push(`<meta property="og:image" content="${escapeHTMLAttr(ogImageURL)}">`);
  }
  // og:url is derived from the request URL itself; it is escaped anyway so a
  // hostile Host header cannot inject into the attribute.
  metaTags.push(`<meta property="og:url" content="${escapeHTMLAttr(requestUrl)}">`);
  metaTags.push(`<meta property="og:type" content="website">`);

  // Twitter Card
  const twitterImageURL = safeHTMLURL(branding.twitter_image_url) ?? ogImageURL;
  if (twitterImageURL) {
    metaTags.push(`<meta name="twitter:card" content="summary_large_image">`);
    metaTags.push(`<meta name="twitter:title" content="${escapeHTMLAttr(title)}">`);
    metaTags.push(`<meta name="twitter:description" content="${escapeHTMLAttr(description)}">`);
    metaTags.push(`<meta name="twitter:image" content="${escapeHTMLAttr(twitterImageURL)}">`);
  }

  const headHTML = [faviconLink, metaTags.join("\n"), styleTag, `<script>window.__LG_BOOT__=${bootJson}</script>`]
    .filter((part) => part.length > 0)
    .join("\n");

  return { title, headHTML };
}

/**
 * Route and handle one request. Runtime-agnostic: everything platform-specific
 * (socket pairs, HTML rewriting) is reached through `runtime`.
 */
export async function handleRequest(request: Request, env: Env, runtime: AppRuntime): Promise<Response> {
  const url = new URL(request.url);
  const requestID = crypto.randomUUID();
  const startedAt = Date.now();
  await workerDebug(env.DB, "request.start", { request_id: requestID, method: request.method, url: request.url });

  try {
    let response: Response;
    if (url.pathname === "/api/nodes") {
      if (request.method !== "GET") response = methodNotAllowed();
      else if (!env.DB) response = json({ error: "d1_required" }, { status: 503 });
      else {
        const dbStatus = await inspectDatabase(env.DB);
        response = databaseReady(dbStatus) ? json(await listNodes(env.DB)) : dbInitRequiredResponse(dbStatus);
      }
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/public-config") {
      if (request.method !== "GET") response = methodNotAllowed();
      else response = json(await buildPublicConfig(env));
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/token/download") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleDownloadToken(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/token/download/extend") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleDownloadTokenExtend(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/token/job") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleJobToken(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/jobs/live-session") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleLiveSession(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_lg/enroll") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleEnroll(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_agent/download") {
      response = await handleAgentDownload(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_agent/update") {
      response = await handleAgentUpdate(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname.startsWith("/_agent/")) {
      response = await handleAgentArtifact(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname.startsWith("/deps/")) {
      response = await handleDepsRequest(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_lg/control/config") {
      response = await handleNodeControlConfig(request, env, runtime);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_lg/control/keyset") {
      response = await handleNodeControlKeyset(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_lg/control/cert-bundle") {
      response = await handleNodeControlCertBundle(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_lg/control/cert/ack") {
      response = await handleNodeControlCertAck(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/_lg/control/sync") {
      response = await handleNodeControlSync(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/iperf/session") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleIperfSession(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/iperf/session/close") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleIperfSessionClose(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/iperf/session/ws") {
      response = request.method !== "GET" ? methodNotAllowed() : await handleIperfSessionWebSocket(request, env, runtime.sockets);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/jobs/ws") {
      response = request.method !== "GET" ? methodNotAllowed() : await handleJobWebSocketProxy(request, env, runtime.sockets);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/jobs/live") {
      response = request.method !== "GET" ? methodNotAllowed() : await handleLiveJobWebSocket(request, env, runtime.sockets, runtime.tcp);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/session") {
      response = await handleAdminSession(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/setup") {
      response = await handleAdminSetup(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/db/init") {
      response = await handleAdminDatabaseInit(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/login") {
      response = await handleAdminLogin(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/logout") {
      response = await handleAdminLogout(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/users") {
      response = await handleAdminUsers(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/users/password") {
      response = await handleAdminUserPassword(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/users/totp/setup") {
      response = await handleAdminUserTotpSetup(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/users/totp/reset") {
      response = await handleAdminUserTotpReset(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/nodes") {
      response = await handleAdminNodes(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/nodes/reorder") {
      response = await handleAdminNodeReorder(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/nodes/events") {
      response = await handleAdminNodeEvents(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/nodes/check") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleAdminNodeCheck(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/nodes/init") {
      response = await handleAdminNodeInitToken(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/dns-settings") {
      response = await handleAdminDNSSettings(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/runtime-secrets") {
      response = await handleAdminRuntimeSecrets(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/project-settings") {
      response = await handleAdminProjectSettings(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/nodes/dns") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleAdminNodeDNS(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/nodes/cert") {
      response = await handleAdminNodeCertificate(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/certificates") {
      response = await handleAdminCertificates(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/admin/init/node") {
      response = request.method !== "POST" ? methodNotAllowed() : await handleAdminNodeInit(request, env);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (url.pathname === "/api/client-info") {
      response = request.method !== "GET" ? methodNotAllowed() : await handleClientInfo(request, runtime.tcp);
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    if (env.ASSETS && request.method === "GET") {
      const assetResponse = await env.ASSETS.fetch(request);
      if (assetResponse.headers.get("content-type")?.includes("text/html")) {
        const transformed = await runtime.transformHTML(assetResponse, buildHTMLTransform(await buildPublicConfig(env), request.url));
        const headers = new Headers(transformed.headers);
        headers.set("cache-control", "no-store");
        response = new Response(transformed.body, { status: transformed.status, statusText: transformed.statusText, headers });
      } else {
        response = assetResponse;
      }
      workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
      return response;
    }
    response = notFound();
    workerLog("request.complete", { request_id: requestID, method: request.method, url: request.url, status: response.status, duration_ms: Date.now() - startedAt });
    return response;
  } catch (error) {
    if (error instanceof RequestError) {
      const response = json({ error: error.message }, { status: error.status });
      workerLog("request.error", {
        request_id: requestID,
        method: request.method,
        url: request.url,
        status: response.status,
        duration_ms: Date.now() - startedAt,
        error: error.message,
      });
      return response;
    }
    if (error instanceof ServiceConfigError) {
      // The setting name stays server-side only; clients only need the
      // generic "service_unconfigured" signal to show the unavailable UI.
      const response = json({ error: "service_unconfigured" }, { status: 503 });
      workerWarn("request.error", {
        request_id: requestID,
        method: request.method,
        url: request.url,
        status: response.status,
        duration_ms: Date.now() - startedAt,
        error: "service_unconfigured",
        missing: error.setting,
      });
      return response;
    }
    const errorMessage = error instanceof Error ? error.message : "internal_error";
    const response = json({ error: "internal_error" }, { status: 500 });
    workerError("request.error", {
      request_id: requestID,
      method: request.method,
      url: request.url,
      status: response.status,
      duration_ms: Date.now() - startedAt,
      error: errorMessage,
    });
    return response;
  }
}
