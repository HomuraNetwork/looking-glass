import { recordDownloadLink, recordDownloadLinkExtension, recordOperation } from "./audit";
import { Env } from "./config";
import { challengeError, challengeStatusCode, createChallengeVerifier } from "./challenge";
import { getNode } from "./db";
import { clientIP, json, readJSON } from "./http";
import { inspectJobTarget } from "./ip-guard";
import { normalizeJobCount } from "./job-options";
import { consumeRateLimit } from "./rate-limit";
import { getRuntimeJWK } from "./runtime-secrets";
import { LIVE_SESSION_TTL_SECONDS, signLiveSessionToken } from "./session-token";
import { kidFromJWK, sha256Hex, signCompact } from "./signing";

const DOWNLOAD_TTL_SECONDS = 900;
const DOWNLOAD_EXTENSION_SECONDS = 600;
const DOWNLOAD_MAX_EXTENSIONS = 2;
const JOB_TTL_SECONDS = 300;
const DOWNLOAD_LINK_LIMIT = 6;
const DOWNLOAD_LINK_WINDOW_SECONDS = 60;
const JOB_TOKEN_LIMIT = 6;
const JOB_TOKEN_WINDOW_SECONDS = 60;
const LIVE_SESSION_LIMIT = 4;
const LIVE_SESSION_WINDOW_SECONDS = 60;

interface DownloadRequest {
  node: string;
  size?: string;
  turnstile_token?: string;
}

interface DownloadExtendRequest {
  node: string;
  link_id: string;
  token: string;
}

interface LiveSessionRequest {
  node: string;
  turnstile_token?: string;
}

export async function handleLiveSession(request: Request, env: Env): Promise<Response> {
  const body = await readJSON<LiveSessionRequest>(request);
  if (!body.node) return json({ error: "node_required" }, { status: 400 });
  const node = await getNode(env.DB, body.node);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;
  const challenge = await createChallengeVerifier(env.DB).verify({
    token: body.turnstile_token,
    request,
    idempotencyKey: crypto.randomUUID(),
  });
  if (challenge.status !== "success") {
    return json({ error: challengeError(challenge.status), provider: challenge.provider }, { status: challengeStatusCode(challenge.status) });
  }

  const rateLimit = await consumeRateLimit({
    db: env.DB,
    action: "live_session",
    node: internalNodeID,
    clientIP: clientIP(request),
    limit: LIVE_SESSION_LIMIT,
    windowSeconds: LIVE_SESSION_WINDOW_SECONDS,
  });
  if (!rateLimit.allowed) return json({ error: "rate_limited", reset_at: rateLimit.resetAt }, { status: 429 });

  const { token, exp } = await signLiveSessionToken({ node: internalNodeID, clientIP: clientIP(request), env });
  const sessionID = `lvs_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  await recordOperation(env.DB, {
    id: sessionID,
    operationType: "live_session",
    node: internalNodeID,
    clientIP: clientIP(request),
    status: "issued",
    metadata: { ttl_seconds: LIVE_SESSION_TTL_SECONDS },
    createdAt: exp - LIVE_SESSION_TTL_SECONDS,
    expiresAt: exp,
  });
  return json({ token, expires_at: exp, node: node.id, domain: node.domain });
}

interface JobRequest {
  node: string;
  tool: string;
  target: string;
  ipver: string;
  count: number;
  remote_dns?: boolean;
  turnstile_token?: string;
}

const allowedSizes = new Set(["10M", "100M", "1G"]);
const allowedTools = new Set(["ping", "mtr", "traceroute", "nexttrace"]);

export async function handleDownloadToken(request: Request, env: Env): Promise<Response> {
  const body = await readJSON<DownloadRequest>(request);
  if (body.size && !allowedSizes.has(body.size)) return json({ error: "invalid_size" }, { status: 400 });
  const node = await getNode(env.DB, body.node);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;
  const challenge = await createChallengeVerifier(env.DB).verify({
    token: body.turnstile_token,
    request,
    idempotencyKey: crypto.randomUUID(),
  });
  if (challenge.status !== "success") {
    return json({ error: challengeError(challenge.status), provider: challenge.provider }, { status: challengeStatusCode(challenge.status) });
  }

  const rateLimit = await consumeRateLimit({
    db: env.DB,
    action: "download_link",
    node: internalNodeID,
    clientIP: clientIP(request),
    limit: DOWNLOAD_LINK_LIMIT,
    windowSeconds: DOWNLOAD_LINK_WINDOW_SECONDS,
  });
  if (!rateLimit.allowed) return json({ error: "rate_limited", reset_at: rateLimit.resetAt }, { status: 429 });

  const now = Math.floor(Date.now() / 1000);
  const tokenJwk = await getRuntimeJWK(env.DB, "LG_TOKEN_SIGN_JWK");
  const linkID = `dl_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const claims = downloadClaims({
    node: internalNodeID,
    clientIP: clientIP(request),
    kid: await kidFromJWK(tokenJwk),
    exp: now + DOWNLOAD_TTL_SECONDS,
    linkID,
  });
  const token = await signCompact(claims, tokenJwk);
  await recordDownloadLink(env.DB, {
    id: linkID,
    node: internalNodeID,
    size: "any",
    token,
    clientIP: clientIP(request),
    createdAt: now,
    expiresAt: claims.exp,
  });
  await recordOperation(env.DB, {
    id: linkID,
    operationType: "download_link",
    node: internalNodeID,
    clientIP: clientIP(request),
    status: "issued",
    metadata: { sizes: [...allowedSizes] },
    createdAt: now,
    expiresAt: claims.exp,
  });
  return json({
    token,
    expires_at: claims.exp,
    node: node.id,
    domain: node.domain,
    link_id: linkID,
    sizes: [...allowedSizes],
    extensions_remaining: DOWNLOAD_MAX_EXTENSIONS,
  });
}

export async function handleDownloadTokenExtend(request: Request, env: Env): Promise<Response> {
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<DownloadExtendRequest>(request);
  if (!body.node || !body.link_id || !body.token) return json({ error: "download_link_required" }, { status: 400 });
  const node = await getNode(env.DB, body.node);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;
  const ip = clientIP(request);
  const clientHash = (await sha256Hex(ip)).slice(0, 16);
  const tokenHash = await sha256Hex(body.token);
  const row = await env.DB.prepare(
    `SELECT id, expires_at, extension_count, status
     FROM download_links
     WHERE id = ? AND node_id = ? AND client_ip_hash = ? AND token_hash = ?`,
  )
    .bind(body.link_id, internalNodeID, clientHash, tokenHash)
    .first<{ id: string; expires_at: number; extension_count: number; status: string }>();
  if (!row) return json({ error: "download_link_not_found" }, { status: 404 });
  const now = Math.floor(Date.now() / 1000);
  if (row.status !== "active") return json({ error: "download_link_inactive", status: row.status }, { status: 409 });
  if (row.expires_at <= now) {
    await env.DB.prepare("UPDATE download_links SET status = 'expired' WHERE id = ?").bind(row.id).run();
    return json({ error: "download_link_expired" }, { status: 410 });
  }
  if (row.extension_count >= DOWNLOAD_MAX_EXTENSIONS) {
    return json({ error: "download_link_extension_limit", extensions_remaining: 0 }, { status: 409 });
  }
  const nextExpiresAt = Math.max(row.expires_at, now) + DOWNLOAD_EXTENSION_SECONDS;
  const tokenJwk = await getRuntimeJWK(env.DB, "LG_TOKEN_SIGN_JWK");
  const claims = downloadClaims({
    node: internalNodeID,
    clientIP: ip,
    kid: await kidFromJWK(tokenJwk),
    exp: nextExpiresAt,
    linkID: row.id,
  });
  const token = await signCompact(claims, tokenJwk);
  const extended = await recordDownloadLinkExtension(env.DB, {
    id: row.id,
    node: internalNodeID,
    clientHash,
    previousTokenHash: tokenHash,
    token,
    expiresAt: claims.exp,
    extendedAt: now,
    maxExtensions: DOWNLOAD_MAX_EXTENSIONS,
  });
  if (!extended) {
    const current = await env.DB.prepare("SELECT extension_count, status, expires_at FROM download_links WHERE id = ?").bind(row.id).first<{
      extension_count: number;
      status: string;
      expires_at: number;
    }>();
    if (!current) return json({ error: "download_link_not_found" }, { status: 404 });
    if (current.status !== "active") return json({ error: "download_link_inactive", status: current.status }, { status: 409 });
    if (current.expires_at <= now) return json({ error: "download_link_expired" }, { status: 410 });
    if (current.extension_count >= DOWNLOAD_MAX_EXTENSIONS) {
      return json({ error: "download_link_extension_limit", extensions_remaining: 0 }, { status: 409 });
    }
    return json({ error: "download_link_not_found" }, { status: 404 });
  }
  const nextExtensionCount = extended.extension_count;
  await recordOperation(env.DB, {
    id: `dlx_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`,
    operationType: "download_link",
    node: internalNodeID,
    clientIP: ip,
    status: "extended",
    metadata: { link_id: row.id, extension_count: nextExtensionCount },
    createdAt: now,
    expiresAt: claims.exp,
  });
  return json({
    token,
    expires_at: claims.exp,
    node: node.id,
    domain: node.domain,
    link_id: row.id,
    sizes: [...allowedSizes],
    extensions_remaining: Math.max(0, DOWNLOAD_MAX_EXTENSIONS - nextExtensionCount),
  });
}

function downloadClaims(input: { node: string; clientIP: string; kid: string; exp: number; linkID: string }) {
  return {
    typ: "download",
    kid: input.kid,
    node: input.node,
    size: "*",
    link_id: input.linkID,
    ip: input.clientIP,
    ip_binding: "relaxed",
    exp: input.exp,
    nonce: crypto.randomUUID().replaceAll("-", ""),
  };
}

export async function handleJobToken(request: Request, env: Env): Promise<Response> {
  const body = await readJSON<JobRequest>(request);
  if (!allowedTools.has(body.tool)) return json({ error: "invalid_tool" }, { status: 400 });
  const node = await getNode(env.DB, body.node);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;
  const challenge = await createChallengeVerifier(env.DB).verify({
    token: body.turnstile_token,
    request,
    idempotencyKey: crypto.randomUUID(),
  });
  if (challenge.status !== "success") {
    return json({ error: challengeError(challenge.status), provider: challenge.provider }, { status: challengeStatusCode(challenge.status) });
  }

  const rateLimit = await consumeRateLimit({
    db: env.DB,
    action: "job_token",
    node: internalNodeID,
    clientIP: clientIP(request),
    limit: JOB_TOKEN_LIMIT,
    windowSeconds: JOB_TOKEN_WINDOW_SECONDS,
  });
  if (!rateLimit.allowed) return json({ error: "rate_limited", reset_at: rateLimit.resetAt }, { status: 429 });

  const guard = await inspectJobTarget({ target: body.target, ipver: body.ipver, remoteDNS: body.remote_dns === true }, env.DB);
  if (!guard.allowed) {
    return json({ error: guard.error, checked_ips: guard.checkedIPs }, { status: guard.status || 403 });
  }
  const count = normalizeJobCount(body.count);
  const now = Math.floor(Date.now() / 1000);
  const tokenJwk = await getRuntimeJWK(env.DB, "LG_TOKEN_SIGN_JWK");
  const claims = {
    typ: "job",
    kid: await kidFromJWK(tokenJwk),
    node: internalNodeID,
    tool: body.tool,
    target: guard.target,
    ipver: body.ipver,
    count,
    remote_dns: body.remote_dns === true,
    ip: clientIP(request),
    ip_binding: "relaxed",
    exp: now + JOB_TTL_SECONDS,
    nonce: crypto.randomUUID().replaceAll("-", ""),
  };
  const token = await signCompact(claims, tokenJwk);
  const jobID = `job_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  await recordOperation(env.DB, {
    id: jobID,
    operationType: "job",
    node: internalNodeID,
    clientIP: clientIP(request),
    status: "token_issued",
    metadata: {
      tool: body.tool,
      target: guard.target,
      ipver: body.ipver,
      count,
      remote_dns: body.remote_dns === true,
      checked_ips: guard.checkedIPs,
    },
    createdAt: now,
    expiresAt: claims.exp,
  });
  return json({ token, expires_at: claims.exp, node: node.id, domain: node.domain, job_id: jobID });
}
