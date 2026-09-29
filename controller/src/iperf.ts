import { signedAgentRequest } from "./admin";
import { closeIperfSessionAudit, expireOpenIperfSessions, recordOperation } from "./audit";
import { challengeError, challengeStatusCode, createChallengeVerifier } from "./challenge";
import { Env } from "./config";
import { getNode } from "./db";
import { clientIP, dbBindingMissing, json, readJSON } from "./http";
import { fetchNode, nodeOrigin, nodeURL } from "./node-transport";
import { consumeRateLimit } from "./rate-limit";
import { sha256Hex } from "./signing";
import type { SocketRuntime } from "./runtime";

const IPERF_SESSION_LIMIT = 3;
const IPERF_SESSION_WINDOW_SECONDS = 60;

interface IperfRequest {
  node: string;
  mode: string;
  udp?: boolean;
  direction?: string;
  reverse?: boolean;
  duration: number;
  parallel: number;
  turnstile_token?: string;
}

export async function handleIperfSession(request: Request, env: Env): Promise<Response> {
  const body = await readJSON<IperfRequest>(request);
  const mode = normalizeMode(body);
  if (!mode) return json({ error: "invalid_iperf_mode" }, { status: 400 });
  const reverse = body.reverse === true || body.direction === "reverse" || body.direction === "r" || body.mode === "r";
  const node = await getNode(env.DB, body.node);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;
  const duration = clampNumber(body.duration, 1, 40);
  const parallel = clampNumber(body.parallel, 1, 10);
  const ip = clientIP(request);
  await expireOpenIperfSessions(env.DB);

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
    action: "iperf_session",
    node: internalNodeID,
    clientIP: ip,
    limit: IPERF_SESSION_LIMIT,
    windowSeconds: IPERF_SESSION_WINDOW_SECONDS,
  });
  if (!rateLimit.allowed) return json({ error: "rate_limited", reset_at: rateLimit.resetAt }, { status: 429 });

  const sessionID = `ipf_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const agentBody = JSON.stringify({
    session_id: sessionID,
    client_ip: ip,
    mode,
    direction: reverse ? "reverse" : (body.direction ?? "download"),
    reverse,
    duration,
    parallel,
    ttl: 180,
    max_runs: 4,
    run_budget: 200,
  });
  const path = "/_lg/control/iperf/open";
  // This selects the node's HTTPS control endpoint. The iperf data port is
  // returned separately by the agent in `payload.port` below.
  const agentRequest = await signedAgentRequest(env.DB, {
    method: "POST",
    url: `${nodeOrigin(node.domain, node.port)}${path}`,
    path,
    nodeID: internalNodeID,
    body: agentBody,
  });
  const agentResponse = await fetchNode({
    domain: node.domain,
    port: node.port,
    path,
    init: agentRequest,
  });
  if (!agentResponse.ok) return json({ error: "agent_iperf_open_failed" }, { status: 502 });
  const responseBody = await agentResponse.text();
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(responseBody) as Record<string, unknown>;
  } catch {
    return json({ error: "agent_iperf_open_bad_response" }, { status: 502 });
  }

  // Persist the agent-selected measurement port, not the HTTPS control port.
  if (env.DB) {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO iperf_sessions (id, node_id, client_ip_hash, port, status, created_at, expires_at)
       VALUES (?, ?, ?, ?, 'open', ?, ?)`,
    )
      .bind(sessionID, internalNodeID, (await sha256Hex(ip)).slice(0, 16), payload.port ?? null, now, payload.expires_at ?? null)
      .run();
    await recordOperation(env.DB, {
      id: sessionID,
      operationType: "iperf_session",
      node: internalNodeID,
      clientIP: ip,
      status: "open",
      metadata: { mode, reverse, duration, parallel, port: payload.port ?? null },
      createdAt: now,
      expiresAt: typeof payload.expires_at === "number" ? payload.expires_at : undefined,
    });
  }
  return json(payload);
}

export async function handleIperfSessionClose(request: Request, env: Env): Promise<Response> {
  if (!env.DB) return dbBindingMissing();
  await expireOpenIperfSessions(env.DB);
  const body = await readJSON<{ node?: string; session_id?: string }>(request);
  const nodeID = body.node?.trim() || "";
  const sessionID = body.session_id?.trim() || "";
  if (!nodeID || !sessionID) return json({ error: "missing_iperf_session" }, { status: 400 });
  const node = await getNode(env.DB, nodeID);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;

  const ip = clientIP(request);
  const clientHash = (await sha256Hex(ip)).slice(0, 16);
  const session = await env.DB
    .prepare("SELECT status FROM iperf_sessions WHERE id = ? AND node_id = ? AND client_ip_hash = ?")
    .bind(sessionID, internalNodeID, clientHash)
    .first<{ status: string }>();
  if (!session) return json({ error: "iperf_session_not_found" }, { status: 404 });
  if (session.status !== "open") return json({ ok: true, session_id: sessionID, status: session.status });

  const path = "/_lg/control/iperf/close";
  const agentBody = JSON.stringify({ session_id: sessionID });
  const agentRequest = await signedAgentRequest(env.DB, {
    method: "POST",
    url: `${nodeOrigin(node.domain, node.port)}${path}`,
    path,
    nodeID: internalNodeID,
    body: agentBody,
  });
  const agentResponse = await fetchNode({
    domain: node.domain,
    port: node.port,
    path,
    init: agentRequest,
  });
  if (!agentResponse.ok) return json({ error: "agent_iperf_close_failed" }, { status: 502 });
  const responseBody = await agentResponse.text();

  await closeIperfSessionAudit(env.DB, { id: sessionID, status: "closed_by_request", reason: "closed_by_request" });
  let payload: Record<string, unknown> = {};
  try {
    payload = JSON.parse(responseBody) as Record<string, unknown>;
  } catch {
    payload = { ok: true };
  }
  return json({ ...payload, session_id: sessionID, status: "closed_by_request" });
}

export async function handleIperfSessionWebSocket(request: Request, env: Env, sockets: SocketRuntime): Promise<Response> {
  if (!env.DB) return dbBindingMissing();
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return json({ error: "websocket_upgrade_required" }, { status: 400 });
  }
  const url = new URL(request.url);
  const nodeID = url.searchParams.get("node") || "";
  const sessionID = url.searchParams.get("session_id") || "";
  if (!nodeID || !sessionID) return json({ error: "missing_iperf_session" }, { status: 400 });
  const node = await getNode(env.DB, nodeID);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;
  const ip = clientIP(request);
  const clientHash = (await sha256Hex(ip)).slice(0, 16);
  const session = await env.DB
    .prepare("SELECT status FROM iperf_sessions WHERE id = ? AND node_id = ? AND client_ip_hash = ?")
    .bind(sessionID, internalNodeID, clientHash)
    .first<{ status: string }>();
  if (!session) return json({ error: "iperf_session_not_found" }, { status: 404 });
  if (session.status !== "open") return json({ error: "iperf_session_inactive", status: session.status }, { status: 409 });
  const path = "/_lg/control/iperf/events";
  const fullPath = `${path}?session_id=${encodeURIComponent(sessionID)}`;
  const agentRequest = await signedAgentRequest(env.DB, {
    method: "GET",
    url: `${nodeOrigin(node.domain, node.port)}${fullPath}`,
    path,
    nodeID: internalNodeID,
    body: "",
    headers: { upgrade: "websocket" },
  });
  // Do not attach AbortSignal.timeout() to an upgraded WebSocket. The signal
  // would remain live after the 101 response and abort the established event
  // stream when the timeout fires.
  const signedHeaders: Record<string, string> = {};
  agentRequest.headers.forEach((value, key) => {
    signedHeaders[key] = value;
  });
  const agent = await sockets.connectWebSocket(nodeURL(node.domain, node.port, fullPath), {
    method: "GET",
    headers: signedHeaders,
  });
  if (!agent) return json({ error: "agent_iperf_websocket_failed" }, { status: 502 });
  const pair = await sockets.createSocketPair();
  const browser = pair.server;
  let closedRecorded = false;
  const recordClosed = (status: string, reason?: string) => {
    if (closedRecorded) return;
    closedRecorded = true;
    void closeIperfSessionAudit(env.DB, { id: sessionID, status, reason });
  };
  browser.accept({ allowHalfOpen: true });
  agent.accept({ allowHalfOpen: true });
  // This is an agent-to-browser event stream. The browser has no control
  // messages, so never relay client frames into the agent session protocol.
  agent.addEventListener("message", (event) => {
    const message = String(event.data);
    const status = iperfCloseStatus(message);
    if (status) recordClosed(status.status, status.reason);
    browser.send(event.data as string);
  });
  browser.addEventListener("close", () => {
    recordClosed("browser_closed", "browser_websocket_closed");
    void closeAgentIperfSession(env, node, sessionID);
    agent.close();
  });
  agent.addEventListener("close", () => {
    recordClosed("closed", "agent_websocket_closed");
    browser.close();
  });
  browser.addEventListener("error", () => {
    recordClosed("browser_error", "browser_websocket_error");
    void closeAgentIperfSession(env, node, sessionID);
    agent.close();
  });
  agent.addEventListener("error", () => {
    recordClosed("agent_error", "agent_websocket_error");
    browser.close();
  });
  return pair.upgradeResponse();
}

function normalizeMode(body: IperfRequest): "tcp" | "udp" | null {
  const raw = body.udp ? "udp" : (body.mode || "tcp").toLowerCase();
  if (raw === "tcp" || raw === "r" || raw === "reverse") return "tcp";
  if (raw === "udp") return "udp";
  return null;
}

function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

async function closeAgentIperfSession(env: Env, node: { internal_id: string; domain: string; port?: number }, sessionID: string): Promise<void> {
  const path = "/_lg/control/iperf/close";
  const agentBody = JSON.stringify({ session_id: sessionID });
  const agentRequest = await signedAgentRequest(env.DB, {
    method: "POST",
    url: `${nodeOrigin(node.domain, node.port)}${path}`,
    path,
    nodeID: node.internal_id,
    body: agentBody,
  });
  await fetchNode({
    domain: node.domain,
    port: node.port,
    path,
    init: agentRequest,
  });
}

function iperfCloseStatus(message: string): { status: string; reason: string } | null {
  try {
    const frame = JSON.parse(message) as { type?: unknown; event?: unknown; status?: unknown; reason?: unknown; close_reason?: unknown; line?: unknown };
    const type = String(frame.type ?? frame.event ?? "");
    if (type !== "closed" && type !== "close") return null;
    const status = typeof frame.status === "string" && frame.status.trim() ? frame.status.trim() : "closed";
    const reason =
      typeof frame.reason === "string" && frame.reason.trim()
        ? frame.reason.trim()
        : typeof frame.close_reason === "string" && frame.close_reason.trim()
          ? frame.close_reason.trim()
        : typeof frame.line === "string" && frame.line.trim()
          ? frame.line.trim()
          : status;
    return { status, reason };
  } catch {
    return null;
  }
}
