import { recordOperation } from "./audit";
import { lookupAsns, canonicalIPKey } from "./asn";
import { getNode } from "./db";
import { clientIP, json } from "./http";
import { inspectJobTarget, isIPAddress } from "./ip-guard";
import { reportNodeUnavailable } from "./availability";
import { normalizeJobCount } from "./job-options";
import { getBooleanProjectSetting } from "./project-settings";
import { getRuntimeJWK } from "./runtime-secrets";
import { nodeOrigin, nodeURL } from "./node-transport";
import { relaxedIPMatch, verifyLiveSessionToken } from "./session-token";
import { consumeRateLimit } from "./rate-limit";
import { base64URLToBytes, kidFromJWK, signCompact } from "./signing";
import { compactTracerouteHop, parseTracerouteHop, type TracerouteHop } from "./traceroute";
import type { Env } from "./config";
import type { ProxiedSocket, SqlDatabase, SocketRuntime, TcpRuntime } from "./runtime";

const allowedLiveTools = new Set(["ping", "mtr", "traceroute", "nexttrace"]);

export function agentJobWebSocketTarget(domain: string, port: number, token: string) {
  return {
    url: nodeURL(domain, port, `/jobs/${encodeURIComponent(token)}/ws`),
    // The agent accepts its signed domain as Origin without a port. The URL
    // still uses the node's configured port for the actual connection.
    headers: { upgrade: "websocket", origin: nodeOrigin(domain) },
  };
}
/** Per-connection command budget: generous for interactive terminals. */
export const LIVE_JOB_COMMAND_LIMIT = 10;
export const LIVE_JOB_COMMAND_WINDOW_SECONDS = 60;

/**
 * Control frames carry out-of-band events (currently just job completion) and
 * are never rendered as terminal output. They must not be gated on debug
 * streams: the browser has to learn a job finished even when debug is off.
 *
 * The browser only talks to the worker (browser <- worker <- agent), and the
 * agent's job socket closing is the authoritative "job finished" signal, so the
 * worker emits this frame when it observes that close.
 */
export type LiveJobStream = "stdout" | "debug" | "control";
export type LiveJobControlEvent = "complete";
type LiveJobFrameMode = "command" | "replace" | "append";

/**
 * Optional structural tag so the client can dispatch on the frame TYPE instead
 * of guessing from the line text. Only mtr output is tagged today: an mtr row
 * and a traceroute hop line look alike, but only mtr carries kind "mtr" (with
 * its hop number, used for stable ordering when hops arrive out of order).
 */
export type LiveJobFrameKind = "mtr" | "mtr-header" | "traceroute";

export interface LiveJobFrameOptions {
  mode?: LiveJobFrameMode;
  key?: string;
  kind?: LiveJobFrameKind;
  /** mtr hop number; used to order rows that arrive out of sequence. */
  hop?: number;
  /** Structured mtr row fields (present when kind is "mtr"). */
  mtr?: MtrHop;
  /** Structured traceroute hop (present when kind is "traceroute"). */
  trace?: TracerouteHop;
}

export interface LiveJobFramePayload {
  stream: LiveJobStream;
  line: string;
  mode?: LiveJobFrameMode;
  key?: string;
  kind?: LiveJobFrameKind;
  hop?: number;
  mtr?: MtrHop;
  trace?: TracerouteHop;
}

export function liveJobFrame(stream: LiveJobStream, line: string, options: LiveJobFrameOptions = {}): string {
  return JSON.stringify({ stream, ...options, line });
}

/** A control frame carrying an out-of-band event, never terminal output. */
export function liveJobControlFrame(event: LiveJobControlEvent): string {
  return JSON.stringify({ stream: "control", event });
}

export async function liveJobDebugEnabled(db: SqlDatabase | undefined): Promise<boolean> {
  return getBooleanProjectSetting(db, "LG_DEBUG_STREAMS");
}

export class LiveJobSlot {
  private generation = 0;
  private agent: ProxiedSocket | null = null;

  next(): { id: number; replaced: boolean } {
    const replaced = this.agent !== null;
    this.generation += 1;
    if (this.agent) this.agent.close(1000, "replaced");
    this.agent = null;
    return { id: this.generation, replaced };
  }

  setAgent(generation: number, socket: ProxiedSocket): boolean {
    if (!this.isCurrent(generation)) {
      socket.close(1000, "replaced");
      return false;
    }
    this.agent = socket;
    return true;
  }

  clear(generation: number): void {
    if (!this.isCurrent(generation)) return;
    this.agent = null;
  }

  closeActive(): void {
    this.generation += 1;
    this.agent?.close();
    this.agent = null;
  }

  isCurrent(generation: number): boolean {
    return generation === this.generation;
  }
}

export function guardStopMessage(error: string | undefined): string {
  if (error === "invalid_target") return "stopped: target is not a valid domain or IP";
  if (error === "ip_family_mismatch") return "stopped: target IP does not match the selected IP family";
  if (error === "blocked_private_ip") return "stopped: target is blocked because it resolves to a private/local IP";
  if (error === "frontend_dns_required") return "stopped: choose a resolved public IP before running with Remote DNS off";
  if (error === "dns_no_records") return "stopped: worker DNS safety check found no usable public address";
  return `stopped: ${error || "job target rejected"}`;
}

function sendLiveJobFrame(
  socket: ProxiedSocket,
  stream: LiveJobStream,
  line: string,
  debugEnabled: boolean,
  options: LiveJobFrameOptions = {},
): void {
  if (stream === "debug" && !debugEnabled) return;
  try {
    socket.send(liveJobFrame(stream, line, options));
  } catch {
    // A browser can close between an async guard/fetch and this frame. Never
    // turn that expected race into an unhandled rejection.
  }
}

/** Send a control frame (never rendered), regardless of the debug setting. */
function sendLiveJobControl(socket: ProxiedSocket, event: LiveJobControlEvent): void {
  try {
    socket.send(liveJobControlFrame(event));
  } catch {
    // Browser already closed; nothing to deliver.
  }
}

/**
 * Signs the agent-facing job token for a live (or proxied) command.
 *
 * The agent validates ip_binding against its TCP peer address, which for a
 * proxied job is the Cloudflare egress IP, not the browser IP. The token must
 * therefore stay unbound ("none"): browser identity is enforced upstream by
 * the live session token (relaxed IP binding + issuance rate limit) and the
 * per-connection command budget. This mirrors agentTokenForJobProxy.
 */
export async function signAgentJobClaims(
  env: Pick<Env, "DB">,
  nodeID: string,
  command: { tool?: string },
  target: string,
  ipver: string,
  count: number,
  remoteDNS: boolean,
  clientIP = "",
): Promise<{ token: string; claims: Record<string, unknown> }> {
  const tokenJwk = await getRuntimeJWK(env.DB, "LG_TOKEN_SIGN_JWK");
  const claims = {
    typ: "job",
    kid: await kidFromJWK(tokenJwk),
    node: nodeID,
    tool: command.tool,
    target,
    ipver,
    count,
    remote_dns: remoteDNS,
    // The agent cannot bind this value to its Cloudflare peer (hence none),
    // but it is a signed, trusted browser identity for concurrency/accounting.
    ip: clientIP,
    ip_binding: "none",
    exp: Math.floor(Date.now() / 1000) + 300,
    nonce: crypto.randomUUID().replaceAll("-", ""),
  };
  const token = await signCompact(claims, tokenJwk);
  return { token, claims };
}

export function liveJobCommandDisplay(input: {
  tool: string;
  target: string;
  ipver: string;
  count: number;
  remoteDNS: boolean;
  originalTarget?: string;
}): string {
  const ipFlag = input.ipver === "ipv6" ? "-6" : "-4";
  const target = input.target.trim();
  const originalTarget = input.originalTarget?.trim() || "";
  const comment = !input.remoteDNS && safeDisplayTarget(originalTarget) && originalTarget !== target ? ` # ${originalTarget}` : "";
  if (input.tool === "ping") return `ping ${ipFlag} -O -c ${input.count} -W 2 ${target}${comment}`;
  if (input.tool === "mtr") return `mtr ${ipFlag} --split ${target}${comment}`;
  if (input.tool === "traceroute") return `traceroute ${ipFlag} -n -w 2 -e ${target}${comment}`;
  if (input.tool === "nexttrace") return `nexttrace ${input.ipver === "ipv6" ? "--ipv6" : "--ipv4"} --map -g en ${target}${comment}`;
  return `${input.tool} ${target}${comment}`;
}

/**
 * A parsed mtr hop row, carried as structured fields so the client renders its
 * own (aligned) table instead of trusting mtr's whitespace padding, which
 * varies with terminal width and hostname length.
 */
export interface MtrHop {
  hop: number;
  /** AS number token, e.g. "AS15169" or "AS???" (mtr -z; "-" when unknown). */
  asn: string;
  /** Host as mtr printed it: an IP under -n, else a hostname, or "???" . */
  host: string;
  loss: string;
  snt: string;
  last: string;
  avg: string;
  best: string;
  wrst: string;
}

/**
 * Parse one `mtr --split` hop line into structured fields.
 *
 * Real deployments do not agree on the hop label or the loss format, so all of
 * these must parse:
 *   - ` 1. AS15169  8.8.8.8  0.0%  2 ...`   (current agent: --split -n -z)
 *   - ` 1.|-- host  0.0%  2 ...`            (mtr's classic --split label)
 *   - ` 1 203.0.113.1 0 1 1 0 0 0`        (bare hop, integer loss)
 *   - `[1] host 0.0% ...`
 *
 * The previous version required the label to be `N.`/`N.|--`, so the bare-hop
 * form (and integer loss) never matched: no hop frame was emitted, the streamed
 * table was never de-duplicated, and every split cycle appended a whole new
 * copy. Field positions follow mtr's own column order (Loss% Snt Last Avg Best
 * Wrst), so the rendered table matches mtr's meaning.
 */
export function parseMtrHop(line: string): MtrHop | null {
  const trimmed = trimAgentLine(line);
  const fields = trimmed.trim().split(/\s+/);
  if (fields.length < 8) return null;
  const hopMatch = /^\[?(\d+)\]?\.?(?:\|--)?$/.exec(fields[0]);
  if (!hopMatch) return null;
  const hop = Number(hopMatch[1]);

  // The ASN column is present only with -z (mtr prints "AS####"/"AS???").
  const hasAsn = /^AS\d+$|^AS\?\?\?$/.test(fields[1]);
  const asn = hasAsn ? fields[1] : "";
  const rest = hasAsn ? fields.slice(2) : fields.slice(1);
  // rest: [host, loss, snt, last, avg, best, wrst, (stdev)]
  if (rest.length < 7) return null;
  const [host, loss, snt, last, avg, best, wrst] = rest;
  // Require a plausible loss cell so a traceroute row (`1 192.168.1.1
  // (192.168.1.1) 0.500 ms ...`) is not mistaken for a hop when this is called
  // without the tool gate.
  if (!/^\d+(?:\.\d+)?%?$/.test(loss)) return null;
  return { hop, asn, host, loss: normalizeMtrLoss(loss), snt, last, avg, best, wrst };
}

/**
 * Normalize an mtr loss cell to a `N.N%` string. Older/other mtr builds print a
 * bare integer (`0`), and some print parts-per-million (`50000` for 50%), so a
 * value above 100 without a percent sign is treated as ppm.
 */
function normalizeMtrLoss(loss: string): string {
  if (loss.includes("%")) return loss;
  const value = Number(loss);
  if (!Number.isFinite(value)) return loss;
  return `${(value >= 100 ? value / 1000 : value).toFixed(1)}%`;
}

/** Frame keys that mark mtr output, so the client can dispatch on the frame
 * TYPE instead of guessing from the line text (a traceroute hop line looks a
 * lot like an mtr row, but only mtr output carries these keys). */
export const MTR_HEADER_KEY = "mtr-header";
export const MTR_HOP_KEY_PREFIX = "mtr-hop-";

export function mtrReplaceFrameForLine(line: string): LiveJobFramePayload | null {
  const hop = parseMtrHop(line);
  if (!hop) return null;
  return {
    stream: "stdout",
    mode: "replace",
    key: `${MTR_HOP_KEY_PREFIX}${hop.hop}`,
    // `line` stays human-readable for copy/fallback; the structured `mtr`
    // field is what the client renders.
    line: compactMtrHopLine(hop),
    kind: "mtr",
    hop: hop.hop,
    mtr: hop,
  };
}

/** A space-separated fallback rendering (used for clipboard + legacy clients). */
function compactMtrHopLine(hop: MtrHop): string {
  return [hop.asn, hop.host, hop.loss, hop.snt, hop.last, hop.avg, hop.best, hop.wrst]
    .filter((part) => part !== "")
    .join(" ");
}

export function mtrHeaderLines(): string[] {
  return [
    "Hop  AS        Host                             Loss%   Snt   Last   Avg  Best  Wrst",
  ];
}

/** The mtr table header as a tagged frame, so the client renders it as a header. */
export function mtrHeaderFrame(): LiveJobFramePayload {
  return {
    stream: "stdout",
    mode: "replace",
    key: MTR_HEADER_KEY,
    line: mtrHeaderLines()[0],
    kind: "mtr-header",
  };
}


function trimAgentLine(line: string): string {
  return line.replace(/\r?\n$/, "");
}

function safeDisplayTarget(target: string): boolean {
  return /^[A-Za-z0-9.:-]+$/.test(target);
}

export async function handleJobWebSocketProxy(request: Request, env: Env, sockets: SocketRuntime): Promise<Response> {
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return json({ error: "websocket_upgrade_required" }, { status: 400 });
  }
  const url = new URL(request.url);
  const nodeID = url.searchParams.get("node");
  const token = url.searchParams.get("token");
  if (!nodeID || !token) return json({ error: "node_token_required" }, { status: 400 });

  const node = await getNode(env.DB, nodeID);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;

  let agentToken: string;
  try {
    agentToken = await agentTokenForJobProxy(token, env, internalNodeID, clientIP(request));
  } catch {
    return json({ error: "invalid_token" }, { status: 401 });
  }

  const target = agentJobWebSocketTarget(node.domain, node.port, agentToken);
  const agent = await sockets.connectWebSocket(target.url, { headers: target.headers });
  if (!agent) {
    void reportNodeUnavailable(env, internalNodeID);
    return json({ error: "agent_websocket_failed" }, { status: 502 });
  }

  const pair = await sockets.createSocketPair();
  const browser = pair.server;
  // Proxying across two sockets: keep the half-open behavior so the close
  // frames can be coordinated (the runtime's automatic close-reply can tear the
  // peer down before we relay it). See the ProxiedSocket.accept docs.
  browser.accept({ allowHalfOpen: true });
  agent.accept({ allowHalfOpen: true });
  browser.addEventListener("message", (event) => safeSocketSend(agent, event.data));
  agent.addEventListener("message", (event) => safeSocketSend(browser, event.data));
  browser.addEventListener("close", () => safeSocketClose(agent));
  agent.addEventListener("close", () => safeSocketClose(browser));
  browser.addEventListener("error", () => safeSocketClose(agent));
  agent.addEventListener("error", () => safeSocketClose(browser));
  return pair.upgradeResponse();
}

// Either peer can close between an event being queued and its send/close
// running; a throw there becomes an unhandled rejection in the Workers
// runtime. Mirror the live path's guarded framing (sendLiveJobFrame).
export function safeSocketSend(socket: ProxiedSocket, data: unknown): void {
  try {
    socket.send(data as ArrayBuffer | ArrayBufferView | string);
  } catch {
    // Peer already closed; dropping the frame is the correct outcome.
  }
}

export function safeSocketClose(socket: ProxiedSocket, code?: number, reason?: string): void {
  try {
    socket.close(code, reason);
  } catch {
    // Already closed/closing; nothing to do.
  }
}

export interface LiveJobAuthSuccess {
  node: { id: string; internal_id: string; domain: string; port: number };
  claims: { typ: string; node: string; ip: string; exp: number };
}

export interface LiveJobAuthFailure {
  response: Response;
}

/**
 * Shared auth path for /api/jobs/live: resolves the node, then verifies the
 * `?token=` live session token (signature, typ, node, expiry, relaxed IP
 * binding). Kept as its own unit so the WebSocket upgrade itself (which needs
 * the Workers runtime WebSocketPair) stays thin and testable.
 */
export async function authorizeLiveJobSocket(request: Request, env: Env): Promise<LiveJobAuthSuccess | LiveJobAuthFailure> {
  const url = new URL(request.url);
  const nodeID = url.searchParams.get("node") || "";
  const token = url.searchParams.get("token") || "";
  if (!nodeID) return { response: json({ error: "node_required" }, { status: 400 }) };
  if (!token) return { response: json({ error: "live_session_required" }, { status: 401 }) };
  const node = await getNode(env.DB, nodeID);
  if (!node) return { response: json({ error: "node_not_found" }, { status: 404 }) };
  const internalNodeID = node.internal_id;

  const verified = await verifyLiveSessionToken({
    token,
    env,
    expectedNodeID: internalNodeID,
    clientIP: clientIP(request),
  });
  if ("error" in verified) {
    if (verified.error === "node_mismatch") return { response: json({ error: "node_mismatch" }, { status: 403 }) };
    return { response: json({ error: "invalid_live_session" }, { status: 401 }) };
  }
  return { node: { id: node.id, internal_id: internalNodeID, domain: node.domain, port: node.port }, claims: verified.claims };
}

export async function handleLiveJobWebSocket(request: Request, env: Env, sockets: SocketRuntime, tcp?: TcpRuntime): Promise<Response> {
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return json({ error: "websocket_upgrade_required" }, { status: 400 });
  }
  const authorized = await authorizeLiveJobSocket(request, env);
  if ("response" in authorized) return authorized.response;
  const sessionToken = new URL(request.url).searchParams.get("token") || "";

  const pair = await sockets.createSocketPair();
  const browser = pair.server;
  const slot = new LiveJobSlot();
  const debugEnabled = await liveJobDebugEnabled(env.DB);
  browser.accept({ allowHalfOpen: true });
  browser.addEventListener("message", (event) => {
    const run = slot.next();
    if (run.replaced) {
      sendLiveJobFrame(browser, "debug", "stopped previous live job before starting replacement", debugEnabled);
    }
    void runLiveJob({
      request,
      env,
      nodeID: authorized.node.internal_id,
      nodeDomain: authorized.node.domain,
      nodePort: authorized.node.port,
      clientIP: authorized.claims.ip,
      sessionToken,
      requestClientIP: clientIP(request),
      payload: String(event.data),
      browser,
      sockets,
      tcp,
      debugEnabled,
      isCurrent: () => slot.isCurrent(run.id),
      setAgent: (socket) => {
        slot.setAgent(run.id, socket);
      },
    }).catch(() => {
      // Keep operational failures visible even when debug streams are off.
      if (slot.isCurrent(run.id)) sendLiveJobFrame(browser, "stdout", "error: live_job_failed", debugEnabled);
    }).finally(() => {
      slot.clear(run.id);
    });
  });
  browser.addEventListener("close", () => slot.closeActive());
  browser.addEventListener("error", () => slot.closeActive());
  return pair.upgradeResponse();
}

async function runLiveJob(input: {
  request: Request;
  env: Pick<Env, "DB" | "ASSETS">;
  nodeID: string;
  nodeDomain: string;
  nodePort: number;
  clientIP: string;
  sessionToken: string;
  requestClientIP: string;
  payload: string;
  browser: ProxiedSocket;
  sockets: SocketRuntime;
  tcp?: TcpRuntime;
  debugEnabled: boolean;
  isCurrent: () => boolean;
  setAgent: (socket: ProxiedSocket) => void;
}): Promise<void> {
  let command: { tool?: string; target?: string; ipver?: string; count?: number; remote_dns?: boolean; original_target?: string };
  try {
    command = JSON.parse(input.payload) as { tool?: string; target?: string; ipver?: string; count?: number; remote_dns?: boolean; original_target?: string };
  } catch {
    sendLiveJobFrame(input.browser, "stdout", "error: bad_json", input.debugEnabled);
    return;
  }
  if (!command || typeof command !== "object" || typeof command.tool !== "string" || !allowedLiveTools.has(command.tool) || typeof command.target !== "string" || !command.target.trim()) {
    sendLiveJobFrame(input.browser, "stdout", "error: invalid_command", input.debugEnabled);
    return;
  }
  // A live socket may outlive the token's original handshake. Re-verify on
  // every command, including the relaxed browser-IP binding.
  const session = await verifyLiveSessionToken({
    token: input.sessionToken,
    env: input.env,
    expectedNodeID: input.nodeID,
    clientIP: input.requestClientIP,
  });
  if ("error" in session) {
    sendLiveJobFrame(input.browser, "stdout", "error: live_session_expired", input.debugEnabled);
    input.browser.close(1008, "live_session_expired");
    return;
  }
  // Budget is consumed before the target guard on purpose: the guard performs
  // a worker-side DNS lookup, so charging every command (including ones that
  // will be blocked as private/invalid) also bounds that lookup. A legitimate
  // user fat-fingering a private IP spends a slot per attempt; that is the
  // accepted trade-off for keeping guard lookups rate-limited too.
  const rateLimit = await consumeRateLimit({
    db: input.env.DB,
    action: "live_command",
    node: input.nodeID,
    // Keep the signed original browser address as the stable identity across
    // reconnects and relaxed-prefix address rotation.
    clientIP: session.claims.ip,
    limit: LIVE_JOB_COMMAND_LIMIT,
    windowSeconds: LIVE_JOB_COMMAND_WINDOW_SECONDS,
  });
  if (!rateLimit.allowed) {
    sendLiveJobFrame(input.browser, "stdout", "error: command_rate_limited", input.debugEnabled);
    return;
  }
  const now = Math.floor(Date.now() / 1000);
  const count = normalizeJobCount(command.count);
  const ipver = command.ipver || "ipv4";
  const remoteDNS = command.remote_dns === true;
  const guard = await inspectJobTarget({ target: command.target, ipver, remoteDNS }, input.env.DB);
  if (!input.isCurrent()) return;
  if (!guard.allowed) {
    const jobID = `job_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
    await recordOperation(input.env.DB, {
      id: jobID,
      operationType: "job",
      node: input.nodeID,
      clientIP: input.clientIP,
      status: guard.error || "blocked",
      metadata: {
        tool: command.tool,
        target: command.target,
        ipver,
        remote_dns: remoteDNS,
        checked_ips: guard.checkedIPs,
      },
      createdAt: now,
      expiresAt: now + 300,
    });
    sendLiveJobFrame(input.browser, "debug", `error: ${guard.error || "blocked"}`, input.debugEnabled);
    // Render the command first so the terminal output retains context
    sendLiveJobFrame(
      input.browser,
      "stdout",
      `$ ${liveJobCommandDisplay({
        tool: command.tool,
        target: command.target,
        ipver,
        count,
        remoteDNS,
        originalTarget: command.original_target,
      })}`,
      input.debugEnabled,
      { mode: "command" },
    );
    // Detailed error reason when DNS resolution or target guard fails
    if (guard.error === "dns_no_records") {
      const recordType = ipver === "ipv6" ? "IPv6 (AAAA)" : "IPv4 (A)";
      sendLiveJobFrame(
        input.browser,
        "stdout",
        `error: DNS resolution failed: no ${recordType} record found for "${command.target}"`,
        input.debugEnabled,
      );
    } else if (guard.error === "ip_family_mismatch") {
      sendLiveJobFrame(
        input.browser,
        "stdout",
        `error: IP family mismatch: target "${command.target}" is not a valid ${ipver === "ipv6" ? "IPv6" : "IPv4"} address`,
        input.debugEnabled,
      );
    } else if (guard.error === "blocked_private_ip") {
      sendLiveJobFrame(
        input.browser,
        "stdout",
        `error: Target "${command.target}" is blocked because it resolves to a private or reserved IP address`,
        input.debugEnabled,
      );
    } else if (guard.error === "invalid_target") {
      sendLiveJobFrame(
        input.browser,
        "stdout",
        `error: Invalid target "${command.target}": must be a valid domain or IP address`,
        input.debugEnabled,
      );
    }
    sendLiveJobFrame(input.browser, "stdout", guardStopMessage(guard.error), input.debugEnabled);
    sendLiveJobControl(input.browser, "complete");
    return;
  }
  const claims = await signAgentJobClaims(input.env, input.nodeID, command, guard.target, ipver, count, remoteDNS, input.clientIP);
  const jobID = `job_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  await recordOperation(input.env.DB, {
    id: jobID,
    operationType: "job",
    node: input.nodeID,
    clientIP: input.clientIP,
    status: "live_started",
    metadata: {
      tool: command.tool,
      target: guard.target,
      ipver,
      count,
      remote_dns: remoteDNS,
      checked_ips: guard.checkedIPs,
    },
    createdAt: now,
    expiresAt: now + 300,
  });
  if (!input.isCurrent()) return;
  sendLiveJobFrame(
    input.browser,
    "stdout",
    `$ ${liveJobCommandDisplay({
      tool: command.tool,
      target: guard.target,
      ipver,
      count,
      remoteDNS,
      originalTarget: command.original_target,
    })}`,
    input.debugEnabled,
    { mode: "command" },
  );
  if (command.tool === "mtr") {
    const header = mtrHeaderFrame();
    sendLiveJobFrame(input.browser, "stdout", header.line, input.debugEnabled, { mode: header.mode, key: header.key, kind: header.kind });
  }
  sendLiveJobFrame(input.browser, "debug", `started: ${command.tool} ${guard.target}`, input.debugEnabled);
  const target = agentJobWebSocketTarget(input.nodeDomain, input.nodePort, claims.token);
  const agent = await input.sockets.connectWebSocket(target.url, { headers: target.headers });
  if (!agent) {
    if (!input.isCurrent()) return;
    void reportNodeUnavailable(input.env, input.nodeID);
    sendLiveJobFrame(input.browser, "stdout", "error: agent_websocket_failed", input.debugEnabled);
    return;
  }
  if (!input.isCurrent()) {
    agent.close(1000, "replaced");
    return;
  }
  input.setAgent(agent);
  agent.accept({ allowHalfOpen: true });
  // Resolve ASNs at mtr's own cycle boundary, not on a timer: mtr prints hops
  // 1..N in order and then wraps back to 1, so a hop number that does not
  // increase means a new cycle started and the previous one finished. The first
  // wrap is the first complete path — resolve then. After that, only a newly
  // discovered (deeper) hop triggers another lookup. ASNs already known for an
  // IP are kept and never re-queried or dropped.
  const mtrHops = new Map<number, MtrHop>();
  const knownAsns = new Map<string, string>();
  let maxHopSeen = 0;
  let firstCycleDone = false;
  let enriching = false;
  let enrichAgain = false;
  const requestAsns = () => {
    if (!input.tcp || !input.isCurrent()) return;
    if (enriching) {
      enrichAgain = true;
      return;
    }
    enriching = true;
    void enrichMtrAsns(
      { browser: input.browser, debugEnabled: input.debugEnabled, isCurrent: input.isCurrent, tcp: input.tcp },
      mtrHops,
      knownAsns,
    ).finally(() => {
      enriching = false;
      if (enrichAgain) {
        enrichAgain = false;
        requestAsns();
      }
    });
  };
  await new Promise<void>((resolve) => {
    agent.addEventListener("message", (event) => {
      if (!input.isCurrent()) return;
      const line = trimAgentLine(String(event.data));
      // mtr and the system traceroute are parsed in the worker and emitted as
      // typed frames, so the client renders them without guessing the tool from
      // its own UI state.
      if (command.tool === "traceroute") {
        const hop = parseTracerouteHop(line);
        if (hop) {
          sendLiveJobFrame(input.browser, "stdout", compactTracerouteHop(hop), input.debugEnabled, {
            mode: "replace",
            key: `trace-hop-${hop.hop}`,
            kind: "traceroute",
            hop: hop.hop,
            trace: hop,
          });
          return;
        }
      }
      const replacement = command.tool === "mtr" ? mtrReplaceFrameForLine(line) : null;
      if (replacement) {
        if (replacement.mtr) {
          const hop = replacement.mtr.hop;
          const existing = mtrHops.get(hop);
          const hostIP = isIPAddress(replacement.mtr.host) ? canonicalIPKey(replacement.mtr.host) : "";
          // Never drop a known ASN: reuse it when the agent sent none, whether
          // it came from this hop earlier or from another hop with the same IP.
          const preserved = replacement.mtr.asn
            || (existing && existing.host === replacement.mtr.host ? existing.asn : "")
            || (hostIP ? knownAsns.get(hostIP) : "")
            || "";
          if (preserved && !replacement.mtr.asn) {
            replacement.mtr.asn = preserved;
            replacement.line = compactMtrHopLine(replacement.mtr);
          }
          const hostChanged = existing !== undefined && existing.host !== replacement.mtr.host;
          mtrHops.set(hop, replacement.mtr);
          if (isMtrCycleBoundary(hop, maxHopSeen)) {
            // Wrapped back: the first complete cycle has finished.
            if (!firstCycleDone) {
              firstCycleDone = true;
              requestAsns();
            }
          } else {
            const deeper = hop > maxHopSeen;
            maxHopSeen = hop;
            // A deeper hop appeared after the first path: resolve the additions.
            if (deeper && firstCycleDone) requestAsns();
          }
          if (firstCycleDone && hostChanged && hostIP && !knownAsns.has(hostIP)) requestAsns();
        }
        sendLiveJobFrame(input.browser, replacement.stream, replacement.line, input.debugEnabled, {
          mode: replacement.mode,
          key: replacement.key,
          kind: replacement.kind,
          hop: replacement.hop,
          mtr: replacement.mtr,
        });
        return;
      }
      sendLiveJobFrame(input.browser, "stdout", line, input.debugEnabled);
    });
    agent.addEventListener("close", () => {
      if (!input.isCurrent()) {
        resolve();
        return;
      }
      // Resolve any remaining missing ASNs before announcing completion, so the
      // browser renders them while it still holds the socket. Bounded and
      // best-effort: a slow or failed lookup never delays completion beyond its
      // timeout.
      void enrichMtrAsns(
        { browser: input.browser, debugEnabled: input.debugEnabled, isCurrent: input.isCurrent, tcp: input.tcp },
        mtrHops,
        knownAsns,
      ).finally(() => {
        if (!input.isCurrent()) {
          resolve();
          return;
        }
        // Authoritative completion: a control frame the browser always receives,
        // independent of the debug-stream setting. The debug line stays for
        // operators who enabled debug streams.
        sendLiveJobControl(input.browser, "complete");
        sendLiveJobFrame(input.browser, "debug", "command closed", input.debugEnabled);
        resolve();
      });
    });
    agent.addEventListener("error", () => {
      if (!input.isCurrent()) {
        resolve();
        return;
      }
      sendLiveJobFrame(input.browser, "stdout", "error: agent_websocket_error", input.debugEnabled);
      resolve();
    });
  });
}

/**
 * Fill in the ASN for mtr hops the agent left blank, using one Team Cymru bulk
 * TCP query for the whole trace. Sends a `replace` frame per enriched hop (the
 * same key the row already has, so the client updates it in place).
 *
 * Called at mtr's cycle boundary (see runLiveJob) rather than on a timer, and
 * only for hops that still lack an ASN, so a running trace costs one lookup on
 * the first complete path plus one per newly discovered hop.
 *
 * Exported for tests.
 */
export interface MtrAsnEnrichmentContext {
  browser: ProxiedSocket;
  debugEnabled: boolean;
  isCurrent: () => boolean;
  tcp?: TcpRuntime;
}

/**
 * mtr prints one row per hop, ascending within a cycle, then wraps back to a
 * lower hop number for the next cycle. A hop that does not exceed the running
 * maximum therefore marks a new cycle — the point at which the previous cycle's
 * hop set is complete and ASNs can be resolved once. Exported for tests.
 */
export function isMtrCycleBoundary(hop: number, previousMaxHop: number): boolean {
  return previousMaxHop > 0 && hop <= previousMaxHop;
}

export async function enrichMtrAsns(
  context: MtrAsnEnrichmentContext,
  hops: Map<number, MtrHop>,
  knownAsns?: Map<string, string>,
): Promise<number> {
  if (hops.size === 0 || !context.tcp) return 0;
  // First, check if any hops can be filled from knownAsns immediately
  if (knownAsns) {
    for (const hop of hops.values()) {
      if (!hop.asn && isIPAddress(hop.host)) {
        const cached = knownAsns.get(canonicalIPKey(hop.host));
        if (cached) {
          const enriched: MtrHop = { ...hop, asn: cached };
          hops.set(hop.hop, enriched);
          sendLiveJobFrame(context.browser, "stdout", compactMtrHopLine(enriched), context.debugEnabled, {
            mode: "replace",
            key: `${MTR_HOP_KEY_PREFIX}${hop.hop}`,
            kind: "mtr",
            hop: hop.hop,
            mtr: enriched,
          });
        }
      }
    }
  }
  const missing = [...hops.values()].filter((hop) => !hop.asn && isIPAddress(hop.host));
  if (missing.length === 0) return 0;
  const records = await lookupAsns(context.tcp, missing.map((hop) => hop.host));
  if (records.size === 0 || !context.isCurrent()) return 0;
  let patched = 0;
  for (const hop of missing) {
    const record = records.get(canonicalIPKey(hop.host));
    if (!record) continue;
    if (knownAsns) knownAsns.set(canonicalIPKey(hop.host), record.asn);
    const enriched: MtrHop = { ...hop, asn: record.asn };
    // Remember the enrichment so a later pass (the debounced one or the final
    // completion pass) does not re-send the same patch.
    hops.set(hop.hop, enriched);
    sendLiveJobFrame(context.browser, "stdout", compactMtrHopLine(enriched), context.debugEnabled, {
      mode: "replace",
      key: `${MTR_HOP_KEY_PREFIX}${hop.hop}`,
      kind: "mtr",
      hop: hop.hop,
      mtr: enriched,
    });
    patched += 1;
  }
  return patched;
}

export async function agentTokenForJobProxy(
  browserToken: string,
  env: Pick<Env, "DB">,
  expectedNodeID: string,
  browserIP: string,
): Promise<string> {
  const [payloadPart, signaturePart] = browserToken.split(".");
  if (!payloadPart || !signaturePart) throw new Error("malformed_token");
  const payload = base64URLToBytes(payloadPart);
  const signature = base64URLToBytes(signaturePart);
  const jwk = await getRuntimeJWK(env.DB, "LG_TOKEN_SIGN_JWK");
  const verifyKey = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    { name: "Ed25519" } as AlgorithmIdentifier,
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" } as AlgorithmIdentifier,
    verifyKey,
    signature as unknown as BufferSource,
    payload as unknown as BufferSource,
  );
  if (!ok) throw new Error("bad_signature");

  const claims = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;
  if (claims.typ !== "job" || typeof claims.exp !== "number" || claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error("bad_claims");
  }
  if (claims.node !== expectedNodeID) throw new Error("node_mismatch");
  if (typeof claims.ip !== "string") throw new Error("ip_mismatch");
  if (typeof claims.nonce !== "string" || !claims.nonce) throw new Error("nonce_required");
  // Strict/relaxed tokens must match the caller's IP. Any other binding
  // (including "none") is rejected: /api/token/job only issues relaxed
  // tokens, so accepting an unbound token here would let a stolen token be
  // replayed from anywhere. Keep this fail-closed.
  if (claims.ip_binding === "strict" ? claims.ip !== browserIP : claims.ip_binding === "relaxed" ? !relaxedIPMatch(claims.ip, browserIP) : true) {
    throw new Error("ip_mismatch");
  }
  return signCompact(
    {
      ...claims,
      kid: await kidFromJWK(jwk),
      ip: claims.ip,
      ip_binding: "none",
      // Preserve the browser nonce: the agent's single-use nonce cache must
      // see a replay as the same job, even when this proxy is reconnected.
      nonce: claims.nonce,
    },
    jwk,
  );
}
