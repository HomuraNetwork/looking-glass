import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable, type Duplex } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as NodeWebReadableStream } from "node:stream/web";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { WebSocketServer, type WebSocket } from "ws";

import { handleRequest, runScheduledPass } from "../src/app";
import { applyMigrations, databaseReady, ensureDefaultNodeProfile, inspectDatabase } from "../src/db-bootstrap";
import type { Env } from "../src/config";
import type { SocketPair, SocketRuntime } from "../src/runtime";
import { createNodeSqliteDatabase } from "./sqlite";
import { connectWsWebSocket, nodeTransformHTML, wrapWsSocket } from "./sockets";
import { fileAssetServer } from "./assets";
import { nodeTcp } from "./tcp";
import {
	applyClientIPHeaders,
	DEFAULT_CLIENT_IP_HEADER,
	forwardedHeaderTrusted,
	normalizeRemoteAddress,
	parseTrustedProxyCIDRs,
	requestOrigin,
	resolveClientIP,
	type RequestNetworkOptions,
	type TrustedProxyEntry,
} from "./request";
import { BodyTooLargeError, readRequestBody } from "./body";
import { resolveSchedule, msUntilNextRun, type CronSchedule } from "./cron";

/**
 * Local (self-hosted / Docker) entry point.
 *
 * Runs the same runtime-neutral core (app.ts) as the Cloudflare Worker, but
 * wires Node capabilities: node:sqlite for storage, `ws` for WebSockets, the
 * filesystem for static assets, and setInterval for the cron pass.
 *
 * Upgrade flow: Node's `ws` handshake is asynchronous and must happen only
 * after the core authorizes the request. So the HTTP server handles the
 * `upgrade` event, stashes the raw socket in AsyncLocalStorage, and re-enters
 * the core with a normal Request. When the core calls createSocketPair(), we
 * complete the ws handshake on the stashed socket and return the pair.
 *
 * Configuration (environment):
 *   LG_PORT              HTTP port (default 8787)
 *   LG_DB_PATH           SQLite file path (default ./looking-glass.sqlite)
 *   LG_ASSETS_DIR        directory of built frontend assets (default ../frontend/dist)
 *   LG_SCHEDULE_CRON     cron schedule for the background pass, same 5-field
 *                        syntax as the Cloudflare crons trigger
 *                        (default every 30 minutes; "none" disables)
 */

interface LocalNetworkConfig extends RequestNetworkOptions {
  /** True when LG_TRUST_PROXY_HEADER was explicitly configured. */
  clientIPHeaderExplicit: boolean;
  /** Parsed LG_TRUSTED_PROXY_CIDRS (empty when unset). */
  trustedProxyList: TrustedProxyEntry[];
}

interface LocalConfig {
  port: number;
  dbPath: string;
  assetsDir: string;
  schedule: CronSchedule | null;
  network: LocalNetworkConfig;
}

function loadConfig(): LocalConfig {
  const trustProxy = process.env.LG_TRUST_PROXY === "1" || process.env.LG_TRUST_PROXY === "true";
  const schedule = resolveSchedule(process.env.LG_SCHEDULE_CRON);
  if (process.env.LG_SCHEDULE_SECONDS !== undefined) {
    console.warn(JSON.stringify({ app: "hlg", event: "config.deprecated", variable: "LG_SCHEDULE_SECONDS", use: "LG_SCHEDULE_CRON" }));
  }
  if (process.env.LG_SCHEDULE_CRON !== undefined && schedule === null && process.env.LG_SCHEDULE_CRON.trim().toLowerCase() !== "none") {
    console.error(JSON.stringify({ app: "hlg", event: "config.invalid", variable: "LG_SCHEDULE_CRON", value: process.env.LG_SCHEDULE_CRON, message: "not a valid 5-field cron expression; the background pass is disabled" }));
  }
  const trustProxyHeader = process.env.LG_TRUST_PROXY_HEADER?.trim() || "";
  const legacyClientIPHeader = process.env.LG_CLIENT_IP_HEADER?.trim() || "";
  if (!trustProxyHeader && legacyClientIPHeader) {
    console.warn(
      JSON.stringify({
        app: "hlg",
        event: "config.deprecated",
        variable: "LG_CLIENT_IP_HEADER",
        use: "LG_TRUST_PROXY_HEADER",
      }),
    );
  }
  const clientIPHeader = trustProxyHeader || legacyClientIPHeader;
  const clientIPHeaderExplicit = clientIPHeader !== "";
  let trustedProxyList: TrustedProxyEntry[];
  try {
    trustedProxyList = parseTrustedProxyCIDRs(process.env.LG_TRUSTED_PROXY_CIDRS);
  } catch (error) {
    console.error(
      JSON.stringify({
        app: "hlg",
        event: "config.invalid",
        variable: "LG_TRUSTED_PROXY_CIDRS",
        message: error instanceof Error ? error.message : String(error),
      }),
    );
    throw error;
  }
  logNetworkConfigWarnings({ trustProxy, clientIPHeader, clientIPHeaderExplicit, trustedProxyList });

  return {
    port: Number(process.env.LG_PORT || "8787"),
    dbPath: process.env.LG_DB_PATH || resolve(process.cwd(), "looking-glass.sqlite"),
    // Default relative to the bundled server (controller/local/dist -> controller/
    // frontend/dist) so the stack works from any working directory.
    assetsDir: process.env.LG_ASSETS_DIR || resolve(__dirname, "..", "..", "frontend", "dist"),
    schedule,
    network: {
      trustProxy,
      trustedHops: Number(process.env.LG_TRUST_PROXY_HOPS || "1"),
      // Explicit origin override wins over proxy headers: it also fixes the
      // host when the deployment is reached through several names.
      publicOrigin: process.env.LG_PUBLIC_ORIGIN || undefined,
      // Which proxy header carries the client IP (default x-forwarded-for).
      clientIPHeader: clientIPHeaderExplicit ? clientIPHeader : undefined,
      clientIPHeaderExplicit,
      trustedProxyList,
    },
  };
}

/**
 * Emit the deployment warnings/confirmation for the client-IP trust model.
 * The load-bearing rule: an explicitly configured LG_TRUST_PROXY_HEADER opts out
 * of the allowlist (the operator owns perimeter control via firewall/network
 * policy); otherwise LG_TRUSTED_PROXY_CIDRS gates who may set the header.
 */
function logNetworkConfigWarnings(input: {
  trustProxy: boolean;
  clientIPHeader: string;
  clientIPHeaderExplicit: boolean;
  trustedProxyList: TrustedProxyEntry[];
}): void {
  const { trustProxy, clientIPHeader, clientIPHeaderExplicit, trustedProxyList } = input;
  if (!trustProxy) {
    if (trustedProxyList.length > 0) {
      console.warn(
        JSON.stringify({
          app: "hlg",
          event: "config.warning",
          variable: "LG_TRUSTED_PROXY_CIDRS",
          message: "LG_TRUSTED_PROXY_CIDRS is set but LG_TRUST_PROXY is not enabled; it is ignored.",
        }),
      );
    }
    return;
  }
  if (clientIPHeaderExplicit) {
    console.warn(
      JSON.stringify({
        app: "hlg",
        event: "config.warning",
        variable: "LG_TRUST_PROXY_HEADER",
        message: `LG_TRUST_PROXY_HEADER=${clientIPHeader} is trusted from any peer; LG_TRUSTED_PROXY_CIDRS is not applied. Restrict the origin port to your proxy with a firewall or network policy.`,
      }),
    );
    if (trustedProxyList.length > 0) {
      console.warn(
        JSON.stringify({
          app: "hlg",
          event: "config.warning",
          variable: "LG_TRUSTED_PROXY_CIDRS",
          message: "LG_TRUSTED_PROXY_CIDRS is ignored because LG_TRUST_PROXY_HEADER is explicitly configured.",
        }),
      );
    }
    return;
  }
  if (trustedProxyList.length === 0) {
    console.warn(
      JSON.stringify({
        app: "hlg",
        event: "config.warning",
        variable: "LG_TRUSTED_PROXY",
        message: "Forwarded client-IP headers are trusted from any peer; set LG_TRUSTED_PROXY_CIDRS or restrict the origin port with a firewall.",
      }),
    );
    return;
  }
  console.log(
    JSON.stringify({
      app: "hlg",
      event: "config.trusted_proxy_list",
      entries: trustedProxyList.length,
      header: clientIPHeader || DEFAULT_CLIENT_IP_HEADER,
    }),
  );
}

const UNTRUSTED_PROXY_WARN_INTERVAL_MS = 60_000;
let lastUntrustedProxyWarnAt = 0;

/** Warn (at most once a minute) that a peer outside the allowlist was ignored. */
function warnUntrustedProxyPeer(peer: string): void {
  const now = Date.now();
  if (now - lastUntrustedProxyWarnAt < UNTRUSTED_PROXY_WARN_INTERVAL_MS) return;
  lastUntrustedProxyWarnAt = now;
  console.warn(
    JSON.stringify({
      app: "hlg",
      event: "config.untrusted_proxy_peer",
      peer,
      message: "request from a peer outside LG_TRUSTED_PROXY_CIDRS; forwarded client-IP headers ignored",
    }),
  );
}

/** Convert a Node IncomingMessage into a web Request with a sane network view. */
async function toWebRequest(req: IncomingMessage, config: LocalConfig): Promise<Request> {
  const defaultHost = `localhost:${config.port}`;
  const url = new URL(req.url ?? "/", requestOrigin(req.headers, defaultHost, config.network));
  const method = req.method ?? "GET";
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) for (const v of value) headers.append(key, v);
    else if (value !== undefined) headers.set(key, value);
  }
  // The client IP comes from the TCP peer unless an explicitly trusted proxy
  // vouches for a forwarded chain; see local/request.ts.
  const peer = normalizeRemoteAddress(req.socket?.remoteAddress);
  const network = config.network;
  const clientIPHeader = network.clientIPHeader || DEFAULT_CLIENT_IP_HEADER;
  const forwardedTrusted = forwardedHeaderTrusted(
    {
      trustProxy: network.trustProxy,
      clientIPHeaderExplicit: network.clientIPHeaderExplicit,
      trustedProxyList: network.trustedProxyList,
    },
    peer,
  );
  if (network.trustProxy && !forwardedTrusted) warnUntrustedProxyPeer(peer);
  applyClientIPHeaders(
    headers,
    resolveClientIP(req.headers, peer, forwardedTrusted, network.trustedHops, clientIPHeader),
    clientIPHeader,
  );
  let body: ArrayBuffer | undefined;
  if (method !== "GET" && method !== "HEAD") {
    // Buffer with a transport cap BEFORE the core sees the request: an
    // unbounded read would let parallel large uploads exhaust the process.
    const read = await readRequestBody(req);
    if ("overflow" in read) throw new BodyTooLargeError();
    const merged = read.body;
    body = merged.buffer.slice(merged.byteOffset, merged.byteOffset + merged.byteLength) as ArrayBuffer;
  }
  return new Request(url, { method, headers, body });
}

/** Write a web Response back to a Node ServerResponse, streaming the body. */
async function writeWebResponse(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => res.setHeader(key, value));
  if (!response.body) {
    res.end();
    return;
  }
  // Stream instead of buffering: responses can be large (e.g. the agent
  // binary served by /_agent/*), and a full arrayBuffer() would hold the
  // whole payload in memory per in-flight request.
  const body = Readable.fromWeb(response.body as unknown as NodeWebReadableStream);
  await pipeline(body, res);
}

/** The raw upgrade stashed while the core authorizes and upgrades. */
interface PendingUpgrade {
  wss: WebSocketServer;
  req: IncomingMessage;
  socket: Duplex;
  head: Buffer;
  /** Set once the handshake completes; the 101 is written by `ws` itself. */
  upgraded?: boolean;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const db = createNodeSqliteDatabase({ path: config.dbPath });
  // Apply pending migrations (which also creates the full schema on a fresh
  // database). The check is by
  // migration state, not by table presence, so a ready database from an older
  // release still gets its new migrations. Migrations preserve tables and node
  // rows, though an explicitly retired column may be removed. An unrecoverable
  // database is a loud failure instead of an automatic reset.
  const status = await inspectDatabase(db);
  const { applied } = await applyMigrations(db);
  if (applied.length > 0) await ensureDefaultNodeProfile(db);
  const after = await inspectDatabase(db);
  if (!databaseReady(after)) {
    console.error(
      JSON.stringify({
        app: "hlg",
        event: "db.unusable",
        before: status.status,
        missing_tables: after.missing_tables,
        message:
          "The database does not match the current schema and could not be upgraded in place. It was NOT modified destructively. Restore a backup, or remove the file to start over (data will be lost).",
      }),
    );
    process.exit(1);
  }
  if (applied.length > 0) {
    console.log(
      JSON.stringify({
        app: "hlg",
        event: "db.migrated",
        before: status.status,
        applied_migrations: applied,
      }),
    );
  }
  const assets = existsSync(config.assetsDir) ? fileAssetServer(config.assetsDir) : undefined;
  if (!assets) {
    console.error(
      JSON.stringify({
        app: "hlg",
        event: "assets.missing",
        assets_dir: config.assetsDir,
        message: "Built frontend assets not found; the SPA will not be served. Build controller/frontend or set LG_ASSETS_DIR.",
      }),
    );
  }
  const env: Env = { DB: db, ASSETS: assets };

  const wss = new WebSocketServer({ noServer: true });
  const upgrades = new AsyncLocalStorage<PendingUpgrade>();

  const sockets: SocketRuntime = {
    async createSocketPair(): Promise<SocketPair> {
      const pending = upgrades.getStore();
      if (!pending) throw new Error("createSocketPair called outside an upgrade");
      const ws = await new Promise<WebSocket>((resolve, reject) => {
        pending.wss.handleUpgrade(pending.req, pending.socket, pending.head, (socket) => resolve(socket));
        pending.socket.once("error", reject);
      });
      pending.upgraded = true;
      const proxied = wrapWsSocket(ws);
      // The core relays between `client` and `server`; here both ends are the
      // accepted socket, and the upgrade response is a placeholder: `ws` has
      // already written the 101 handshake to the raw socket, and the entry
      // discards this response (undici rejects status 101 construction).
      return {
        client: proxied,
        server: proxied,
        upgradeResponse: () => new Response(null),
      } satisfies SocketPair;
    },
    connectWebSocket: (url, init) => connectWsWebSocket(url, init),
  };

  /**
   * Fire-and-forget background work (the local analogue of ctx.waitUntil):
   * keep the promise alive past the response and log failures. The set keeps
   * the tasks referenced so they are not collected mid-flight.
   */
  const backgroundTasks = new Set<Promise<unknown>>();
  const trackBackgroundTask = (task: Promise<unknown>): void => {
    const tracked = task.catch((error) => {
      console.error(JSON.stringify({ app: "hlg", event: "background.error", error: error instanceof Error ? error.message : String(error) }));
    });
    backgroundTasks.add(tracked);
    void tracked.finally(() => backgroundTasks.delete(tracked));
  };

  const server = createServer(async (req, res) => {
    try {
      const request = await toWebRequest(req, config);
      const response = await handleRequest(request, env, { sockets, tcp: nodeTcp, transformHTML: nodeTransformHTML, waitUntil: trackBackgroundTask });
      await writeWebResponse(res, response);
    } catch (error) {
      if (res.headersSent) {
        // The response already started; nothing coherent can be written.
        res.destroy();
        return;
      }
      if (error instanceof BodyTooLargeError) {
        // Answer before tearing the socket down, and close the connection:
        // the unread remainder of the body must not be parsed as a new
        // request on the same socket.
        res.statusCode = 413;
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.setHeader("connection", "close");
        res.end(JSON.stringify({ error: "payload_too_large" }));
        const teardown = () => req.destroy();
        res.on("finish", teardown);
        // If the client keeps streaming (no 'finish' because the socket
        // stalls), do not hold it open indefinitely.
        setTimeout(teardown, 1000).unref();
        return;
      }
      console.error(JSON.stringify({
        app: "hlg",
        event: "request.error",
        error: error instanceof Error ? error.message : String(error),
      }));
      res.statusCode = 500;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  });

  server.on("upgrade", (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const pending: PendingUpgrade = { wss, req, socket, head };
    // Re-enter the core; if it authorizes, createSocketPair() completes the
    // handshake. If it rejects, we must close the raw socket ourselves.
    void upgrades.run(pending, async () => {
      try {
        const request = await toWebRequest(req, config);
        const response = await handleRequest(request, env, { sockets, tcp: nodeTcp, transformHTML: nodeTransformHTML, waitUntil: trackBackgroundTask });
        if (!pending.upgraded) {
          // The core returned a normal response (e.g. 401) instead of upgrading.
          socket.write(`HTTP/1.1 ${response.status} ${statusText(response.status)}\r\n\r\n`);
          socket.destroy();
        }
      } catch {
        socket.destroy();
      }
    });
  });

  if (config.schedule) {
    scheduleNextPass(config.schedule);
  }

  /** Run the background pass on the cron schedule, re-arming after each run. */
  function scheduleNextPass(schedule: CronSchedule): void {
    const delay = msUntilNextRun(schedule);
    if (delay === null) {
      console.error(JSON.stringify({ app: "hlg", event: "schedule.unreachable", cron: schedule.expression }));
      return;
    }
    const timer = setTimeout(() => {
      void runScheduledPass(env).catch((error) => {
        console.error(JSON.stringify({ app: "hlg", event: "schedule.error", error: error instanceof Error ? error.message : String(error) }));
      }).finally(() => scheduleNextPass(schedule));
    }, delay);
    // Do not hold the process open just for the schedule.
    timer.unref?.();
  }

  server.listen(config.port, () => {
    console.log(
      JSON.stringify({
        app: "hlg",
        event: "server.start",
        runtime: "node",
        port: config.port,
        db: config.dbPath,
        assets: assets ? config.assetsDir : null,
        schedule_cron: config.schedule?.expression ?? null,
      }),
    );
  });
  server.on("error", (error) => {
    console.error(
      JSON.stringify({
        app: "hlg",
        event: "server.listen_failed",
        port: config.port,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    process.exit(1);
  });
}

function statusText(status: number): string {
  if (status === 400) return "Bad Request";
  if (status === 401) return "Unauthorized";
  if (status === 403) return "Forbidden";
  if (status === 404) return "Not Found";
  return "Error";
}

void main().catch((error) => {
  console.error("fatal:", error);
  process.exit(1);
});
