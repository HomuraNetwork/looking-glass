import type { HTMLTransform, ProxiedSocket } from "../src/runtime";

/**
 * Node runtime adapters built on `ws`.
 *
 * Outbound WebSocket support lives here because Node's fetch cannot open a
 * WebSocket client. The HTTP entry point handles inbound upgrades directly:
 * it wraps the accepted `ws` socket and builds the runtime socket pair.
 *  - outbound: `ws` in client mode.
 */

/** Minimal shape of a `ws` WebSocket we rely on (avoids a hard @types/ws dep). */
export interface WsLike {
  send(data: unknown): void;
  close(code?: number, reason?: string): void;
  /** Forcibly destroy the underlying connection (used on handshake timeout). */
  terminate?(): void;
  on(event: "message", listener: (data: RawWsData, isBinary: boolean) => void): void;
  on(event: "close" | "error", listener: () => void): void;
  readyState: number;
}

/** ws delivers message data as Buffer | ArrayBuffer | Buffer[]; text frames included. */
type RawWsData = Buffer | ArrayBuffer | Buffer[];

const WS_OPEN = 1;

/** Wrap a `ws` socket as the runtime's ProxiedSocket (accept() is a no-op). */
export function wrapWsSocket(socket: WsLike): ProxiedSocket {
  return {
    accept() {
      // The ws handshake is already complete by the time we hold the socket.
    },
    send(data) {
      if (socket.readyState !== WS_OPEN) return;
      try {
        socket.send(data);
      } catch {
        // Peer closed between the check and the send; dropping is correct.
      }
    },
    close(code, reason) {
      try {
        socket.close(code, reason);
      } catch {
        // Already closing/closed.
      }
    },
    addEventListener(type, listener) {
      if (type === "message") {
        // ws hands TEXT frames over as a Buffer too; forwarding it verbatim
        // would send a BINARY frame to the peer and browsers would surface a
        // Blob where the frontend expects JSON text. Decode text frames,
        // pass binary frames through untouched (e.g. iPerf payloads).
        socket.on("message", (data, isBinary) => {
          (listener as (event: { data: unknown }) => void)({ data: isBinary ? data : String(data) });
        });
        return;
      }
      socket.on(type, () => (listener as () => void)());
    },
  };
}

/**
 * How long an outbound WebSocket may take to complete its handshake. A node
 * that accepts the TCP connection but stalls the upgrade would otherwise hold
 * the proxy request open indefinitely, occupying the connection and handler.
 */
const HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * Wait for an outbound socket to finish its handshake, with an application-
 * layer timeout. Returns the wrapped socket, or null on error/close/timeout.
 * On timeout the half-open connection is terminated first.
 */
export function awaitSocketOpen(socket: WsLike, timeoutMs: number = HANDSHAKE_TIMEOUT_MS): Promise<ProxiedSocket | null> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: ProxiedSocket | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(value);
    };
    const timeout = setTimeout(() => {
      // Kill the half-open connection, then report failure. Late open/error
      // events are ignored via the settled guard.
      socket.terminate?.();
      finish(null);
    }, timeoutMs);
    socket.on("open" as never, () => finish(wrapWsSocket(socket)) as never);
    socket.on("error", () => finish(null));
    socket.on("close", () => finish(null));
  });
}

/**
 * Outbound WebSocket to an agent node (client mode). Returns null when the
 * connection fails to open or the handshake does not complete in time,
 * matching the Cloudflare path where a non-upgrade response yields no socket.
 */
export async function connectWsWebSocket(url: string | URL, init: RequestInit, timeoutMs?: number): Promise<ProxiedSocket | null> {
  const WebSocketClient = require("ws") as new (url: string, options?: Record<string, unknown>) => WsLike;
  const headers = (init.headers as Record<string, string> | undefined) ?? {};
  const socket = new WebSocketClient(String(url), { headers });
  return await awaitSocketOpen(socket, timeoutMs);
}

/** Apply the head/title injection by string substitution (no HTMLRewriter). */
export async function nodeTransformHTML(response: Response, transform: HTMLTransform): Promise<Response> {
  const html = await response.text();
  const withTitle = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapeTitle(transform.title)}</title>`);
  const withHead = withTitle.includes("</head>")
    ? withTitle.replace("</head>", `${transform.headHTML}\n</head>`)
    : withTitle;
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(withHead, { status: response.status, headers });
}

function escapeTitle(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}
