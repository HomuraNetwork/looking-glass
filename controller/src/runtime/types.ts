/**
 * Runtime abstraction: the small set of platform capabilities the worker core
 * depends on. The Cloudflare implementation is the platform types themselves
 * (D1Database, WebSocketPair, Fetcher) so the Cloudflare path is a zero-change
 * drop-in; a local runtime implements the same interfaces on top of SQLite /
 * `ws` / the filesystem.
 *
 * Keep this surface intentionally minimal: only the members the core actually
 * uses. Widening it is a deliberate act.
 */

/**
 * A SQL database. Structured so the platform's `D1Database` satisfies it
 * as-is (no adapter needed on Cloudflare).
 *
 * Only these members are used by the core:
 *  - prepare(sql).bind(...).first<T>()/.all<T>()/.run()
 *  - batch(statements)
 *
 * `raw`, `exec`, `dump`, `withSession` are intentionally out of scope.
 */
export interface SqlStatement {
  bind(...values: unknown[]): SqlStatement;
  first<T = unknown>(colName: string): Promise<T | null>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<SqlResult<T>>;
  run<T = Record<string, unknown>>(): Promise<SqlResult<T>>;
}

export interface SqlResult<T = unknown> {
  success: true;
  results: T[];
  meta: { changes?: number } & Record<string, unknown>;
}

export interface SqlDatabase {
  prepare(query: string): SqlStatement;
  batch<T = unknown>(statements: SqlStatement[]): Promise<SqlResult<T>[]>;
}

/**
 * A WebSocket as the proxy code needs it, independent of runtime. Cloudflare's
 * `WebSocket` satisfies this shape; the local runtime wraps `ws` (where
 * `accept()` is a no-op because the handshake is already complete).
 */
export interface ProxiedSocket {
  /**
   * Accept the server side of the pair. No-op where already accepted.
   *
   * `allowHalfOpen` keeps the socket from auto-replying to a peer Close, which
   * the Cloudflare runtime does by default for compatibility dates >=
   * 2026-04-07 (`web_socket_auto_reply_to_close`) and which the runtime docs
   * note interferes with WebSocket proxying. A relay sets it so it can forward
   * the Close to the other peer itself. Other runtimes ignore it.
   */
  accept(options?: { allowHalfOpen?: boolean }): void;
  send(data: string | ArrayBuffer | ArrayBufferView): void;
  close(code?: number, reason?: string): void;
  addEventListener(
    type: "message",
    listener: (event: { data: unknown }) => void,
  ): void;
  addEventListener(type: "close" | "error", listener: () => void): void;
}

/**
 * A pair of connected WebSockets for a proxied conversation. `client` is the
 * browser-facing end that `upgradeResponse()` hands back to the platform
 * (Cloudflare wires it to the browser connection); `server` is the end the
 * worker itself uses — accept it and relay browser frames through it.
 */
export interface SocketPair {
  client: ProxiedSocket;
  server: ProxiedSocket;
  /**
   * Build the HTTP response that completes the upgrade. Cloudflare: the 101
   * Response carrying `client`. The local runtime has already written the
   * handshake to the raw socket by the time this is called, so it returns a
   * placeholder that its entry point discards (undici rejects constructing a
   * 101 Response outside an upgrade).
   */
  upgradeResponse(): Response;
}

/** Creates a connected socket pair ready for bidirectional relay. */
export type SocketPairFactory = () => Promise<SocketPair>;

/**
 * WebSocket operations the proxy core needs. Two directions, both
 * runtime-specific:
 *  - `createSocketPair`: accept an *incoming* upgrade (browser -> worker).
 *    Cloudflare: WebSocketPair (synchronous, wrapped in a promise). Node:
 *    `ws` WebSocketServer.handleUpgrade, which is asynchronous.
 *  - `connectWebSocket`: open an *outbound* WebSocket (worker -> agent node).
 *    Cloudflare: fetch() with an Upgrade header, then response.webSocket.
 *    Node: the `ws` client (Node's fetch cannot perform a WS upgrade).
 */
export interface SocketRuntime {
  createSocketPair(): Promise<SocketPair>;
  /** Open an outbound WebSocket; returns null when the peer did not upgrade. */
  connectWebSocket(url: string | URL, init: RequestInit): Promise<ProxiedSocket | null>;
}

export interface TcpQueryOptions {
  /** Stop reading once this many bytes have arrived. Default 1 MiB. */
  limit?: number;
  /** Abort the exchange after this long. Default 5000ms. */
  timeoutMs?: number;
}

/**
 * One-shot outbound TCP exchange: write `payload`, then read until the peer
 * closes or the limit/timeout is hit. This is the shape the ASN lookup needs
 * (Team Cymru's whois bulk protocol) and nothing more; a general bidirectional
 * socket API would widen the runtime surface for no caller.
 *
 * Cloudflare implements it with `cloudflare:sockets`; the local runtime with
 * `node:net`. Both must NOT half-close the write side before reading: doing so
 * makes some peers (and the Workers runtime) close the whole connection and the
 * response is lost.
 */
export interface TcpRuntime {
  query(hostname: string, port: number, payload: Uint8Array, options?: TcpQueryOptions): Promise<Uint8Array>;
}

/**
 * Serves built static assets. The Cloudflare implementation is the ASSETS
 * `Fetcher` binding; the local one reads from a directory.
 */
export interface AssetServer {
  fetch(request: Request): Promise<Response>;
}

/**
 * A head/title injection applied to the served HTML shell. Provided by the core
 * so runtime implementations only need to apply it, not understand it.
 */
export interface HTMLTransform {
  title: string;
  /** Raw HTML appended inside <head> (already escaped by the caller). */
  headHTML: string;
}
