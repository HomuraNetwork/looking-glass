import { connect } from "cloudflare:sockets";
import type { HTMLTransform, ProxiedSocket, SocketPair, SocketRuntime, TcpQueryOptions, TcpRuntime } from "./types";

/**
 * Cloudflare runtime adapters. These wire the platform's native capabilities
 * (WebSocketPair, HTMLRewriter, Upgrade-header fetch) into the runtime-neutral
 * interfaces the core uses.
 */

/**
 * WebSockets created on Cloudflare default to delivering binary frames as
 * `Blob` (compatibility flag `websocket_standard_binary_type`, active at our
 * compatibility date). The proxy forwards a frame with `send()`, and
 * `WebSocket.send()` accepts only `string | ArrayBuffer | ArrayBufferView`, so
 * a Blob would make the forward throw and the frame be dropped. Opt this
 * socket back into ArrayBuffer delivery before it is accepted, so relayed
 * binary frames survive.
 */
function forceArrayBufferDelivery(socket: WebSocket): void {
  socket.binaryType = "arraybuffer";
}

export function cfCreateSocketPair(): SocketPair {
  const pair = new WebSocketPair();
  // Cloudflare's WebSocketPair: index 0 is the client end, index 1 the server
  // end. The worker relays through the SERVER end (the core calls accept()
  // on it and listens/sends there); the CLIENT end must be handed back to the
  // platform via the 101 response so it is wired to the browser connection.
  // Returning the server end here instead leaves the browser side dead: the
  // handshake completes (101) but no frames ever flow.
  const client = pair[0] as unknown as WebSocket;
  const server = pair[1] as unknown as WebSocket;
  forceArrayBufferDelivery(server);
  return {
    client: client as unknown as ProxiedSocket,
    server: server as unknown as ProxiedSocket,
    upgradeResponse: () => new Response(null, { status: 101, webSocket: client }),
  };
}

/**
 * Open an outbound WebSocket to a node. Cloudflare performs this with a fetch()
 * carrying an Upgrade header; the platform returns the socket on the response.
 */
async function cfConnectWebSocket(url: string | URL, init: RequestInit): Promise<ProxiedSocket | null> {
  const response = await fetch(new Request(url, init));
  const socket = response.webSocket as unknown as WebSocket | null;
  if (!socket) return null;
  forceArrayBufferDelivery(socket);
  return socket as unknown as ProxiedSocket;
}

export const cfSockets: SocketRuntime = {
  async createSocketPair(): Promise<SocketPair> {
    return cfCreateSocketPair();
  },
  connectWebSocket: cfConnectWebSocket,
};

/**
 * One-shot outbound TCP query over `cloudflare:sockets`.
 *
 * `allowHalfOpen: true` is required and the writable side must NOT be closed
 * before reading: closing it half-closes the connection, and the Workers
 * runtime then tears the whole socket down, so the response arrives as zero
 * bytes. Instead we write, read to EOF (the peer closes after our `end` line),
 * then close the socket ourselves.
 *
 * `connectFn` is injectable so the behavior above can be tested without a live
 * socket.
 */
export function createCfTcp(connectFn: typeof connect = connect): TcpRuntime {
  return {
    async query(hostname: string, port: number, payload: Uint8Array, options: TcpQueryOptions = {}): Promise<Uint8Array> {
      const limit = options.limit ?? 1 << 20;
      const timeoutMs = options.timeoutMs ?? 5000;
      const socket = connectFn({ hostname, port }, { allowHalfOpen: true });
      const writer = socket.writable.getWriter();
      let closed = false;
      const close = () => {
        if (closed) return;
        closed = true;
        void socket.close().catch(() => {});
      };
      const timer = setTimeout(close, timeoutMs);
      try {
        await socket.opened;
        await writer.write(payload);
        // Do not writer.close(): see the note above.
        const reader = socket.readable.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            chunks.push(value);
            total += value.length;
          }
          if (total >= limit) {
            await reader.cancel().catch(() => {});
            break;
          }
        }
        return concatBytes(chunks, total);
      } finally {
        clearTimeout(timer);
        close();
      }
    },
  };
}

export const cfTcp: TcpRuntime = createCfTcp();

function concatBytes(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Apply a title/head injection with HTMLRewriter. Equivalent output to the
 * local runtime's string transform; HTMLRewriter is preferred on Cloudflare
 * because it streams.
 */
export async function cfTransformHTML(response: Response, transform: HTMLTransform): Promise<Response> {
  return new HTMLRewriter()
    .on("title", {
      element(el) {
        el.setInnerContent(transform.title);
      },
    })
    .on("head", {
      element(el) {
        if (transform.headHTML) el.append(transform.headHTML, { html: true });
      },
    })
    .transform(response);
}
