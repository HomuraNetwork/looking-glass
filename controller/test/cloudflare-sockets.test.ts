import { describe, expect, it, vi } from "vitest";

// The Cloudflare adapter is excluded from the local tsconfig, so importing the
// module under vitest pulls the real implementation. It references the global
// WebSocketPair only inside createSocketPair, which the stubs below provide.

interface StubSocket {
  binaryType: string;
  accepted: Array<{ allowHalfOpen?: boolean }>;
  accept(options?: { allowHalfOpen?: boolean }): void;
}

function stubSocket(): StubSocket {
  return {
    binaryType: "blob",
    accepted: [],
    accept(options) {
      this.accepted.push(options ?? {});
    },
  };
}

/**
 * Two Cloudflare compatibility-date defaults (active at our compatibility date)
 * affect a WebSocket proxy and are guarded here:
 *  - websocket_standard_binary_type: binary frames arrive as Blob; the proxy
 *    forwards with send(), which rejects a Blob, so the adapter must opt the
 *    socket back into ArrayBuffer delivery.
 *  - web_socket_auto_reply_to_close: the runtime auto-replies to a peer Close,
 *    which interferes with proxying; callers ask for half-open.
 */
describe("Cloudflare socket adapter", () => {
  it("opts relayed sockets into ArrayBuffer delivery and half-open accept", async () => {
    const client = stubSocket();
    const server = stubSocket();
    vi.stubGlobal("WebSocketPair", function WebSocketPairStub(this: unknown) {
      return [client, server];
    } as unknown as typeof WebSocketPair);

    const { cfCreateSocketPair, cfSockets } = await import("../src/runtime/cloudflare");
    const pair = cfCreateSocketPair();

    // The server end is what the worker relays through.
    expect(server.binaryType).toBe("arraybuffer");
    expect(pair.server).toBe(server as unknown as typeof pair.server);

    // The core's accept() passes allowHalfOpen; the adapter must forward it.
    pair.server.accept({ allowHalfOpen: true });
    expect(server.accepted).toEqual([{ allowHalfOpen: true }]);

    vi.unstubAllGlobals();
    expect(cfSockets).toBeDefined();
  });

  it("normalizes outbound sockets to ArrayBuffer delivery", async () => {
    const agentSocket = stubSocket();
    // undici rejects constructing a 101 Response, so the stub is a plain object
    // exposing the shape the adapter reads (response.webSocket).
    vi.stubGlobal("fetch", vi.fn(async () => ({ webSocket: agentSocket }) as unknown as Response));

    const { cfSockets } = await import("../src/runtime/cloudflare");
    const socket = await cfSockets.connectWebSocket("https://node.example/jobs/x/ws", { headers: { upgrade: "websocket" } });
    expect(socket).toBe(agentSocket as unknown as typeof socket);
    // Without this the agent's binary frames would arrive as Blob and be
    // dropped when the proxy forwards them.
    expect(agentSocket.binaryType).toBe("arraybuffer");

    vi.unstubAllGlobals();
  });

  it("issues the TCP query without half-closing the write side", async () => {
    // Reproduces the bug found on the live edge: writer.close() half-closes the
    // socket, the Workers runtime tears it down, and the read yields zero bytes.
    // The adapter must write, read to EOF, and only then close the socket.
    const events: string[] = [];
    const chunks = [new TextEncoder().encode("13335 | 1.1.1.1 | 1.1.1.0/24 | AU | apnic\n")];
    const stub = {
      opened: Promise.resolve({}),
      writable: {
        getWriter: () => ({
          write: async () => { events.push("write"); },
          close: async () => { events.push("writer.close"); },
        }),
      },
      readable: {
        getReader: () => ({
          read: async () => (chunks.length ? { done: false, value: chunks.shift() } : { done: true, value: undefined }),
          cancel: async () => {},
        }),
      },
      close: async () => { events.push("socket.close"); },
    };
    const connectFn = vi.fn(() => stub) as unknown as Parameters<typeof createCfTcp>[0];

    const { createCfTcp } = await import("../src/runtime/cloudflare");
    const result = await createCfTcp(connectFn).query("whois.cymru.com", 43, new TextEncoder().encode("begin\nend\n"), { timeoutMs: 200 });

    expect(connectFn).toHaveBeenCalledWith({ hostname: "whois.cymru.com", port: 43 }, { allowHalfOpen: true });
    expect(new TextDecoder().decode(result)).toBe("13335 | 1.1.1.1 | 1.1.1.0/24 | AU | apnic\n");
    expect(events).toEqual(["write", "socket.close"]);
    expect(events).not.toContain("writer.close");
  });
});
