import { describe, expect, it, vi } from "vitest";
import { awaitSocketOpen, wrapWsSocket, type WsLike } from "./sockets";

/**
 * Frame fidelity: `ws` delivers TEXT frames as a Buffer as well. The wrapper
 * must decode text frames and pass binary frames through, or the browser
 * receives a Blob where the frontend expects JSON text (live jobs, iPerf).
 */
type MessageListener = (data: Buffer | ArrayBuffer, isBinary: boolean) => void;

interface FakeSocket extends WsLike {
  emit(data: Buffer | ArrayBuffer, isBinary: boolean): void;
  emitOpen(): void;
  emitClose(): void;
  emitError(): void;
}

function fakeSocket() {
  const messageListeners: MessageListener[] = [];
  const openListeners: Array<() => void> = [];
  const closeListeners: Array<() => void> = [];
  const errorListeners: Array<() => void> = [];
  const sent: unknown[] = [];
  const socket = {
    send(data: unknown) {
      sent.push(data);
    },
    close() {},
    on(event: string, listener: (...args: unknown[]) => void) {
      if (event === "message") messageListeners.push(listener as MessageListener);
      else if (event === "open") openListeners.push(listener as () => void);
      else if (event === "close") closeListeners.push(listener as () => void);
      else if (event === "error") errorListeners.push(listener as () => void);
    },
    readyState: 1,
    emit(data: Buffer | ArrayBuffer, isBinary: boolean) {
      for (const listener of messageListeners) listener(data, isBinary);
    },
    emitOpen() {
      for (const listener of openListeners) listener();
    },
    emitClose() {
      for (const listener of closeListeners) listener();
    },
    emitError() {
      for (const listener of errorListeners) listener();
    },
  } as unknown as FakeSocket;
  return { socket, sent };
}

describe("ws socket wrapper frame fidelity", () => {
  it("decodes text frames into strings", () => {
    const { socket } = fakeSocket();
    const proxied = wrapWsSocket(socket);
    const received: unknown[] = [];
    proxied.addEventListener("message", (event) => received.push(event.data));
    socket.emit(Buffer.from('{"type":"stdout","text":"hi"}'), false);
    expect(received).toEqual(['{"type":"stdout","text":"hi"}']);
  });

  it("passes binary frames through untouched", () => {
    const { socket } = fakeSocket();
    const proxied = wrapWsSocket(socket);
    const received: unknown[] = [];
    proxied.addEventListener("message", (event) => received.push(event.data));
    const payload = Buffer.from([0, 1, 2, 255]);
    socket.emit(payload, true);
    expect(received[0]).toBe(payload);
  });

  it("sends strings as-is so they stay text frames", () => {
    const { socket, sent } = fakeSocket();
    const proxied = wrapWsSocket(socket);
    proxied.send('{"type":"run"}');
    expect(sent).toEqual(['{"type":"run"}']);
  });
});

describe("outbound handshake timeout", () => {
  it("resolves the wrapped socket when the handshake opens in time", async () => {
    const { socket } = fakeSocket();
    const pending = awaitSocketOpen(socket, 500);
    socket.emitOpen();
    const result = await pending;
    expect(result).not.toBeNull();
  });

  it("terminates a stalled handshake and resolves null", async () => {
    const { socket } = fakeSocket();
    const terminate = vi.fn();
    (socket as { terminate?(): void }).terminate = terminate;
    const pending = awaitSocketOpen(socket, 25);
    const result = await Promise.race([
      pending,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout did not fire")), 2000)),
    ]);
    expect(result).toBeNull();
    expect(terminate).toHaveBeenCalledTimes(1);
  });

  it("ignores late open/close events after the timeout fired", async () => {
    const { socket } = fakeSocket();
    const pending = awaitSocketOpen(socket, 20);
    const timedOut = await pending;
    expect(timedOut).toBeNull();
    // A node completing (or closing) the handshake after the timeout must not
    // resurrect the already-settled request.
    socket.emitOpen();
    socket.emitClose();
    socket.emitError();
    await expect(pending).resolves.toBeNull();
  });

  it("resolves null on an immediate error before the timeout", async () => {
    const { socket } = fakeSocket();
    const terminate = vi.fn();
    (socket as { terminate?(): void }).terminate = terminate;
    const pending = awaitSocketOpen(socket, 5000);
    socket.emitError();
    await expect(pending).resolves.toBeNull();
    expect(terminate).not.toHaveBeenCalled();
  });
});
