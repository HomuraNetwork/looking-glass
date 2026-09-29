import { connect } from "node:net";
import type { TcpQueryOptions, TcpRuntime } from "../src/runtime";

/**
 * Node implementation of the one-shot TCP query used by the ASN lookup.
 *
 * Mirrors the Cloudflare adapter's contract: write the payload, read until the
 * peer closes, then tear the socket down. Unlike `cloudflare:sockets`, Node's
 * `net.Socket` does not half-close implicitly, but the write side is still left
 * open until the peer ends the conversation (Team Cymru closes after `end`).
 */
export const nodeTcp: TcpRuntime = {
  query(hostname: string, port: number, payload: Uint8Array, options: TcpQueryOptions = {}): Promise<Uint8Array> {
    const limit = options.limit ?? 1 << 20;
    const timeoutMs = options.timeoutMs ?? 5000;
    return new Promise<Uint8Array>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let settled = false;
      const socket = connect({ host: hostname, port });
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (error) reject(error);
        else resolve(Buffer.concat(chunks, total));
      };
      const timer = setTimeout(() => finish(new Error("tcp_query_timeout")), timeoutMs);
      timer.unref?.();
      socket.on("connect", () => socket.write(Buffer.from(payload)));
      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        total += chunk.length;
        if (total >= limit) finish();
      });
      socket.on("end", () => finish());
      socket.on("close", () => finish());
      socket.on("error", (error) => finish(error));
    });
  },
};
