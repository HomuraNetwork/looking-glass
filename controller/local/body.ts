import type { IncomingMessage } from "node:http";

/**
 * Transport-level cap on inbound request bodies for the local runtime.
 *
 * The core enforces per-endpoint JSON limits (readJSON: 64 KiB), but the entry
 * point has to buffer the raw body BEFORE the core can validate anything —
 * without a transport cap, any client could hold arbitrarily large uploads in
 * process memory (parallel huge requests exhaust the Node process). This cap
 * bounds that buffering; it is deliberately larger than the JSON limit so a
 * future non-JSON endpoint is not blocked by the transport, and the stream is
 * no longer buffered once the cap is crossed (memory stays bounded even while
 * the peer keeps sending).
 */
export const MAX_BODY_BYTES = 1 << 20; // 1 MiB

/** Signal that the body exceeded MAX_BODY_BYTES and was not buffered. */
export class BodyTooLargeError extends Error {
  constructor() {
    super("request body exceeds the transport limit");
    this.name = "BodyTooLargeError";
  }
}

export type BodyRead = { body: Buffer } | { overflow: true };

/**
 * Buffer an inbound request body up to maxBytes.
 *
 * On overflow the promise resolves immediately with { overflow: true } and the
 * stream is paused: no further chunk is buffered. The caller is expected to
 * answer 413 with Connection: close and then tear the socket down (see the
 * server handler in entry.ts) — the socket must NOT be destroyed before the
 * response has been flushed, or the client never sees the status.
 */
export function readRequestBody(req: IncomingMessage, maxBytes: number = MAX_BODY_BYTES): Promise<BodyRead> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        chunks.length = 0;
        req.pause();
        resolve({ overflow: true });
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      resolve({ body: Buffer.concat(chunks) });
    });
    req.on("error", (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}
