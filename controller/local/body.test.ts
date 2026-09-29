import { describe, expect, it } from "vitest";
import { EventEmitter } from "node:events";
import { readRequestBody, type BodyRead } from "./body";
import type { IncomingMessage } from "node:http";

/**
 * The transport-level body cap. The entry point has to buffer request bodies
 * before the core can apply its per-endpoint limits, so the read itself must
 * be bounded — an unbounded read lets parallel large uploads exhaust memory.
 */
class FakeRequest extends EventEmitter {
  paused = false;
  pause() {
    this.paused = true;
  }
  resume() {
    this.paused = false;
  }
  push(chunk: Buffer) {
    this.emit("data", chunk);
  }
  end() {
    this.emit("end");
  }
}

describe("local request body cap", () => {
  it("buffers a body that fits the cap", async () => {
    const req = new FakeRequest() as unknown as IncomingMessage & FakeRequest;
    const pending: Promise<BodyRead> = readRequestBody(req, 100);
    req.push(Buffer.from("hello "));
    req.push(Buffer.from("world"));
    req.end();
    const read = await pending;
    if (!("body" in read)) throw new Error("expected a buffered body");
    expect(read.body.toString()).toBe("hello world");
  });

  it("resolves overflow immediately and stops buffering", async () => {
    const req = new FakeRequest() as unknown as IncomingMessage & FakeRequest;
    const pending: Promise<BodyRead> = readRequestBody(req, 8);
    req.push(Buffer.from("12345678")); // exactly at the cap: still fine
    req.push(Buffer.from("9")); // crosses the cap
    const read = await Promise.race([pending, new Promise<never>((_, reject) => setTimeout(() => reject(new Error("not settled synchronously")), 100))]);
    expect(read).toEqual({ overflow: true });
    // The stream is paused and further chunks are not buffered.
    expect(req.paused).toBe(true);
    req.push(Buffer.from("0123456789".repeat(1000)));
    req.end();
    await expect(pending).resolves.toEqual({ overflow: true });
  });

  it("treats a body exactly at the cap as fitting", async () => {
    const req = new FakeRequest() as unknown as IncomingMessage & FakeRequest;
    const pending: Promise<BodyRead> = readRequestBody(req, 8);
    req.push(Buffer.from("12345678"));
    req.end();
    const read = await pending;
    expect("body" in read && read.body.length === 8).toBe(true);
  });

  it("rejects on stream errors", async () => {
    const req = new FakeRequest() as unknown as IncomingMessage & FakeRequest;
    const pending: Promise<BodyRead> = readRequestBody(req, 100);
    req.emit("error", new Error("boom"));
    await expect(pending).rejects.toThrow("boom");
  });
});
