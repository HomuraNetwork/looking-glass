import { describe, expect, it, vi } from "vitest";
import { resetWorkerDebugCache, workerDebug, workerDebugEnabledCached, workerError, workerLog, workerLogPayload, workerWarn } from "../src/log";

describe("worker logs", () => {
  it("builds structured payloads without query strings", () => {
    expect(
      workerLogPayload("request.complete", {
        method: "GET",
        url: "https://worker.test/api/jobs/ws?token=secret&node=testnode01",
        status: 101,
      }),
    ).toEqual({
      app: "hlg",
      event: "request.complete",
      method: "GET",
      path: "/api/jobs/ws",
      status: 101,
    });
  });

  it("caches the debug flag so repeated calls do not re-read D1", async () => {
    resetWorkerDebugCache();
    let reads = 0;
    const db = {
      prepare(sql: string) {
        return {
          bind() {
            return this;
          },
          async first<T>() {
            reads += 1;
            if (sql.includes("FROM project_settings")) return { value_json: "true" } as T;
            return null as T | null;
          },
        };
      },
    } as unknown as D1Database;

    expect(await workerDebugEnabledCached(db)).toBe(true);
    expect(await workerDebugEnabledCached(db)).toBe(true);
    // Second call within the TTL is served from the module-level cache.
    expect(reads).toBe(1);
    resetWorkerDebugCache();
    expect(await workerDebugEnabledCached(db)).toBe(true);
    expect(reads).toBe(2);
  });

  it("routes each level to the matching console method", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const debug = vi.spyOn(console, "debug").mockImplementation(() => {});
    try {
      workerLog("info.event", { a: 1 });
      workerWarn("warn.event", { b: 2 });
      workerError("error.event", { c: 3 });

      expect(log).toHaveBeenCalledOnce();
      expect(JSON.parse(String(log.mock.calls[0][0]))).toMatchObject({ event: "info.event", a: 1 });
      expect(warn).toHaveBeenCalledOnce();
      expect(JSON.parse(String(warn.mock.calls[0][0]))).toMatchObject({ event: "warn.event", b: 2 });
      expect(error).toHaveBeenCalledOnce();
      expect(JSON.parse(String(error.mock.calls[0][0]))).toMatchObject({ event: "error.event", c: 3 });
      // workerDebug is still gated on the D1 flag, so nothing is emitted here.
      expect(debug).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      warn.mockRestore();
      error.mockRestore();
      debug.mockRestore();
    }
  });

  it("emits debug only when the debug flag is enabled", async () => {
    resetWorkerDebugCache();
    const debug = vi.spyOn(console, "debug").mockImplementation(() => {});
    const enabledDb = {
      prepare(sql: string) {
        return {
          bind() {
            return this;
          },
          async first<T>() {
            if (sql.includes("FROM project_settings")) return { value_json: "true" } as T;
            return null as T | null;
          },
        };
      },
    } as unknown as D1Database;
    try {
      await workerDebug(enabledDb, "debug.event", { d: 4 });
      expect(debug).toHaveBeenCalledOnce();
      expect(JSON.parse(String(debug.mock.calls[0][0]))).toMatchObject({ event: "debug.event", d: 4 });

      resetWorkerDebugCache();
      debug.mockClear();
      const disabledDb = {
        prepare() {
          return {
            bind() {
              return this;
            },
            async first<T>() {
              return null as T | null;
            },
          };
        },
      } as unknown as D1Database;
      await workerDebug(disabledDb, "debug.hidden");
      expect(debug).not.toHaveBeenCalled();
    } finally {
      debug.mockRestore();
      resetWorkerDebugCache();
    }
  });
});
