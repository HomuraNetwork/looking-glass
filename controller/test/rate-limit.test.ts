import { describe, expect, it } from "vitest";
import { consumeRateLimit } from "../src/rate-limit";

describe("rate limits", () => {
  it("uses a single conditional upsert instead of select then update", async () => {
    const statements: string[] = [];
    const db = {
      prepare(sql: string) {
        statements.push(sql);
        if (/SELECT[\s\S]+FROM rate_limits/i.test(sql)) throw new Error("rate_limit_select_used");
        return {
          bind() {
            return {
              async first<T>() {
                return { count: 1, reset_at: 1780000060 } as T;
              },
            };
          },
        };
      },
    } as unknown as D1Database;

    const result = await consumeRateLimit({
      db,
      action: "download_link",
      node: "testnode01",
      clientIP: "203.0.113.44",
      limit: 6,
      windowSeconds: 60,
      now: 1780000000,
    });

    expect(result).toEqual({ allowed: true, resetAt: 1780000060, remaining: 5 });
    expect(statements).toHaveLength(1);
    expect(statements[0]).toMatch(/ON CONFLICT/i);
    expect(statements[0]).toMatch(/RETURNING/i);
  });

  it("shares the command budget across reconnects using the same D1 key", async () => {
    const counts = new Map<string, number>();
    const db = {
      prepare() {
        return {
          bind(...values: unknown[]) {
            return {
              async first<T>() {
                const key = String(values[0]);
                const count = (counts.get(key) ?? 0) + 1;
                if (count > Number(values[7])) return null;
                counts.set(key, count);
                return { count, reset_at: Number(values[2]) } as T;
              },
            };
          },
        };
      },
    } as unknown as D1Database;
    const input = { db, action: "live_command" as const, node: "n1", clientIP: "203.0.113.8", limit: 10, windowSeconds: 60, now: 1780000000 };
    for (let index = 0; index < 10; index++) expect((await consumeRateLimit(input)).allowed).toBe(true);
    expect((await consumeRateLimit(input)).allowed).toBe(false);
    // A reconnect has no local counter, but the shared D1 bucket remains spent.
    expect((await consumeRateLimit({ ...input })).allowed).toBe(false);
  });
});
