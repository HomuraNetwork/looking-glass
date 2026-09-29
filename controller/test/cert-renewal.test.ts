import { describe, expect, it, vi } from "vitest";
import { triggerNodeSync } from "../src/node-trigger";
import { nudgeExpiringCertificateNodes } from "../src/cert-renewal";
import type { Env } from "../src/config";

const TEST_ADMIN_SIGN_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  d: "8KFFpX6ChMcTnF7o8_6XBcVbZmf3jENYipawxBlhXlE",
  x: "GpxaP5sYy-7BlvsIbAgSzGMefIXx4k7EQ5t70spALf8",
} as JsonWebKey;

function envWith(): Env {
  const secrets: Record<string, string> = { LG_ADMIN_SIGN_JWK: JSON.stringify(TEST_ADMIN_SIGN_JWK) };
  return {
    DB: {
      prepare(sql: string) {
        const all = async <T>() => ({ results: [] as T[], success: true });
        const first = async <T>() => {
          if (sql.includes("FROM runtime_secrets")) {
            const value = secrets[String((arguments as unknown as unknown[])[0])];
            return (value ? { value } : null) as T | null;
          }
          return null as T | null;
        };
        return {
          all,
          first,
          run: async () => ({ success: true, meta: { changes: 1 } }),
          bind(...values: unknown[]) {
            return {
              async run() {
                return { success: true, meta: { changes: 1 } };
              },
              async first<T>() {
                if (sql.includes("FROM runtime_secrets")) {
                  const value = secrets[String(values[0])];
                  return (value ? { value } : null) as T | null;
                }
                return null as T | null;
              },
              all,
            };
          },
        };
      },
    } as unknown as D1Database,
  } as unknown as Env;
}

describe("triggerNodeSync", () => {
  it("POSTs an admin-signed reload request and reports success", async () => {
    const seen: { url: string; method: string }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        seen.push({ url: request.url, method: request.method });
        expect(request.headers.get("x-lg-signature")).toBeTruthy();
        return new Response("{}", { status: 200 });
      }),
    );
    try {
      const result = await triggerNodeSync(envWith(), { id: "n1", internal_id: "n1", domain: "n1.example.net" });
      expect(result.ok).toBe(true);
      expect(seen).toEqual([{ url: "https://n1.example.net/_lg/control/cert/reload", method: "POST" }]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("reports failure without throwing when the node is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("dial tcp: connection refused");
      }),
    );
    try {
      const result = await triggerNodeSync(envWith(), { id: "n1", internal_id: "n1", domain: "n1.example.net" });
      expect(result.ok).toBe(false);
      expect(result.error).toContain("connection refused");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("nudgeExpiringCertificateNodes", () => {
  it("does nothing when there are no managed bundles", async () => {
    const result = await nudgeExpiringCertificateNodes(envWith());
    expect(result).toEqual({ checked: 0, nudged: 0, failed: 0 });
  });
});
