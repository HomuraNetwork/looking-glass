import { describe, expect, it, vi } from "vitest";
import { fetchNode, nodeOrigin, nodeURL } from "../src/node-transport";

const domain = "testnode01.lgtest-node.example";

describe("node transport (https only)", () => {
  it("fetches over HTTPS and never downgrades to plaintext HTTP", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        seen.push(request.url);
        if (request.url.startsWith("https://")) {
          throw new Error("dial tcp: connection refused");
        }
        return new Response("should not happen", { status: 200 });
      }),
    );
    try {
      // A transport failure must surface; there is no HTTP fallback.
      await expect(
        fetchNode({ domain, path: "/generate_204" }),
      ).rejects.toThrow("dial tcp: connection refused");
      // Only the HTTPS attempt was made.
      expect(seen).toEqual([`https://${domain}/generate_204`]);
      expect(seen.some((url) => url.startsWith("http://"))).toBe(false);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("preserves a Request input body for the single HTTPS attempt", async () => {
    const body = "ping-payload";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        expect(request.method).toBe("POST");
        expect(await request.text()).toBe(body);
        return new Response("ok", { status: 200 });
      }),
    );
    try {
      const request = new Request(`https://${domain}/_lg/control/iperf/open`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      const response = await fetchNode({
        domain,
        path: "/_lg/control/iperf/open",
        init: request,
      });
      expect(response.status).toBe(200);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("routes control requests through a configured HTTPS port", async () => {
    expect(nodeOrigin(domain, 8443)).toBe(`https://${domain}:8443`);
    expect(nodeURL(domain, 8443, "/_lg/control/cert/reload").toString()).toBe(`https://${domain}:8443/_lg/control/cert/reload`);
    const seen: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      seen.push(request.url);
      return new Response(null, { status: 204 });
    }));
    try {
      await fetchNode({ domain, port: 9443, path: "/generate_204" });
      expect(seen).toEqual([`https://${domain}:9443/generate_204`]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
