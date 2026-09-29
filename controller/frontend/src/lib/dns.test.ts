import { describe, expect, it } from "vitest";
import { buildCloudflareDNSURL, resolveFrontendDNS } from "./dns";

describe("frontend http dns", () => {
  it("builds cloudflare dns json urls", () => {
    expect(buildCloudflareDNSURL("example.com", "A")).toBe("https://cloudflare-dns.com/dns-query?name=example.com&type=A");
  });

  it("formats ipv4 answers from cloudflare dns json", async () => {
    const result = await resolveFrontendDNS("example.com", "ipv4", async () => {
      return new Response(JSON.stringify({ Answer: [{ type: 1, data: "192.0.2.34" }] }), {
        headers: { "content-type": "application/json" },
      });
    });

    expect(result).toEqual({
      lines: ["frontend dns: example.com", "  A 192.0.2.34"],
      answers: ["192.0.2.34"],
      skipped: false,
    });
  });

  it("returns all matching answers so the user can choose one before submit", async () => {
    const result = await resolveFrontendDNS("example.com", "ipv4", async () => {
      return new Response(
        JSON.stringify({
          Answer: [
            { type: 1, data: "192.0.2.35" },
            { type: 1, data: "192.0.2.34" },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      );
    });

    expect(result.answers).toEqual(["192.0.2.34", "192.0.2.35"]);
  });

  it("does not fall back to remote dns when frontend dns has no answers", async () => {
    const result = await resolveFrontendDNS("missing.example", "ipv4", async () => {
      return new Response(JSON.stringify({ Answer: [] }), {
        headers: { "content-type": "application/json" },
      });
    });

    expect(result).toEqual({
      lines: ["frontend dns: missing.example", "  no A records found"],
      answers: [],
      skipped: false,
    });
  });

  it("rejects invalid targets before querying http dns", async () => {
    let called = false;
    const result = await resolveFrontendDNS("not a host!", "ipv4", async () => {
      called = true;
      return new Response("{}");
    });

    expect(result).toEqual({
      lines: ["invalid target: not a domain or IP"],
      answers: [],
      skipped: false,
      error: "invalid_target",
    });
    expect(called).toBe(false);
  });

  it("skips http dns for literal IP targets", async () => {
    const result = await resolveFrontendDNS("  192.0.2.1  ", "ipv4", async () => {
      throw new Error("fetch should not be called");
    });

    expect(result).toEqual({
      lines: [],
      answers: ["192.0.2.1"],
      skipped: true,
    });
  });
});
