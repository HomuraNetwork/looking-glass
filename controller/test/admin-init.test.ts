import { describe, expect, it } from "vitest";
import type { Env } from "../src/config";

describe("admin init helpers", () => {
  it("keeps batched init-token queries within D1's 100-parameter limit", async () => {
    const binds: number[] = [];
    const db = {
      prepare() {
        return {
          bind(...values: unknown[]) {
            binds.push(values.length);
            return { all: async () => ({ results: [] }) };
          },
          first: async () => null,
        };
      },
    } as unknown as D1Database;
    const { attachActiveInitTokens } = await import("../src/admin-api");
    await attachActiveInitTokens({ DB: db } as unknown as Env, Array.from({ length: 100 }, (_, index) => ({ id: `node-${index}` })), "https://worker.test");
    // The init-token lookups are batched under D1's 100-parameter limit: 99
    // node ids + the expiry, then the remainder. (Later single-parameter binds
    // are the install-config reads.)
    expect(binds.slice(0, 2)).toEqual([100, 2]);
  });

  it("does not query for an empty node list", async () => {
    let prepares = 0;
    const db = { prepare: () => { prepares += 1; throw new Error("unexpected_query"); } } as unknown as D1Database;
    const { attachActiveInitTokens } = await import("../src/admin-api");
    expect(await attachActiveInitTokens({ DB: db } as unknown as Env, [], "https://worker.test")).toEqual([]);
    expect(prepares).toBe(0);
  });

  it("builds node domains from split base domains", async () => {
    const { nodeDomainsFromBases } = await import("../src/dns");

    expect(
      nodeDomainsFromBases({
        nodeID: "testnode01",
        base: ".lgtest-node.example",
        v4Base: "lgtest-node-v4.example",
        v6Base: "lgtest-node-v6.example",
      }),
    ).toEqual({
      domain: "testnode01.lgtest-node.example",
      domain_v4: "testnode01.lgtest-node-v4.example",
      domain_v6: "testnode01.lgtest-node-v6.example",
    });
  });

  it("builds node domains from a custom prefix", async () => {
    const { nodeDomainsFromBases } = await import("../src/dns");

    expect(nodeDomainsFromBases({ nodeID: "hk02", prefix: "edge-hk", base: "lg.example.net", singleBase: true })).toEqual({
      domain: "edge-hk.lg.example.net",
      domain_v4: "edge-hk-v4.lg.example.net",
      domain_v6: "edge-hk-v6.lg.example.net",
    });
  });

  it("accepts full custom domain overrides", async () => {
    const { nodeDomainsFromBases } = await import("../src/dns");

    expect(
      nodeDomainsFromBases({
        nodeID: "hk02",
        base: "lg.example.net",
        v4Base: "lg-v4.example.net",
        v6Base: "lg-v6.example.net",
        domain: "lg-hk.example.net",
        domainV4: "lg-hk-ipv4.example.net",
        domainV6: "lg-hk-ipv6.example.net",
      }),
    ).toEqual({
      domain: "lg-hk.example.net",
      domain_v4: "lg-hk-ipv4.example.net",
      domain_v6: "lg-hk-ipv6.example.net",
    });
  });

  it("builds address-family domains from one base when split bases are disabled", async () => {
    const { nodeDomainsFromBases } = await import("../src/dns");

    expect(nodeDomainsFromBases({ nodeID: "hk02", base: "lg.example.net", singleBase: true })).toEqual({
      domain: "hk02.lg.example.net",
      domain_v4: "hk02-v4.lg.example.net",
      domain_v6: "hk02-v6.lg.example.net",
    });
  });

  it("builds testnode DNS records from configured domains", async () => {
    const { dnsRecordsForNode } = await import("../src/dns");

    expect(
      dnsRecordsForNode({
        nodeID: "testnode01",
        base: ".lgtest-node.example",
        v4Base: "lgtest-node-v4.example",
        v6Base: "lgtest-node-v6.example",
        ipv4: "203.0.113.9",
        ipv6: "2001:db8::a",
      }),
    ).toEqual([
      { type: "A", name: "testnode01.lgtest-node.example", content: "203.0.113.9" },
      { type: "AAAA", name: "testnode01.lgtest-node.example", content: "2001:db8::a" },
      { type: "A", name: "testnode01.lgtest-node-v4.example", content: "203.0.113.9" },
      { type: "AAAA", name: "testnode01.lgtest-node-v6.example", content: "2001:db8::a" },
    ]);
  });
});
