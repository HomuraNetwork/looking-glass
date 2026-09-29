import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildCymruQuery,
  canonicalIPKey,
  clearAsnCache,
  lookupAsns,
  parseCymruResponse,
  CYMRU_HOST,
  CYMRU_PORT,
} from "../src/asn";
import type { TcpRuntime } from "../src/runtime";

const SAMPLE = [
  "Bulk mode; whois.cymru.com [test fixture]",
  "64496   | 192.0.2.1        | 192.0.2.0/24        | ZZ | arin     | 2020-01-01 | EXAMPLE-NET - Example Network",
  "64497   | 198.51.100.1     | 198.51.100.0/24     | ZZ | arin     | 2020-01-01 | EXAMPLE-NET - Example Network",
  "64497   | 2001:db8::68                           | 2001:db8::/32       | ZZ | arin     | 2020-01-01 | EXAMPLE-NET - Example Network",
  "NA      | 192.168.1.1      | NA                  |    | other    |            | NA",
  "Error: no ASN or IP match on line 7.",
].join("\n");

beforeEach(() => clearAsnCache());

describe("Cymru query/response", () => {
  it("builds the bulk verbose request", () => {
    expect(new TextDecoder().decode(buildCymruQuery(["192.0.2.1", "198.51.100.1"]))).toBe("begin\nverbose\n192.0.2.1\n198.51.100.1\nend\n");
  });

  it("parses verbose rows keyed by canonical IP, skipping NA", () => {
    const records = parseCymruResponse(SAMPLE);
    expect(records.get("192.0.2.1")).toEqual({
      asn: "AS64496",
      name: "EXAMPLE-NET - Example Network",
      prefix: "192.0.2.0/24",
      country: "ZZ",
      registry: "arin",
    });
    expect(records.get(canonicalIPKey("2001:db8::68"))?.asn).toBe("AS64497");
    expect(records.has("192.168.1.1")).toBe(false);
    // The header and error lines are ignored.
    expect(records.size).toBe(3);
  });
});

describe("ASN lookup", () => {
  it("queries once for many addresses and caches the result", async () => {
    const calls: Array<{ host: string; port: number; payload: string }> = [];
    const tcp: TcpRuntime = {
      async query(host, port, payload) {
        calls.push({ host, port, payload: new TextDecoder().decode(payload) });
        return new TextEncoder().encode(SAMPLE);
      },
    };

    const first = await lookupAsns(tcp, ["192.0.2.1", "198.51.100.1", "2001:db8::68"]);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ host: CYMRU_HOST, port: CYMRU_PORT });
    expect(calls[0].payload).toBe("begin\nverbose\n192.0.2.1\n198.51.100.1\n2001:db8::68\nend\n");
    expect(first.get("192.0.2.1")?.asn).toBe("AS64496");
    expect(first.get(canonicalIPKey("2001:db8::68"))?.asn).toBe("AS64497");

    // A second lookup for the same addresses is served from the cache: no query.
    const second = await lookupAsns(tcp, ["192.0.2.1", "198.51.100.1", "2001:db8::68"]);
    expect(calls).toHaveLength(1);
    expect(second.get("198.51.100.1")?.asn).toBe("AS64497");
  });

  it("skips non-IP hosts and returns empty without a tcp runtime", async () => {
    const tcp: TcpRuntime = { query: vi.fn(async () => new Uint8Array()) };
    await expect(lookupAsns(tcp, ["???", "example.com"])).resolves.toEqual(new Map());
    expect(tcp.query).not.toHaveBeenCalled();
    await expect(lookupAsns(undefined, ["192.0.2.1"])).resolves.toEqual(new Map());
  });

  it("never throws when the TCP query fails", async () => {
    const tcp: TcpRuntime = { query: vi.fn(async () => { throw new Error("network down"); }) };
    await expect(lookupAsns(tcp, ["192.0.2.1"])).resolves.toEqual(new Map());
  });
});

describe("canonicalIPKey", () => {
  it("normalizes IPv6 so differently-written forms match", () => {
    expect(canonicalIPKey("2001:db8::68")).toBe(canonicalIPKey("2001:DB8:0:0:0:0:0:68"));
    expect(canonicalIPKey("::1")).toBe("::1");
    expect(canonicalIPKey("192.0.2.1")).toBe("192.0.2.1");
  });
});
