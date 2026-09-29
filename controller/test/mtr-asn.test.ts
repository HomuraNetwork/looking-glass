import { beforeEach, describe, expect, it } from "vitest";
import { clearAsnCache } from "../src/asn";
import { enrichMtrAsns, isMtrCycleBoundary, parseMtrHop, type MtrHop } from "../src/job-proxy";
import type { ProxiedSocket, TcpRuntime } from "../src/runtime";

const SAMPLE = [
  "Bulk mode; whois.cymru.com [test fixture]",
  "64496   | 192.0.2.1        | 192.0.2.0/24        | ZZ | arin     | 2020-01-01 | EXAMPLE-NET - Example Network",
  "64497   | 198.51.100.1     | 198.51.100.0/24     | ZZ | arin     | 2020-01-01 | EXAMPLE-NET - Example Network",
].join("\n");

function fakeBrowser() {
  const frames: Array<Record<string, unknown>> = [];
  const socket = {
    send(data: string) {
      frames.push(JSON.parse(data) as Record<string, unknown>);
    },
    accept() {},
    close() {},
    addEventListener() {},
  };
  return { socket: socket as unknown as ProxiedSocket, frames };
}

beforeEach(() => clearAsnCache());

describe("mtr cycle boundary", () => {
  it("detects the wrap from the last hop back to the first", () => {
    // Ascending within a cycle: no boundary.
    expect(isMtrCycleBoundary(1, 0)).toBe(false);
    expect(isMtrCycleBoundary(2, 1)).toBe(false);
    expect(isMtrCycleBoundary(12, 2)).toBe(false);
    // Wrapping to a lower hop number starts the next cycle.
    expect(isMtrCycleBoundary(1, 12)).toBe(true);
    expect(isMtrCycleBoundary(3, 12)).toBe(true);
    // Same hop repeated still counts as a wrap (single-hop paths, e.g. ??:).
    expect(isMtrCycleBoundary(1, 1)).toBe(true);
  });
});

describe("mtr ASN enrichment", () => {
  it("patches only hops missing an ASN, in one bulk query, in place", async () => {
    const { socket, frames } = fakeBrowser();
    const hops = new Map<number, MtrHop>();
    hops.set(1, parseMtrHop("1 192.0.2.1 0 3 3 0 0 0")!);
    hops.set(2, parseMtrHop("2 198.51.100.1 0 3 3 0 0 0")!);
    // This hop already has an ASN (agent -z worked): must not be re-queried.
    hops.set(3, parseMtrHop("3. AS64500 192.0.2.9 0.0% 3 1 1 1 1")!);
    // Unreachable hop: no IP to resolve.
    hops.set(4, parseMtrHop("4 ??? 100.0% 3 0 0 0 0")!);

    const queries: string[] = [];
    const tcp: TcpRuntime = {
      async query(_host, _port, payload) {
        queries.push(new TextDecoder().decode(payload));
        return new TextEncoder().encode(SAMPLE);
      },
    };

    const patched = await enrichMtrAsns({ browser: socket, debugEnabled: false, isCurrent: () => true, tcp }, hops);

    expect(patched).toBe(2);
    expect(queries).toHaveLength(1);
    expect(queries[0]).toBe("begin\nverbose\n192.0.2.1\n198.51.100.1\nend\n");

    const byKey = new Map(frames.map((frame) => [frame.key as string, frame]));
    expect(byKey.get("mtr-hop-1")).toMatchObject({ mode: "replace", kind: "mtr", hop: 1, mtr: { asn: "AS64496", host: "192.0.2.1" } });
    expect(byKey.get("mtr-hop-2")).toMatchObject({ mtr: { asn: "AS64497", host: "198.51.100.1" } });
    expect(byKey.has("mtr-hop-3")).toBe(false);
    expect(byKey.has("mtr-hop-4")).toBe(false);
  });

  it("does nothing without a tcp runtime or when superseded", async () => {
    const { socket, frames } = fakeBrowser();
    const hops = new Map<number, MtrHop>([[1, parseMtrHop("1 198.51.100.1 0 1 1 0 0 0")!]]);
    expect(await enrichMtrAsns({ browser: socket, debugEnabled: false, isCurrent: () => true }, hops)).toBe(0);

    const tcp: TcpRuntime = { async query() { return new TextEncoder().encode(SAMPLE); } };
    expect(await enrichMtrAsns({ browser: socket, debugEnabled: false, isCurrent: () => false, tcp }, hops)).toBe(0);
    expect(frames).toHaveLength(0);
  });

  it("does not re-patch hops already enriched by an earlier pass", async () => {
    const { socket, frames } = fakeBrowser();
    const hops = new Map<number, MtrHop>();
    hops.set(1, parseMtrHop("1 198.51.100.1 0 3 3 0 0 0")!);
    const tcp: TcpRuntime = { async query() { return new TextEncoder().encode(SAMPLE); } };

    expect(await enrichMtrAsns({ browser: socket, debugEnabled: false, isCurrent: () => true, tcp }, hops)).toBe(1);
    expect(await enrichMtrAsns({ browser: socket, debugEnabled: false, isCurrent: () => true, tcp }, hops)).toBe(0);
    expect(frames).toHaveLength(1);
  });

  it("records resolved ASNs so a later pass over a changed hop reuses them", async () => {
    const { socket, frames } = fakeBrowser();
    const hops = new Map<number, MtrHop>();
    const knownAsns = new Map<string, string>();
    const queries: string[] = [];
    const tcp: TcpRuntime = {
      async query(_host, _port, payload) {
        queries.push(new TextDecoder().decode(payload));
        return new TextEncoder().encode(SAMPLE);
      },
    };

    hops.set(1, parseMtrHop("1 192.0.2.1 0 1 1 0 0 0")!);
    hops.set(2, parseMtrHop("2 198.51.100.1 0 1 1 0 0 0")!);
    expect(await enrichMtrAsns({ browser: socket, debugEnabled: false, isCurrent: () => true, tcp }, hops, knownAsns)).toBe(2);
    expect(queries).toHaveLength(1);
    expect(knownAsns.get("192.0.2.1")).toBe("AS64496");
    expect(knownAsns.get("198.51.100.1")).toBe("AS64497");

    // A deeper hop is discovered later: only that address is queried.
    hops.set(3, parseMtrHop("3 203.0.113.1 0 1 1 0 0 0")!);
    await enrichMtrAsns({ browser: socket, debugEnabled: false, isCurrent: () => true, tcp }, hops, knownAsns);
    expect(queries).toHaveLength(2);
    expect(queries[1]).toBe("begin\nverbose\n203.0.113.1\nend\n");
    // Already-known hops keep their ASN and are not re-patched.
    const patchedHops = frames.filter((frame) => frame.kind === "mtr").map((frame) => frame.hop);
    expect(patchedHops.filter((hop) => hop === 1)).toHaveLength(1);
  });
});
