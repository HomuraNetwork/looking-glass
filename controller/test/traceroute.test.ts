import { describe, expect, it } from "vitest";
import { compactTracerouteHop, parseMplsTag, parseTracerouteHop } from "../src/traceroute";

describe("parseTracerouteHop", () => {
  it("parses system -n -e (IPs, MPLS, per-probe times)", () => {
    const hop = parseTracerouteHop(" 5  192.0.2.20 <MPLS:L=404160,E=0,S=1,T=1>  0.564 ms  0.546 ms 192.0.2.30 <MPLS:L=404160,E=0,S=1,T=1>  0.613 ms");
    expect(hop).toMatchObject({ hop: 5, ecmp: true });
    expect(hop!.responders).toEqual([
      { ip: "192.0.2.20", times: [0.564, 0.546], mpls: { label: "404160", tc: "0", ttl: "1" } },
      { ip: "192.0.2.30", times: [0.613], mpls: { label: "404160", tc: "0", ttl: "1" } },
    ]);
  });

  it("parses the reverse-DNS form and drops hostnames", () => {
    const hop = parseTracerouteHop(" 2  192.0.2.28 (192.0.2.28)  0.170 ms cust-edge.example (192.0.2.24)  0.178 ms  0.157 ms");
    expect(hop!.responders).toEqual([
      { ip: "192.0.2.28", times: [0.17], mpls: null },
      { ip: "192.0.2.24", times: [0.178, 0.157], mpls: null },
    ]);
  });

  it("parses the built-in form", () => {
    const hop = parseTracerouteHop(" 5  192.0.2.30 0.511 ms [ECMP] [MPLS 404160/TC0/TTL1]");
    expect(hop!.responders[0]).toEqual({ ip: "192.0.2.30", times: [0.511], mpls: { label: "404160", tc: "0", ttl: "1" } });
  });

  it("marks all-star hops and rejects headers", () => {
    expect(parseTracerouteHop(" 4  * * *")).toMatchObject({ hop: 4, unanswered: true, responders: [] });
    expect(parseTracerouteHop("traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 60 byte packets")).toBeNull();
    expect(parseTracerouteHop("(built-in) traceroute to 1.1.1.1")).toBeNull();
  });

  it("renders a compact hostname-free line", () => {
    const hop = parseTracerouteHop(" 1  203.0.113.1 (203.0.113.1)  0.300 ms  0.191 ms  0.278 ms")!;
    expect(compactTracerouteHop(hop)).toBe("1  203.0.113.1 0.3 ms 0.191 ms 0.278 ms");
  });
});

describe("parseMplsTag", () => {
  it("accepts both forms", () => {
    expect(parseMplsTag("MPLS:L=79999,E=0,S=1,T=1")).toEqual({ label: "79999", tc: "0", ttl: "1" });
    expect(parseMplsTag("MPLS 404160/TC0/TTL1")).toEqual({ label: "404160", tc: "0", ttl: "1" });
    expect(parseMplsTag("")).toBeNull();
  });
});
