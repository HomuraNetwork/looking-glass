import { beforeEach, describe, it, expect } from "vitest";
import { handleClientInfo, asnOrgFromName } from "../src/client-info";
import { clearAsnCache } from "../src/asn";
import type { TcpRuntime } from "../src/runtime";

function makeRequest(headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/api/client-info", { headers });
}

beforeEach(() => clearAsnCache());

describe("handleClientInfo", () => {
  it("returns 200 with empty strings when no CF data and no TCP", async () => {
    const res = await handleClientInfo(makeRequest());
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, string>;
    expect(body.ip).toBe("127.0.0.1");
    expect(body.colo).toBe("");
    expect(body.asn).toBe("");
  });

  it("includes CF-Connecting-IP header value", async () => {
    const res = await handleClientInfo(makeRequest({ "CF-Connecting-IP": "192.0.2.4" }));
    const body = await res.json() as Record<string, string>;
    expect(body.ip).toBe("192.0.2.4");
  });

  it("falls back to the rightmost x-forwarded-for entry when cf-connecting-ip is absent", async () => {
    // The leftmost entry is the most client-controllable; the rightmost is the
    // closest hop. The spoofable end must never win.
    const body = await (await handleClientInfo(makeRequest({ "X-Forwarded-For": "192.0.2.4, 203.0.113.7" }))).json() as Record<string, string>;
    expect(body.ip).toBe("203.0.113.7");
  });

  it("maps CF properties to response fields without a fallback lookup", async () => {
    const req = new Request("http://localhost/api/client-info");
    (req as any).cf = {
      asn: 64496, asOrganization: "Example Network", colo: "TST",
      country: "US", city: "SG", httpProtocol: "HTTP/2",
      tlsVersion: "TLSv1.3",
    };
    // A TCP runtime that records calls proves the CF path does not fall back.
    let called = 0;
    const tcp: TcpRuntime = { async query() { called++; return new Uint8Array(); } };
    const body = await (await handleClientInfo(req, tcp)).json() as Record<string, string>;
    expect(body.asn).toBe("AS64496");
    expect(body.asOrg).toBe("Example Network");
    expect(body.colo).toBe("TST");
    expect(body.httpProtocol).toBe("HTTP/2");
    expect(body.tlsVersion).toBe("TLSv1.3");
    expect(called).toBe(0);
  });

  it("falls back to a Cymru lookup for the ASN + country off-platform", async () => {
    const tcp: TcpRuntime = {
      async query(_host, _port, payload) {
        const asked = new TextDecoder().decode(payload);
        expect(asked).toContain("192.0.2.1");
        return new TextEncoder().encode(
          "64497 | 192.0.2.1 | 192.0.2.0/24 | ZZ | arin | 2020-01-01 | EXAMPLE-NET - Example Network\n",
        );
      },
    };
    const body = await (await handleClientInfo(makeRequest({ "CF-Connecting-IP": "192.0.2.1" }), tcp)).json() as Record<string, string>;
    expect(body.ip).toBe("192.0.2.1");
    expect(body.asn).toBe("AS64497");
    expect(body.asOrg).toBe("Example Network");
    expect(body.country).toBe("ZZ");
    expect(body.colo).toBe("");
  });

  it("skips the lookup for private addresses", async () => {
    let called = 0;
    const tcp: TcpRuntime = { async query() { called++; return new Uint8Array(); } };
    const body = await (await handleClientInfo(makeRequest({ "CF-Connecting-IP": "192.168.1.5" }), tcp)).json() as Record<string, string>;
    expect(body.asn).toBe("");
    expect(called).toBe(0);
  });
});

describe("asnOrgFromName", () => {
  it("strips the registry prefix from Cymru as-names", () => {
    expect(asnOrgFromName("EXAMPLE-NET - Example Network")).toBe("Example Network");
    expect(asnOrgFromName("No delimiter")).toBe("No delimiter");
  });
});
