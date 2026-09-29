import { describe, expect, it } from "vitest";
import { inspectJobTarget, isPrivateIPAddress } from "../src/ip-guard";

describe("job target ip guard", () => {
  it("classifies private and local addresses", () => {
    expect(isPrivateIPAddress("10.1.2.3")).toBe(true);
    expect(isPrivateIPAddress("192.168.1.20")).toBe(true);
    expect(isPrivateIPAddress("172.16.0.1")).toBe(true);
    expect(isPrivateIPAddress("127.0.0.1")).toBe(true);
    expect(isPrivateIPAddress("fc00::1")).toBe(true);
    expect(isPrivateIPAddress("fe80::1")).toBe(true);
    expect(isPrivateIPAddress("203.0.113.9")).toBe(false);
    expect(isPrivateIPAddress("2606:4700:4700::1111")).toBe(false);
  });

  it("blocks multicast, reserved, benchmarking, and IETF ranges", () => {
    expect(isPrivateIPAddress("224.0.0.1")).toBe(true);
    expect(isPrivateIPAddress("239.1.2.3")).toBe(true);
    expect(isPrivateIPAddress("240.0.0.1")).toBe(true);
    expect(isPrivateIPAddress("255.255.255.255")).toBe(true);
    expect(isPrivateIPAddress("192.0.0.5")).toBe(true);
    expect(isPrivateIPAddress("198.18.0.1")).toBe(true);
    expect(isPrivateIPAddress("198.19.255.255")).toBe(true);
    expect(isPrivateIPAddress("198.20.0.1")).toBe(false);
  });

  it("re-checks IPv4-mapped IPv6 addresses against the IPv4 blocklist", () => {
    expect(isPrivateIPAddress("::ffff:10.0.0.1")).toBe(true);
    expect(isPrivateIPAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateIPAddress("::ffff:c0a8:0001")).toBe(true); // 192.168.0.1
    expect(isPrivateIPAddress("::FFFF:192.168.0.1")).toBe(true);
    expect(isPrivateIPAddress("::ffff:8.8.8.8")).toBe(false);
    expect(isPrivateIPAddress("::ffff:c0a8:0002")).toBe(true); // 192.168.0.2
  });

  it("re-checks deprecated IPv4-compatible IPv6 addresses against the IPv4 blocklist", () => {
    expect(isPrivateIPAddress("::0a00:0001")).toBe(true); // 10.0.0.1
    expect(isPrivateIPAddress("::7f00:0001")).toBe(true); // 127.0.0.1
    expect(isPrivateIPAddress("::0808:0808")).toBe(false); // 8.8.8.8
  });

  it("allows documentation and public IPv6 ranges", () => {
    expect(isPrivateIPAddress("2001:db8::1")).toBe(false);
    expect(isPrivateIPAddress("2606:4700:4700::1111")).toBe(false);
  });

  it("requires frontend-resolved IPs when remote DNS is disabled", async () => {
    const result = await inspectJobTarget({ target: "example.com", ipver: "ipv4", remoteDNS: false }, undefined);
    expect(result).toMatchObject({ allowed: false, error: "frontend_dns_required", status: 400 });
  });

  it("rejects invalid targets before any DNS lookup", async () => {
    let called = false;
    const result = await inspectJobTarget({ target: "not a host!", ipver: "ipv4", remoteDNS: true }, undefined, async () => {
      called = true;
      return new Response("{}");
    });
    expect(result).toMatchObject({ allowed: false, error: "invalid_target", status: 400 });
    expect(called).toBe(false);
  });

  it("rejects literal IP targets that do not match the selected family", async () => {
    expect(await inspectJobTarget({ target: "1.1.1.1", ipver: "ipv6", remoteDNS: false }, undefined)).toMatchObject({
      allowed: false,
      error: "ip_family_mismatch",
      status: 400,
      checkedIPs: ["1.1.1.1"],
    });
    expect(await inspectJobTarget({ target: "2606:4700:4700::1111", ipver: "ipv4", remoteDNS: false }, undefined)).toMatchObject({
      allowed: false,
      error: "ip_family_mismatch",
      status: 400,
      checkedIPs: ["2606:4700:4700::1111"],
    });
  });

  it("blocks selected private IPs before forwarding to the agent", async () => {
    const result = await inspectJobTarget({ target: "192.168.1.20", ipver: "ipv4", remoteDNS: false }, undefined);
    expect(result).toMatchObject({ allowed: false, error: "blocked_private_ip", status: 403, checkedIPs: ["192.168.1.20"] });
  });

  it("checks remote DNS answers but preserves the original command target", async () => {
    const result = await inspectJobTarget(
      { target: "example.com", ipver: "ipv4", remoteDNS: true },
      undefined,
      async () => new Response(JSON.stringify({ Answer: [{ type: 1, data: "203.0.113.9" }] })),
    );
    expect(result).toMatchObject({ allowed: true, target: "example.com", checkedIPs: ["203.0.113.9"] });
  });

  it("blocks remote DNS names that resolve to private addresses", async () => {
    const result = await inspectJobTarget(
      { target: "internal.example", ipver: "ipv4", remoteDNS: true },
      undefined,
      async () => new Response(JSON.stringify({ Answer: [{ type: 1, data: "10.0.0.8" }] })),
    );
    expect(result).toMatchObject({ allowed: false, error: "blocked_private_ip", status: 403, checkedIPs: ["10.0.0.8"] });
  });
});
