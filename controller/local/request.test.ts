import { describe, expect, it } from "vitest";
import {
  applyClientIPHeaders,
  forwardedHeaderTrusted,
  matchesTrustedProxy,
  normalizeRemoteAddress,
  parseTrustedProxyCIDRs,
  requestOrigin,
  resolveClientIP,
} from "./request";

describe("local request network normalization", () => {
  it("normalizes IPv4-mapped socket addresses", () => {
    expect(normalizeRemoteAddress("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(normalizeRemoteAddress("2001:db8::1")).toBe("2001:db8::1");
    expect(normalizeRemoteAddress(undefined)).toBe("unknown");
  });

  it("ignores client-supplied forwarding headers by default (TCP peer wins)", () => {
    const headers = { "cf-connecting-ip": "192.0.2.4", "x-forwarded-for": "192.0.2.4" };
    // A spoofed header must never become the client IP: rate limits, token IP
    // bindings, and audit entries all key off this.
    expect(resolveClientIP(headers, "198.51.100.9", false)).toBe("198.51.100.9");

    const out = new Headers();
    out.set("cf-connecting-ip", "192.0.2.4");
    out.set("x-forwarded-for", "192.0.2.4");
    applyClientIPHeaders(out, "198.51.100.9");
    expect(out.get("cf-connecting-ip")).toBe("198.51.100.9");
    expect(out.get("x-forwarded-for")).toBeNull();
  });

  it("with a trusted proxy, the rightmost x-forwarded-for entry wins", () => {
    // Proxy 10.0.0.5 observed the real client 203.0.113.7 and appended it;
    // the attacker-supplied leftmost entry must be ignored.
    const headers = { "x-forwarded-for": "192.0.2.4, 203.0.113.7" };
    expect(resolveClientIP(headers, "10.0.0.5", true)).toBe("203.0.113.7");
  });

  it("ignores client-supplied entries with the default single trusted hop", () => {
    // A direct client can send XFF itself. With one trusted proxy the client is
    // the rightmost entry, so a spoofed leftmost address never wins.
    const headers = { "x-forwarded-for": "203.0.113.7" };
    expect(resolveClientIP(headers, "198.51.100.9", true)).toBe("203.0.113.7");
    // A forged extra hop must not shift which entry is selected.
    const forged = { "x-forwarded-for": "192.0.2.4, 192.0.2.8" };
    expect(resolveClientIP(forged, "198.51.100.9", true)).toBe("192.0.2.8");
  });

  it("walks the configured number of trusted hops from the right", () => {
    // Two proxies: the client is two entries from the right.
    const headers = { "x-forwarded-for": "203.0.113.7, 10.0.0.5" };
    expect(resolveClientIP(headers, "10.0.0.6", true, 2)).toBe("203.0.113.7");
    // Claiming more hops than the chain has falls back to the peer instead of
    // trusting a client-supplied leftmost value.
    expect(resolveClientIP({ "x-forwarded-for": "203.0.113.7" }, "10.0.0.6", true, 2)).toBe("10.0.0.6");
  });

  it("falls back to the TCP peer when no forwarded chain is present", () => {
    expect(resolveClientIP({}, "198.51.100.9", true)).toBe("198.51.100.9");
    expect(resolveClientIP({ "x-forwarded-for": "" }, "198.51.100.9", true)).toBe("198.51.100.9");
  });

  it("reads the configured client-IP header", () => {
    // e.g. a proxy that sets X-Real-IP instead of X-Forwarded-For.
    const headers = { "x-real-ip": "203.0.113.7" };
    expect(resolveClientIP(headers, "10.0.0.5", true, 1, "x-real-ip")).toBe("203.0.113.7");
    // The default header is ignored when another is configured.
    expect(resolveClientIP({ "x-forwarded-for": "192.0.2.4" }, "10.0.0.5", true, 1, "x-real-ip")).toBe("10.0.0.5");
    // A custom header is still only honored under trustProxy.
    expect(resolveClientIP(headers, "10.0.0.5", false, 1, "x-real-ip")).toBe("10.0.0.5");
  });

  it("strips a port from custom-header values", () => {
    expect(resolveClientIP({ "x-real-ip": "203.0.113.7:52344" }, "10.0.0.5", true, 1, "x-real-ip")).toBe("203.0.113.7");
    expect(resolveClientIP({ "x-real-ip": "[2001:db8::1]:443" }, "10.0.0.5", true, 1, "x-real-ip")).toBe("2001:db8::1");
  });

  it("clears consumed forwarding headers when rebuilding the client IP", () => {
    const out = new Headers();
    out.set("x-forwarded-for", "192.0.2.4");
    out.set("x-real-ip", "192.0.2.4");
    applyClientIPHeaders(out, "198.51.100.9", "x-real-ip");
    expect(out.get("cf-connecting-ip")).toBe("198.51.100.9");
    expect(out.get("x-forwarded-for")).toBeNull();
    expect(out.get("x-real-ip")).toBeNull();
  });

  it("builds the request origin from the environment override", () => {
    expect(requestOrigin({ host: "internal:8787" }, "localhost:8787", { trustProxy: false, publicOrigin: "https://lg.example.com/" })).toBe("https://lg.example.com");
  });

  it("honors x-forwarded-proto only from a trusted proxy", () => {
    const headers = { host: "lg.example.com", "x-forwarded-proto": "https" };
    // Untrusted: an attacker must not be able to flip the request scheme
    // (the admin session cookie's Secure attribute follows it).
    expect(requestOrigin(headers, "localhost:8787", { trustProxy: false })).toBe("http://lg.example.com");
    expect(requestOrigin(headers, "localhost:8787", { trustProxy: true })).toBe("https://lg.example.com");
  });

  it("uses the rightmost x-forwarded-proto so a client cannot prepend one", () => {
    // Client sends "https" hoping to spoof a secure origin; the trusted proxy
    // appended the real scheme ("http") last, which is what must win.
    const headers = { host: "lg.example.com", "x-forwarded-proto": "https, http" };
    expect(requestOrigin(headers, "localhost:8787", { trustProxy: true })).toBe("http://lg.example.com");
  });

  it("defaults to http against the request host", () => {
    expect(requestOrigin({ host: "10.1.2.3:8787" }, "localhost:8787", { trustProxy: false })).toBe("http://10.1.2.3:8787");
    expect(requestOrigin({}, "localhost:8787", { trustProxy: false })).toBe("http://localhost:8787");
  });

  it("parses trusted-proxy IPs and CIDRs (v4, v6, mapped) and rejects invalid input", () => {
    const entries = parseTrustedProxyCIDRs("127.0.0.1/32, ::1/128 172.18.0.0/16, [2001:db8::]/32, ::ffff:10.0.0.1");
    expect(entries).toHaveLength(5);
    expect(entries[0]).toMatchObject({ family: "ipv4", prefix: 32 });
    expect(entries[1]).toMatchObject({ family: "ipv6", prefix: 128 });
    expect(entries[2]).toMatchObject({ family: "ipv4", prefix: 16 });
    expect(entries[3]).toMatchObject({ family: "ipv6", prefix: 32 });
    expect(entries[4]).toMatchObject({ family: "ipv4", prefix: 32 });
    expect(parseTrustedProxyCIDRs(undefined)).toEqual([]);
    expect(parseTrustedProxyCIDRs("   ")).toEqual([]);
    // A security allowlist must not silently degrade to "trust everyone".
    expect(() => parseTrustedProxyCIDRs("999.1.1.1")).toThrow();
    expect(() => parseTrustedProxyCIDRs("10.0.0.0/33")).toThrow();
    expect(() => parseTrustedProxyCIDRs("10.0.0.0/-1")).toThrow();
    expect(() => parseTrustedProxyCIDRs("::1/129")).toThrow();
    // Empty or non-decimal prefixes must be rejected: Number("") is 0, which
    // would turn "10.0.0.0/" into 0.0.0.0/0 (trust everyone).
    expect(() => parseTrustedProxyCIDRs("10.0.0.0/")).toThrow();
    expect(() => parseTrustedProxyCIDRs("10.0.0.0/0x10")).toThrow();
    expect(() => parseTrustedProxyCIDRs("10.0.0.0/ 8")).toThrow();
    // Whitespace, newlines, and repeated separators are tolerated.
    expect(parseTrustedProxyCIDRs("  10.0.0.0/8 ,\n\t::1/128 ,  ")).toHaveLength(2);
  });

  it("matches a peer against exact IPs and CIDRs", () => {
    const entries = parseTrustedProxyCIDRs("10.0.0.0/8, 2001:db8::/32, 127.0.0.1/32");
    expect(matchesTrustedProxy(entries, "10.1.2.3")).toBe(true);
    expect(matchesTrustedProxy(entries, "192.0.2.11")).toBe(false);
    expect(matchesTrustedProxy(entries, "2001:db8:abcd::1")).toBe(true);
    expect(matchesTrustedProxy(entries, "2001:db9::1")).toBe(false);
    expect(matchesTrustedProxy(entries, "127.0.0.1")).toBe(true);
    expect(matchesTrustedProxy(entries, "::ffff:10.1.2.3")).toBe(true);
    expect(matchesTrustedProxy(entries, "fe80::1%eth0")).toBe(false);
    expect(matchesTrustedProxy(entries, "not-an-ip")).toBe(false);
  });

  it("gates forwarded-header trust on the allowlist unless a header is explicit", () => {
    const list = parseTrustedProxyCIDRs("10.0.0.0/8");
    // No trust proxy: forwarded headers are never believed.
    expect(forwardedHeaderTrusted({ trustProxy: false, clientIPHeaderExplicit: false, trustedProxyList: list }, "10.0.0.1")).toBe(false);
    // An explicit LG_TRUST_PROXY_HEADER opts out of the allowlist (the operator
    // owns perimeter control: e.g. CloudFront with an unenumerable origin set).
    expect(forwardedHeaderTrusted({ trustProxy: true, clientIPHeaderExplicit: true, trustedProxyList: list }, "203.0.113.9")).toBe(true);
    // Default header + allowlist: only a listed peer is believed.
    expect(forwardedHeaderTrusted({ trustProxy: true, clientIPHeaderExplicit: false, trustedProxyList: list }, "10.0.0.1")).toBe(true);
    expect(forwardedHeaderTrusted({ trustProxy: true, clientIPHeaderExplicit: false, trustedProxyList: list }, "203.0.113.9")).toBe(false);
    // Default header + no allowlist: legacy behavior (startup warns).
    expect(forwardedHeaderTrusted({ trustProxy: true, clientIPHeaderExplicit: false, trustedProxyList: [] }, "203.0.113.9")).toBe(true);
  });
});
