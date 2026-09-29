import type { IncomingHttpHeaders } from "node:http";

import { parseIPv4, parseIPv6Bytes } from "../src/ip-guard";

/**
 * Client-network normalization for the local runtime.
 *
 * The core derives the client IP from `cf-connecting-ip` (set by Cloudflare
 * itself, so it is trustworthy there) with an `x-forwarded-for` fallback. On a
 * plain Node deployment those headers arrive from the CLIENT and are trivially
 * spoofable — which would forge rate-limit keys, download-token IP bindings,
 * live-session IP checks, and audit entries. The entry point therefore
 * rebuilds both headers from the TCP peer address before the core sees them:
 *
 *  - default (LG_TRUST_PROXY unset): the socket peer IS the client. Incoming
 *    cf-connecting-ip / x-forwarded-for are discarded.
 *  - LG_TRUST_PROXY=1: the deployment sits behind reverse proxy(ies). The
 *    client address is the entry `trustedHops` from the RIGHT of the forwarded
 *    header, because each trusted proxy APPENDS the address it saw (so the
 *    rightmost entries are the closest, most-trusted hops and any
 *    client-supplied entries are pushed to the left). LG_TRUST_PROXY_HOPS sets
 *    how many trusted proxies there are (default 1). LG_TRUST_PROXY_HEADER picks
 *    which header carries the chain (default `x-forwarded-for`) for proxies
 *    that use another one (`x-real-ip`, or `cf-connecting-ip` behind
 *    Cloudflare); a bracketed IPv6 or `host:port` value is normalized.
 *
 *  The proxy MUST be configured to overwrite OR append consistently, and the
 *  hop count must match reality: claiming more trusted hops than actually exist
 *  lets a client-supplied entry be selected. A proxy that overwrites the
 *  forwarded header with the single observed address is safest and works with
 *  the default hop count of 1.
 */

export interface RequestNetworkOptions {
  /** Trust a proxy-supplied client-IP header from the direct peer. */
  trustProxy: boolean;
  /** Number of trusted proxy hops (>= 1). Only used when trustProxy is set. */
  trustedHops?: number;
  /** Absolute origin override (e.g. "https://lg.example.com"). */
  publicOrigin?: string;
  /**
   * Header the trusted proxy sets the client IP in (default "x-forwarded-for").
   * Set this when the front proxy uses a different one (e.g. "x-real-ip", or
   * "cf-connecting-ip" when Cloudflare fronts the origin). Only read when
   * trustProxy is set; the value may be a comma-separated chain (the rightmost
   * `trustedHops` entry wins) or a single address.
   */
  clientIPHeader?: string;
}

/** Default header carrying the forwarded client chain. */
export const DEFAULT_CLIENT_IP_HEADER = "x-forwarded-for";

/**
 * Normalize one forwarded value: trim, drop a `:port` suffix, and unwrap
 * bracketed IPv6 (`[2001:db8::1]:443` -> `2001:db8::1`). Custom headers often
 * carry a port; XFF normally does not, but handling both is harmless.
 */
export function normalizeForwardedValue(value: string): string {
  const trimmed = value.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(trimmed);
  if (bracketed) return bracketed[1];
  const v4Port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(trimmed);
  if (v4Port) return v4Port[1];
  return trimmed;
}

/** Normalize a Node socket address ("::ffff:192.0.2.4" -> "192.0.2.4"). */
export function normalizeRemoteAddress(remote: string | null | undefined): string {
  if (!remote) return "unknown";
  return remote.startsWith("::ffff:") ? remote.slice("::ffff:".length) : remote;
}

/** The client address for a request, given the TCP peer and proxy trust. */
export function resolveClientIP(
  headers: IncomingHttpHeaders,
  peer: string,
  trustProxy: boolean,
  trustedHops = 1,
  clientIPHeader: string = DEFAULT_CLIENT_IP_HEADER,
): string {
  if (!trustProxy) return peer;
  const raw = headers[clientIPHeader.toLowerCase()];
  if (typeof raw !== "string" || !raw.trim()) return peer;
  const entries = raw.split(",").map(normalizeForwardedValue).filter(Boolean);
  const hops = Number.isInteger(trustedHops) && trustedHops >= 1 ? trustedHops : 1;
  // The client is `hops` entries from the right; anything further left is
  // client-supplied and ignored. Not enough entries means the chain is shorter
  // than configured, so fall back to the peer rather than trusting the leftmost.
  const index = entries.length - hops;
  if (index < 0) return peer;
  return entries[index] || peer;
}

/** One parsed entry of the trusted-proxy allowlist. */
export interface TrustedProxyEntry {
  family: "ipv4" | "ipv6";
  bytes: number[];
  prefix: number;
}

/**
 * Parse `LG_TRUSTED_PROXY_CIDRS` into exact-IP/CIDR entries. Entries are
 * comma- or whitespace-separated; each may be a bare IP, `ip/prefix`, a
 * bracketed IPv6 (`[::1]/128`), or an IPv4-mapped IPv6 literal. Invalid input
 * throws: a security allowlist must not silently reduce to "trust everyone".
 */
export function parseTrustedProxyCIDRs(input: string | undefined): TrustedProxyEntry[] {
  if (!input || !input.trim()) return [];
  return input
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(parseTrustedProxyEntry);
}

function parseTrustedProxyEntry(raw: string): TrustedProxyEntry {
  const item = raw.trim();
  let value = item;
  let prefixPart: string | undefined;
  const slash = item.lastIndexOf("/");
  if (slash >= 0) {
    value = item.slice(0, slash);
    prefixPart = item.slice(slash + 1);
  }
  value = value.replace(/^\[/, "").replace(/\]$/, "");

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  let family: "ipv4" | "ipv6";
  let bytes: number[] | null;
  if (mapped) {
    family = "ipv4";
    bytes = parseIPv4(mapped[1]);
  } else {
    const v4 = parseIPv4(value);
    if (v4) {
      family = "ipv4";
      bytes = v4;
    } else {
      family = "ipv6";
      bytes = parseIPv6Bytes(value);
    }
  }
  if (!bytes) throw new Error(`invalid trusted proxy address: ${raw}`);

  const maxPrefix = family === "ipv4" ? 32 : 128;
  // Reject an empty or non-decimal prefix: `Number("")` is 0, which would
  // silently turn "10.0.0.0/" into 0.0.0.0/0 (trust everyone).
  if (prefixPart !== undefined && !/^\d{1,3}$/.test(prefixPart)) {
    throw new Error(`invalid trusted proxy prefix: ${raw}`);
  }
  const prefix = prefixPart === undefined ? maxPrefix : Number(prefixPart);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    throw new Error(`invalid trusted proxy prefix: ${raw}`);
  }
  return { family, bytes, prefix };
}

function peerToBytes(peer: string): { family: "ipv4" | "ipv6"; bytes: number[] } | null {
  // Drop an IPv6 zone index (fe80::1%eth0) and IPv4-mapped prefix; the peer
  // address already went through normalizeRemoteAddress upstream.
  const value = normalizeRemoteAddress(peer).split("%")[0];
  const v4 = parseIPv4(value);
  if (v4) return { family: "ipv4", bytes: v4 };
  const v6 = parseIPv6Bytes(value);
  if (v6) return { family: "ipv6", bytes: v6 };
  return null;
}

function prefixMatches(a: number[], b: number[], prefix: number): boolean {
  if (a.length !== b.length) return false;
  const fullBytes = prefix >> 3;
  for (let index = 0; index < fullBytes; index += 1) {
    if (a[index] !== b[index]) return false;
  }
  const remainder = prefix & 7;
  if (remainder === 0) return true;
  const mask = (0xff << (8 - remainder)) & 0xff;
  return (a[fullBytes] & mask) === (b[fullBytes] & mask);
}

/** True when `peer` falls inside any allowlist entry (same family + prefix). */
export function matchesTrustedProxy(entries: TrustedProxyEntry[], peer: string): boolean {
  const target = peerToBytes(peer);
  if (!target) return false;
  return entries.some((entry) => entry.family === target.family && prefixMatches(entry.bytes, target.bytes, entry.prefix));
}

export interface ForwardedHeaderTrustOptions {
  trustProxy: boolean;
  /** True when LG_TRUST_PROXY_HEADER was explicitly configured. */
  clientIPHeaderExplicit: boolean;
  trustedProxyList: TrustedProxyEntry[];
}

/**
 * Whether the forwarded client-IP header may be believed for this peer.
 *
 * - trustProxy off: never (the TCP peer is the client).
 * - LG_TRUST_PROXY_HEADER explicitly set: yes — the operator declared their proxy
 *   setup (e.g. CloudFront/Cloudflare with an origin IP set too large to
 *   enumerate), so source verification is their firewall/network policy's job
 *   and the allowlist is intentionally not applied. A startup warning says so.
 * - Default header + allowlist set: only from a listed peer.
 * - Default header + no allowlist: yes (legacy behavior; startup warns to set
 *   an allowlist or firewall the port).
 */
export function forwardedHeaderTrusted(options: ForwardedHeaderTrustOptions, peer: string): boolean {
  if (!options.trustProxy) return false;
  if (options.clientIPHeaderExplicit) return true;
  if (options.trustedProxyList.length === 0) return true;
  return matchesTrustedProxy(options.trustedProxyList, peer);
}

/**
 * Rewrite the headers the core derives the client IP from, so every consumer
 * (rate limits, token binding, audit, live-session checks, Turnstile) sees
 * the same, non-spoofable address.
 */
export function applyClientIPHeaders(headers: Headers, clientIP: string, sourceHeader = DEFAULT_CLIENT_IP_HEADER): void {
  // Clear every forwarding header we might have consumed, so nothing the client
  // (or a proxy) sent lingers for the core to misread.
  headers.delete("x-forwarded-for");
  headers.delete("x-real-ip");
  if (sourceHeader.toLowerCase() !== "x-forwarded-for") headers.delete(sourceHeader.toLowerCase());
  headers.set("cf-connecting-ip", clientIP);
}

/** The origin request URLs are built against (drives cookies and signing). */
export function requestOrigin(headers: IncomingHttpHeaders, defaultHost: string, options: RequestNetworkOptions): string {
  if (options.publicOrigin) return options.publicOrigin.replace(/\/+$/, "");
  const host = headers.host ?? defaultHost;
  let proto = "http";
  if (options.trustProxy) {
    const forwarded = headers["x-forwarded-proto"];
    // Take the RIGHTMOST value: that is what the closest trusted proxy wrote.
    // The leftmost value is client-supplied and spoofable (a client can send
    // `X-Forwarded-Proto: https` to make the server believe the connection is
    // secure, which would flip cookie Secure and signed-origin behavior).
    const parts = typeof forwarded === "string" ? forwarded.split(",").map((part) => part.trim()).filter(Boolean) : [];
    const last = parts[parts.length - 1];
    if (last === "https" || last === "http") proto = last;
  }
  return `${proto}://${host}`;
}
