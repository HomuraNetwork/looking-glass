import type { Env } from "./config";
import { parseIPv4, parseIPv6Bytes } from "./ip-guard";
import { getRuntimeJWK } from "./runtime-secrets";
import { base64URLToBytes, kidFromJWK, signCompact } from "./signing";

/** Live terminal session token TTL: one verification covers 30 minutes. */
export const LIVE_SESSION_TTL_SECONDS = 1800;

export interface LiveSessionClaims {
  typ: string;
  kid: string;
  node: string;
  ip: string;
  ip_binding: string;
  exp: number;
  iat?: number;
  nonce?: string;
}

export type LiveSessionVerifyError = "malformed_token" | "bad_signature" | "bad_claims" | "node_mismatch" | "ip_mismatch";

export async function signLiveSessionToken(input: { node: string; clientIP: string; env: Pick<Env, "DB"> }): Promise<{ token: string; exp: number }> {
  const now = Math.floor(Date.now() / 1000);
  const jwk = await getRuntimeJWK(input.env.DB, "LG_TOKEN_SIGN_JWK");
  const token = await signCompact(
    {
      typ: "live",
      kid: await kidFromJWK(jwk),
      node: input.node,
      ip: input.clientIP,
      ip_binding: "relaxed",
      exp: now + LIVE_SESSION_TTL_SECONDS,
      iat: now,
      nonce: crypto.randomUUID().replaceAll("-", ""),
    },
    jwk,
  );
  return { token, exp: now + LIVE_SESSION_TTL_SECONDS };
}

/**
 * Verifies a browser live-session token with the same Ed25519 key used for job
 * tokens. `relaxed` binding matches on an IPv4 /24 or IPv6 /48 prefix, mirroring
 * the agent's ipAllowed policy (agent/internal/token/verify.go) so a mobile
 * client whose address rotates inside its ISP prefix keeps its session.
 */
export async function verifyLiveSessionToken(input: {
  token: string;
  env: Pick<Env, "DB">;
  expectedNodeID: string;
  clientIP: string;
}): Promise<{ claims: LiveSessionClaims } | { error: LiveSessionVerifyError }> {
  const [payloadPart, signaturePart] = input.token.split(".");
  if (!payloadPart || !signaturePart) return { error: "malformed_token" };
  let payload: Uint8Array;
  let signature: Uint8Array;
  try {
    payload = base64URLToBytes(payloadPart);
    signature = base64URLToBytes(signaturePart);
  } catch {
    return { error: "malformed_token" };
  }
  const jwk = await getRuntimeJWK(input.env.DB, "LG_TOKEN_SIGN_JWK");
  const verifyKey = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    { name: "Ed25519" } as AlgorithmIdentifier,
    false,
    ["verify"],
  );
  let ok: boolean;
  try {
    ok = await crypto.subtle.verify(
      { name: "Ed25519" } as AlgorithmIdentifier,
      verifyKey,
      signature as unknown as BufferSource,
      payload as unknown as BufferSource,
    );
  } catch {
    return { error: "bad_signature" };
  }
  if (!ok) return { error: "bad_signature" };

  let claims: LiveSessionClaims;
  try {
    claims = JSON.parse(new TextDecoder().decode(payload)) as LiveSessionClaims;
  } catch {
    return { error: "malformed_token" };
  }
  const now = Math.floor(Date.now() / 1000);
  if (claims.typ !== "live" || typeof claims.exp !== "number" || claims.exp <= now) {
    return { error: "bad_claims" };
  }
  if (typeof claims.node !== "string" || claims.node !== input.expectedNodeID) {
    return { error: "node_mismatch" };
  }
  if (claims.ip_binding !== "relaxed" || typeof claims.ip !== "string" || !relaxedIPMatch(claims.ip, input.clientIP)) {
    return { error: "ip_mismatch" };
  }
  return { claims };
}

/** Relaxed binding: same /24 (IPv4) or /48 (IPv6) prefix, mirroring the agent. */
export function relaxedIPMatch(tokenIP: string, clientIP: string): boolean {
  if (!tokenIP || !clientIP) return false;
  const tokenBytes = ipBytes(tokenIP);
  const clientBytes = ipBytes(clientIP);
  if (!tokenBytes || !clientBytes) return false;
  if (tokenBytes.length !== clientBytes.length) return false;
  const prefix = tokenBytes.length === 4 ? 24 : 48;
  return prefixBytes(tokenBytes, prefix).join(".") === prefixBytes(clientBytes, prefix).join(".");
}

function prefixBytes(bytes: number[], bits: number): number[] {
  const fullBytes = Math.floor(bits / 8);
  const remainderBits = bits % 8;
  const prefix = bytes.slice(0, fullBytes);
  if (remainderBits > 0) {
    const mask = (0xff << (8 - remainderBits)) & 0xff;
    prefix.push(bytes[fullBytes] & mask);
  }
  return prefix;
}

function ipBytes(value: string): number[] | null {
  const trimmed = value.trim();
  const ipv4 = parseIPv4(trimmed);
  if (ipv4) return ipv4;
  const ipv6 = parseIPv6Bytes(trimmed);
  if (ipv6) return ipv6;
  // IPv4-mapped dotted form (::ffff:203.0.113.7): treat it as its IPv4 bytes so
  // tokens minted before Cloudflare normalizes the header keep working.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(trimmed);
  if (mapped) return parseIPv4(mapped[1]);
  return null;
}