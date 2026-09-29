import type { Env } from "./config";
import { bytesToBase64URL, signBytes } from "./signing";
import { getRuntimeJWK } from "./runtime-secrets";

/**
 * Agent release descriptors.
 *
 * `hlg-agent update` runs on the node, not here: the controller only tells the
 * agent what the current build is and hands it a *signed* descriptor. The agent
 * verifies the descriptor against the `config_verify` key it already has from
 * its signed config bundle before downloading or replacing anything, so a
 * tampered response (or a stale one) cannot install an arbitrary binary.
 *
 * The signed payload is a newline-joined canonical string rather than JSON, so
 * the worker and agent do not have to agree on JSON key order to verify it.
 */

export const AGENT_RELEASE_ARCHES = ["amd64", "arm64"] as const;
export type AgentReleaseArch = (typeof AGENT_RELEASE_ARCHES)[number];

export interface AgentReleaseTarget {
  sha256: string;
  size: number;
}

export interface AgentReleaseManifest {
  build_id: string | null;
  targets: Record<string, AgentReleaseTarget>;
}

/**
 * Read the distributed agent manifest (written at build time alongside the
 * binaries). Best-effort: a read failure means "no release available", which
 * callers surface as a 503 rather than silently returning a partial descriptor.
 */
export async function agentReleaseManifest(env: Env, origin: string): Promise<AgentReleaseManifest> {
  const empty: AgentReleaseManifest = { build_id: null, targets: {} };
  if (!env.ASSETS) return empty;
  try {
    const assetURL = new URL("/_agent/manifest.json", origin);
    const response = await env.ASSETS.fetch(new Request(assetURL));
    if (!response.ok) return empty;
    return parseAgentManifest(await response.json());
  } catch {
    return empty;
  }
}

/** Parse a manifest document, tolerating the older string-only `targets` list. */
export function parseAgentManifest(value: unknown): AgentReleaseManifest {
  const manifest: AgentReleaseManifest = { build_id: null, targets: {} };
  if (!value || typeof value !== "object") return manifest;
  const raw = value as { build_id?: unknown; targets?: unknown };
  if (typeof raw.build_id === "string" && raw.build_id) manifest.build_id = raw.build_id;
  if (Array.isArray(raw.targets)) {
    for (const entry of raw.targets) {
      if (!entry || typeof entry !== "object") continue;
      const item = entry as { name?: unknown; sha256?: unknown; size_bytes?: unknown };
      if (typeof item.name !== "string" || typeof item.sha256 !== "string" || typeof item.size_bytes !== "number") continue;
      manifest.targets[item.name] = { sha256: item.sha256, size: item.size_bytes };
    }
  }
  return manifest;
}

export interface AgentReleaseDescriptor {
  build_id: string;
  target: string;
  sha256: string;
  size: number;
  path: string;
  node_id: string;
  expires_at: number;
}

/** How long a descriptor stays valid; the agent also allows a small clock skew. */
export const AGENT_RELEASE_TTL_SECONDS = 900;

/**
 * The exact bytes covered by the release signature. Must stay byte-identical to
 * the agent's `agentupdate.SigningInput`.
 */
export function agentReleaseSigningInput(descriptor: AgentReleaseDescriptor): string {
  return [
    "hlg-agent-release",
    descriptor.build_id,
    descriptor.target,
    descriptor.sha256,
    String(descriptor.size),
    descriptor.path,
    descriptor.node_id,
    String(descriptor.expires_at),
  ].join("\n");
}

/** Sign a release descriptor with the controller's config signing key. */
export async function signAgentRelease(jwk: JsonWebKey, descriptor: AgentReleaseDescriptor): Promise<string> {
  const signature = await signBytes(new TextEncoder().encode(agentReleaseSigningInput(descriptor)), jwk);
  return bytesToBase64URL(signature);
}

/** Fetch the config signing key, used to sign and identify release descriptors. */
export function agentReleaseSigningKey(env: Env): Promise<JsonWebKey> {
  return getRuntimeJWK(env.DB, "LG_CONFIG_SIGN_JWK");
}
