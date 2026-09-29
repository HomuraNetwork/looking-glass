import { Env } from "./config";
import { validateP256PublicKeyBase64URL } from "./certificate-encryption";
import { ensureDefaultNodeProfile } from "./db-bootstrap";
import { getAdminNode } from "./db";
import { json, readJSON } from "./http";
import { syncNodePublicIPs } from "./node-ip";
import { getRuntimeJWK } from "./runtime-secrets";
import { kidFromJWK, publicKeyFromJWK, sha256Hex, signCompact, validateEd25519PublicKeyBase64URL } from "./signing";
import type { SqlDatabase } from "./runtime";

interface EnrollRequest {
  enroll_token: string;
  agent_public_key: string;
  agent_encryption_public_key: string;
  detected_ipv4?: string;
  detected_ipv6?: string;
  version: string;
  build_id?: string;
  capabilities: string[];
}

interface EnrollTokenRow {
  id: string;
  node_id: string | null;
  profile_id: string | null;
  auto_approve: number;
  max_uses: number;
  used_count: number;
  expires_at: number | null;
  revoked_at: number | null;
}

export async function handleEnroll(request: Request, env: Env): Promise<Response> {
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<EnrollRequest>(request);
  if (!(await validateEd25519PublicKeyBase64URL(body.agent_public_key))) {
    return json({ error: "invalid_agent_public_key" }, { status: 400 });
  }
  if (!(await validateP256PublicKeyBase64URL(body.agent_encryption_public_key))) {
    return json({ error: "invalid_agent_encryption_public_key" }, { status: 400 });
  }
  const token = await consumeEnrollToken(env, body.enroll_token);
  if (!token || !token.node_id) return json({ error: "invalid_enroll_token" }, { status: 401 });
  const node = await getAdminNode(env.DB, token.node_id);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const internalNodeID = node.internal_id;

  const now = Math.floor(Date.now() / 1000);
  const updated = await env.DB.prepare(
    `UPDATE nodes
     SET agent_public_key = ?,
         agent_encryption_public_key = ?,
         version = ?,
         build_id = ?,
         capabilities = ?,
         profile_id = COALESCE(?, profile_id),
         config_version = config_version + 1,
         updated_at = ?
     WHERE id = ?
       AND (agent_public_key IS NULL OR agent_public_key = ?)
       AND (agent_encryption_public_key IS NULL OR agent_encryption_public_key = ?)`,
  ).bind(
      body.agent_public_key,
      body.agent_encryption_public_key,
      body.version,
      body.build_id || null,
      JSON.stringify(body.capabilities),
      token.profile_id,
      now,
      internalNodeID,
      body.agent_public_key,
      body.agent_encryption_public_key,
  ).run();
  if ((updated.meta?.changes ?? 0) === 0) {
    return json({ error: "node_identity_change_requires_rekey" }, { status: 409 });
  }

  await syncNodePublicIPs(env, internalNodeID, {
    publicIPv4: body.detected_ipv4,
    publicIPv6: body.detected_ipv6,
  });

  if (token.auto_approve !== 1) {
    return json({ status: "pending", node_id: internalNodeID });
  }
  const config = await buildSignedConfig(env, internalNodeID);
  return json({ status: "active", node_id: internalNodeID, config });
}

async function consumeEnrollToken(env: Env, raw: string): Promise<EnrollTokenRow | null> {
  if (!env.DB) return null;
  const hash = await sha256Hex(raw);
  return env.DB
    .prepare(
      `UPDATE enroll_tokens
       SET used_count = used_count + 1
       WHERE token_hash = ?
         AND node_id IS NOT NULL
         AND revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?)
         AND used_count < max_uses
       RETURNING id, node_id, profile_id, auto_approve, max_uses, used_count, expires_at, revoked_at`,
    )
    .bind(hash, Math.floor(Date.now() / 1000))
    .first<EnrollTokenRow>();
}

export async function buildSignedConfig(env: Env, nodeID: string): Promise<Record<string, unknown>> {
  if (!env.DB) throw new Error("d1_required");
  const now = Math.floor(Date.now() / 1000);
  const tokenJwk = await getRuntimeJWK(env.DB, "LG_TOKEN_SIGN_JWK");
  const configJwk = await getRuntimeJWK(env.DB, "LG_CONFIG_SIGN_JWK");
  const adminJwk = await getRuntimeJWK(env.DB, "LG_ADMIN_SIGN_JWK");
  const [tokenKid, configKid, adminKid] = await Promise.all([kidFromJWK(tokenJwk), kidFromJWK(configJwk), kidFromJWK(adminJwk)]);
  const node = await getAdminNode(env.DB, nodeID);
  if (!node) throw new Error("node_not_found");
  const internalNodeID = node.internal_id;
  const limits = await configLimitsForNode(env.DB, node.profile_id || "default");
  const features = featureFlags(node.features);
  const payload: Record<string, unknown> = {
    version: node.config_version,
    node_id: internalNodeID,
    domain: node.domain,
  };
  addIfPresent(payload, "public_ipv4", node.public_ipv4);
  addIfPresent(payload, "public_ipv6", node.public_ipv6);
  if (node.dynamic_ip) payload.dynamic_ip = true;
  payload.issued_at = now;
  payload.expires_at = now + 86400;
  payload.features = features;
  payload.limits = bundleLimits(limits);
  payload.config_kid = configKid;
  payload.keyset = [
    { kid: adminKid, alg: "Ed25519", use: "admin_verify", public_key: publicKeyFromJWK(adminJwk) },
    { kid: configKid, alg: "Ed25519", use: "config_verify", public_key: publicKeyFromJWK(configJwk) },
    { kid: tokenKid, alg: "Ed25519", use: "token_verify", public_key: publicKeyFromJWK(tokenJwk) },
  ];
  payload.signature = "";
  const signed = await signCompact(payload, configJwk);
  return { ...payload, signature: signed.split(".")[1] };
}

function featureFlags(features: string[] | undefined): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const feature of [...(features ?? [])].sort()) out[feature] = true;
  return out;
}

function bundleLimits(limits: Record<string, unknown>): Record<string, unknown> {
  return {
    download_concurrency: numberLimit(limits, "download_concurrency"),
    download_max_requests_per_token: numberLimit(limits, "download_max_requests_per_token"),
    download_max_bytes_multiplier: numberLimit(limits, "download_max_bytes_multiplier"),
    iperf_active_sessions: numberLimit(limits, "iperf_active_sessions"),
    job_concurrency_per_ip: numberLimit(limits, "job_concurrency_per_ip"),
    job_timeout_sec: numberLimit(limits, "job_timeout_sec"),
    job_max_output_bytes: numberLimit(limits, "job_max_output_bytes"),
    allowed_download_sizes: Array.isArray(limits.allowed_download_sizes) ? limits.allowed_download_sizes : null,
    iperf_port_min: numberLimit(limits, "iperf_port_min"),
    iperf_port_max: numberLimit(limits, "iperf_port_max"),
    iperf_ttl_seconds: numberLimit(limits, "iperf_ttl_seconds"),
    iperf_max_duration: numberLimit(limits, "iperf_max_duration"),
    iperf_max_parallel: numberLimit(limits, "iperf_max_parallel"),
    iperf_max_runs: numberLimit(limits, "iperf_max_runs"),
    iperf_run_budget: numberLimit(limits, "iperf_run_budget"),
    token_ipv4_prefix: numberLimit(limits, "token_ipv4_prefix"),
    token_ipv6_prefix: numberLimit(limits, "token_ipv6_prefix"),
    allowed_control_ttl: numberLimit(limits, "allowed_control_ttl"),
    ...optionalBooleanLimit(limits, "guard_private_ip"),
  };
}

function numberLimit(limits: Record<string, unknown>, key: string): number {
  const value = limits[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

// guard_private_ip is a tri-state on the agent (*bool with omitempty): only
// an explicit boolean is emitted so an unset profile keeps the agent's
// fail-safe default (guard on). 0 (falsy) would read as "disabled".
function optionalBooleanLimit(limits: Record<string, unknown>, key: string): Record<string, boolean> {
  const value = limits[key];
  return typeof value === "boolean" ? { [key]: value } : {};
}

async function configLimitsForNode(db: SqlDatabase, profileID: string): Promise<Record<string, unknown>> {
  let row = await db.prepare("SELECT config_json FROM node_profiles WHERE id = ?").bind(profileID).first<{ config_json: string }>();
  if (!row?.config_json && profileID !== "default") {
    row = await db.prepare("SELECT config_json FROM node_profiles WHERE id = ?").bind("default").first<{ config_json: string }>();
  }
  if (!row?.config_json) {
    await ensureDefaultNodeProfile(db);
    row = await db.prepare("SELECT config_json FROM node_profiles WHERE id = ?").bind("default").first<{ config_json: string }>();
  }
  if (!row?.config_json) throw new Error("node_profile_not_found");
  let profile: Record<string, unknown>;
  try {
    const parsed = JSON.parse(row.config_json) as unknown;
    profile = isRecord(parsed) ? parsed : {};
  } catch {
    throw new Error("node_profile_invalid");
  }
  if (isRecord(profile.limits)) return profile.limits;
  const limits = pickLimitKeys(profile);
  if (Object.keys(limits).length === 0) throw new Error("node_profile_limits_required");
  return limits;
}

const limitKeys = new Set([
  "download_concurrency",
  "download_max_requests_per_token",
  "download_max_bytes_multiplier",
  "iperf_active_sessions",
  "job_concurrency_per_ip",
  "job_timeout_sec",
  "job_max_output_bytes",
  "guard_private_ip",
  "allowed_download_sizes",
  "iperf_port_min",
  "iperf_port_max",
  "iperf_ttl_seconds",
  "iperf_max_duration",
  "iperf_max_parallel",
  "iperf_max_runs",
  "iperf_run_budget",
  "token_ipv4_prefix",
  "token_ipv6_prefix",
  "allowed_control_ttl",
]);

function pickLimitKeys(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (limitKeys.has(key)) out[key] = value;
  }
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function addIfPresent(target: Record<string, unknown>, key: string, value: unknown): void {
  if (typeof value !== "string") return;
  const normalized = value.trim();
  if (normalized) target[key] = normalized;
}
