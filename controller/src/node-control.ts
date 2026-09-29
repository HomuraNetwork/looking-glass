import { Env } from "./config";
import { autoAdvanceCertificateIssuance } from "./acme";
import { recordDownloadUse } from "./audit";
import { validateP256PublicKeyBase64URL } from "./certificate-encryption";
import { syncManagedCertificateToNode } from "./certificates";
import { getAdminNode } from "./db";
import { buildSignedConfig } from "./enroll";
import { json, methodNotAllowed, readJSON } from "./http";
import { workerError, workerWarn } from "./log";
import { bearerToken, consumeNodeInitToken, issueNodeToken, validateNodeInitToken, validateNodeToken } from "./node-tokens";
import { syncNodePublicIPs } from "./node-ip";
import { recordNodeEvent } from "./node-events";
import { validateEd25519PublicKeyBase64URL } from "./signing";
import type { AppRuntime } from "./app";

interface NodeBootstrapRequest {
  agent_public_key?: string;
  agent_encryption_public_key?: string;
  version?: string;
  build_id?: string;
  capabilities?: string[];
  detected_ipv4?: string;
  detected_ipv6?: string;
}

export async function handleNodeControlConfig(request: Request, env: Env, runtime?: AppRuntime): Promise<Response> {
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  if (request.method === "POST") return bootstrapNodeConfig(request, env);
  if (request.method === "GET") return pullNodeConfig(request, env, runtime);
  return methodNotAllowed();
}

export async function handleNodeControlKeyset(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const auth = await authorizedNode(request, env);
  if (!auth) return json({ error: "invalid_node_token" }, { status: 401 });
  const config = await buildSignedConfig(env, auth.nodeID);
  return json({ keyset: config.keyset });
}

export async function handleNodeControlSync(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const auth = await authorizedNode(request, env);
  if (!auth) return json({ error: "invalid_node_token" }, { status: 401 });
  const body = await readJSON<{ type?: string; link_id?: string; size?: string }>(request);
  if (body.type !== "download_used") return json({ error: "invalid_sync_type" }, { status: 400 });
  const linkID = body.link_id?.trim() || "";
  const size = body.size?.trim() || "";
  if (!linkID || !size) return json({ error: "download_usage_required" }, { status: 400 });
  const recorded = await recordDownloadUse(env.DB, { id: linkID, node: auth.nodeID, size });
  if (!recorded) return json({ error: "download_link_not_found" }, { status: 404 });
  return json({ ok: true, usage_count: recorded.usage_count });
}

async function bootstrapNodeConfig(request: Request, env: Env): Promise<Response> {
  const db = env.DB!;
  const body = await readJSON<NodeBootstrapRequest>(request);
  if (!(await validateEd25519PublicKeyBase64URL(body.agent_public_key || ""))) {
    return json({ error: "invalid_agent_public_key" }, { status: 400 });
  }
  if (!(await validateP256PublicKeyBase64URL(body.agent_encryption_public_key || ""))) {
    return json({ error: "invalid_agent_encryption_public_key" }, { status: 400 });
  }
  const bearer = bearerToken(request);
  const init = await validateNodeInitToken(db, bearer);
  if (!init) return json({ error: "invalid_init_token" }, { status: 401 });
  const node = await getAdminNode(db, init.nodeID);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  // Claim the one-time credential before changing keys or issuing any token.
  // The conditional UPDATE is atomic in D1, so concurrent bootstrap requests
  // cannot both pass validation and overwrite the node identity.
  const consumed = await consumeNodeInitToken(db, bearer);
  if (!consumed) return json({ error: "init_token_consumed" }, { status: 409 });
  try {
    await db.batch([
      db.prepare("UPDATE node_tokens SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL")
        .bind(Math.floor(Date.now() / 1000), consumed.nodeID),
      db.prepare(
      `UPDATE nodes
       SET agent_public_key = ?,
           agent_encryption_public_key = ?,
           version = ?,
           build_id = ?,
           capabilities = ?,
           config_version = config_version + 1,
           updated_at = ?
       WHERE id = ?`,
      ).bind(
        body.agent_public_key,
        body.agent_encryption_public_key,
        body.version || null,
        body.build_id || null,
        JSON.stringify(Array.isArray(body.capabilities) ? body.capabilities : []),
        Math.floor(Date.now() / 1000),
        consumed.nodeID,
      ),
    ]);
    await syncNodePublicIPs(env, consumed.nodeID, {
      publicIPv4: body.detected_ipv4,
      publicIPv6: body.detected_ipv6,
    });
    const certSync = await syncManagedCertificateToNode(env, consumed.nodeID);
    const config = await buildSignedConfig(env, consumed.nodeID);
    // Keep long-lived credential issuance as the final fallible operation so
    // a failed certificate/config step cannot strand an active node token.
    const nodeToken = await issueNodeToken(db, consumed.nodeID);
    return json({
      status: "active",
      node_id: consumed.nodeID,
      node_token: nodeToken,
      config,
      cert_sync: certSync,
    });
  } catch (error) {
    // The init credential was intentionally consumed before identity changes;
    // never retry it and risk overwriting a successful concurrent bootstrap.
    // Tell the operator to issue a fresh credential for a deliberate retry.
    workerError("node.bootstrap_failed_after_init_claim", { node: consumed.nodeID, error: error instanceof Error ? error.message : String(error) });
    return json({ error: "bootstrap_failed_new_init_required" }, { status: 503 });
  }
}

async function pullNodeConfig(request: Request, env: Env, runtime?: AppRuntime): Promise<Response> {
  const auth = await authorizedNode(request, env);
  if (!auth) return json({ error: "invalid_node_token" }, { status: 401 });
  const url = new URL(request.url);
  await recordHeartbeat(env, auth.nodeID, url);
  await syncNodePublicIPs(env, auth.nodeID, {
    publicIPv4: url.searchParams.get("detected_ipv4") || undefined,
    publicIPv6: url.searchParams.get("detected_ipv6") || undefined,
  });
  // A node that pulls config without a valid certificate should get one without
  // waiting for the next cron pass. Issuance is staged (begin, then finalize
  // after DNS-01 propagation), so this advances one step per pull. Runs in the
  // background so the (bounded) ACME work never delays the config response.
  scheduleCertificateAdvance(env, runtime);
  return json(await buildSignedConfig(env, auth.nodeID));
}

/**
 * Kick off one certificate-issuance step after the pull response, if the
 * runtime supports background work. Best-effort: failures are logged, never
 * surfaced to the agent.
 */
function scheduleCertificateAdvance(env: Env, runtime?: AppRuntime): void {
  if (!runtime?.waitUntil) return;
  runtime.waitUntil(
    autoAdvanceCertificateIssuance(env).catch((error) => {
      workerWarn("cert.auto_issue_error", { error: error instanceof Error ? error.message : "auto_issue_failed" });
    }),
  );
}

/**
 * A config pull doubles as the node heartbeat: record last_seen_at (a single
 * row update, no history) and, when the agent reports a start marker, an
 * agent_started edge event. The worker never needs to reach an unauthenticated
 * node to learn this.
 *
 * The agent also reports the config bundle version it is currently serving
 * (the same "what I applied" signal used for certificates), so an admin can
 * tell whether a node has picked up its latest config: compare
 * config_applied_version against config_version.
 */
async function recordHeartbeat(env: Env, nodeID: string, url: URL): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await env.DB!.prepare("UPDATE nodes SET last_seen_at = ? WHERE id = ?").bind(now, nodeID).run();
  // The reported build identity lets the controller flag a node whose build
  // is older than the one it now distributes. Only overwrite when reported, so
  // an older agent that does not send it keeps its last known value.
  const buildTime = url.searchParams.get("build_id") || "";
  const version = url.searchParams.get("version") || "";
  if (buildTime || version) {
    await env.DB!.prepare(
      "UPDATE nodes SET build_id = COALESCE(?, build_id), version = COALESCE(?, version) WHERE id = ?",
    )
      .bind(buildTime || null, version || null, nodeID)
      .run();
  }
  const appliedConfig = Number(url.searchParams.get("config_version") || "");
  if (Number.isFinite(appliedConfig) && appliedConfig > 0) {
    await env.DB!.prepare("UPDATE nodes SET config_applied_version = ? WHERE id = ? AND (config_applied_version IS NULL OR config_applied_version < ?)")
      .bind(appliedConfig, nodeID, appliedConfig)
      .run();
  }
  if (url.searchParams.get("started") === "1") {
    await recordNodeEvent(env.DB, { nodeID, type: "agent_started", info: version, now });
  }
}

async function authorizedNode(request: Request, env: Env): Promise<{ nodeID: string } | null> {
  const token = bearerToken(request);
  const auth = await validateNodeToken(env.DB, token);
  if (!auth) return null;
  const requestedNode = new URL(request.url).searchParams.get("node");
  if (requestedNode && requestedNode !== auth.nodeID) {
    const node = await getAdminNode(env.DB, requestedNode);
    if (node?.internal_id !== auth.nodeID) return null;
  }
  return auth;
}
