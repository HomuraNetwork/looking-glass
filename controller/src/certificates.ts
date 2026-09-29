import { Env } from "./config";
import { requireAdmin } from "./admin-auth";
import { encryptForP256PublicKey, p256KeyID } from "./certificate-encryption";
import { getAdminNode, listAdminNodes } from "./db";
import { json, methodNotAllowed, readJSON } from "./http";
import { workerWarn } from "./log";
import { recordNodeEvent } from "./node-events";
import { bearerToken, validateNodeToken } from "./node-tokens";
import { getRuntimeJWK } from "./runtime-secrets";
import { kidFromJWK, signCompact } from "./signing";
import type { SqlDatabase } from "./runtime";

interface AdminNodeCertificateRequest {
  node_id?: string;
  cert_pem?: string;
  key_pem?: string;
  ca_pem?: string;
  cert_expires_at?: number;
  domains?: string[];
}

export interface AdminManagedCertificateImportRequest {
  cert_pem?: string;
  key_pem?: string;
  ca_pem?: string;
  cert_expires_at?: number;
  domains?: string[];
}

export interface SignedCertificateBundle {
  version: number;
  node_id: string;
  domain: string;
  issued_at: number;
  cert_expires_at: number;
  cert_pem: string;
  key_pem: string;
  ca_pem: string;
  config_kid: string;
  signature: string;
}

interface NodeCertificateBundleRow {
  id: string;
  bundle_id: string;
  encrypted_payload: string;
}

export interface AdminNodeCertificateState {
  domains: string[];
  cert_expires_at: number;
  status: string;
  synced_at: number | null;
}

/**
 * Per-node certificate state for the admin node list: the newest published
 * bundle covering each node, or no entry when none does (the node is on its
 * self-signed fallback). Batched to avoid an N+1 query.
 */
export async function nodeCertificateStates(
  db: SqlDatabase,
  nodeIDs: string[],
): Promise<Map<string, AdminNodeCertificateState>> {
  const states = new Map<string, AdminNodeCertificateState>();
  const unique = [...new Set(nodeIDs)].filter(Boolean);
  if (unique.length === 0) return states;
  // D1 caps bound parameters at 100; leave none spare for this query.
  for (let offset = 0; offset < unique.length; offset += 100) {
    const batch = unique.slice(offset, offset + 100);
    const placeholders = batch.map(() => "?").join(",");
    const rows = await db
      .prepare(
        `SELECT ncb.node_id AS node_id, cb.domains_json AS domains_json,
                cb.cert_expires_at AS cert_expires_at, ncb.status AS status, ncb.synced_at AS synced_at
         FROM node_certificate_bundles ncb
         JOIN certificate_bundles cb ON cb.id = ncb.bundle_id
         WHERE ncb.node_id IN (${placeholders})
         ORDER BY ncb.created_at ASC`,
      )
      .bind(...batch)
      .all<{ node_id: string; domains_json: string; cert_expires_at: number; status: string; synced_at: number | null }>();
    // Ascending order means a later row overwrites an earlier one, leaving the
    // newest bundle per node.
    for (const row of rows.results ?? []) {
      states.set(row.node_id, {
        domains: parseDomainsJSON(row.domains_json, ""),
        cert_expires_at: row.cert_expires_at,
        status: row.status,
        synced_at: row.synced_at,
      });
    }
  }
  return states;
}

export interface AdminManagedCertificate {
  bundle_id: string;
  domain: string;
  version: number;
  cert_expires_at: number;
  created_at: number;
  fingerprint_sha256: string;
  domains: string[];
  cert_pem: string;
  ca_pem: string;
  sync_status: string;
  synced_at: number | null;
  nodes: Array<{
    node_id: string;
    status: string;
    synced_at: number | null;
  }>;
}

export async function handleAdminNodeCertificate(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });

  const body = await readJSON<AdminNodeCertificateRequest>(request);
  const nodeID = body.node_id?.trim() || "";
  const node = await getAdminNode(env.DB, nodeID);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });

  const certPEM = normalizePEM(body.cert_pem || "", "CERTIFICATE");
  const keyPEM = normalizePrivateKey(body.key_pem || "");
  const caPEM = body.ca_pem?.trim() ? normalizePEM(body.ca_pem, "CERTIFICATE") : "";
  const now = nowSeconds();
  const certExpiresAt = Number(body.cert_expires_at || 0);
  if (!certPEM || !keyPEM) return json({ error: "certificate_pem_required" }, { status: 400 });
  if (!Number.isFinite(certExpiresAt) || certExpiresAt <= now + 3600) {
    return json({ error: "certificate_expiry_required" }, { status: 400 });
  }

  let stored: Awaited<ReturnType<typeof storeNodeCertificateBundle>>;
  try {
    stored = await storeNodeCertificateBundle(env, node, {
      certPEM,
      keyPEM,
      caPEM,
      certExpiresAt,
      domains: normalizeDomains(body.domains, node.domain),
    });
  } catch (error) {
    if (error instanceof Error && error.message === "node_encryption_key_required") {
      return json({ error: "node_encryption_key_required" }, { status: 409 });
    }
    throw error;
  }
  return json({ bundle: stored });
}

export async function storeNodeCertificateBundle(
  env: Env,
  node: { id: string; internal_id?: string; domain: string },
  input: { certPEM: string; keyPEM: string; caPEM: string; certExpiresAt: number; domains?: string[] },
): Promise<{ id: string; node_bundle_id: string; node_id: string; domain: string; version: number; cert_expires_at: number; created_at: number }> {
  if (!env.DB) throw new Error("d1_required");
  const target = await certificateTarget(env.DB, node.internal_id ?? node.id);
  if (!target?.agent_encryption_public_key) throw new Error("node_encryption_key_required");
  const now = nowSeconds();
  const domains = normalizeDomains(input.domains, target.domain);
  const bundleID = await storeManagedCertificateBundle(env, {
    certPEM: input.certPEM,
    keyPEM: input.keyPEM,
    caPEM: input.caPEM,
    certExpiresAt: input.certExpiresAt,
    domains,
  });
  const nodeBundle = await storeCertificateBundleForNode(env, target, {
    id: bundleID,
    cert_pem: input.certPEM,
    key_pem: input.keyPEM,
    ca_pem: input.caPEM,
    cert_expires_at: input.certExpiresAt,
  });

  return {
    id: bundleID,
    node_bundle_id: nodeBundle.node_bundle_id,
    node_id: target.id,
    domain: target.domain,
    version: now,
    cert_expires_at: input.certExpiresAt,
    created_at: now,
  };
}

export async function storeManagedCertificateBundle(
  env: Env,
  input: { certPEM: string; keyPEM: string; caPEM: string; certExpiresAt: number; domains: string[] },
): Promise<string> {
  if (!env.DB) throw new Error("d1_required");
  const now = nowSeconds();
  const domains = normalizeDomains(input.domains, "managed");
  const bundleDomain = certificateBundleDomain(domains);
  const fingerprint = await certificateFingerprintSHA256(input.certPEM);
  const existing = await env.DB.prepare(
    `SELECT id
     FROM certificate_bundles
     WHERE active = 1
       AND fingerprint_sha256 = ?
       AND domains_json = ?
       AND cert_expires_at = ?
     ORDER BY created_at DESC
     LIMIT 1`,
  )
    .bind(fingerprint, JSON.stringify(domains), input.certExpiresAt)
    .first<{ id: string }>();
  if (existing?.id) return existing.id;

  const bundleID = `cb_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  // Deactivate the previous active bundle and insert the new one as a single
  // atomic batch so concurrent imports can never leave two active bundles.
  await env.DB.batch([
    env.DB.prepare("UPDATE certificate_bundles SET active = 0 WHERE domain = ?").bind(bundleDomain),
    env.DB.prepare(
      `INSERT INTO certificate_bundles (
        id, domain, version, domains_json, fingerprint_sha256, cert_pem, key_pem, ca_pem,
        cert_expires_at, created_at, active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
    ).bind(
      bundleID,
      bundleDomain,
      now,
      JSON.stringify(domains),
      fingerprint,
      input.certPEM,
      input.keyPEM,
      input.caPEM,
      input.certExpiresAt,
      now,
    ),
  ]);
  return bundleID;
}

export async function importManagedCertificateBundles(
  env: Env,
  input: AdminManagedCertificateImportRequest,
  fallbackDomains: string[],
): Promise<{ status: "imported" | "skipped"; domains?: string[]; nodes?: number; skipped?: number; reason?: string }> {
  if (!env.DB) throw new Error("d1_required");
  const certPEM = normalizePEM(input.cert_pem || "", "CERTIFICATE");
  const keyPEM = normalizePrivateKey(input.key_pem || "");
  const caPEM = input.ca_pem?.trim() ? normalizePEM(input.ca_pem, "CERTIFICATE") : "";
  const now = nowSeconds();
  const certExpiresAt = Number(input.cert_expires_at || 0);
  if (!certPEM || !keyPEM) throw new Error("certificate_pem_required");
  if (!Number.isFinite(certExpiresAt) || certExpiresAt <= now + 3600) throw new Error("certificate_expiry_required");

  const nodes = (await listAdminNodes(env.DB)).filter((node) => node.enabled && !node.hidden);
  if (nodes.length === 0) return { status: "skipped", reason: "no_nodes" };
  const domains = normalizeImportDomains(input.domains, fallbackDomains.length > 0 ? fallbackDomains : nodes.map((node) => node.domain));
  if (domains.length === 0) throw new Error("certificate_domains_required");
  const bundleID = await storeManagedCertificateBundle(env, {
    certPEM,
    keyPEM,
    caPEM,
    certExpiresAt,
    domains,
  });

  let stored = 0;
  let skipped = 0;
  for (const node of nodes) {
    try {
      const target = await certificateTarget(env.DB, node.internal_id ?? node.id);
      if (!target?.agent_encryption_public_key) {
        skipped += 1;
        continue;
      }
      await storeCertificateBundleForNode(env, target, {
        id: bundleID,
        cert_pem: certPEM,
        key_pem: keyPEM,
        ca_pem: caPEM,
        cert_expires_at: certExpiresAt,
      });
      stored += 1;
    } catch (error) {
      if (error instanceof Error && error.message === "node_encryption_key_required") {
        skipped += 1;
        continue;
      }
      throw error;
    }
  }
  return { status: "imported", domains, nodes: stored, skipped };
}

export async function listAdminManagedCertificates(db: SqlDatabase): Promise<AdminManagedCertificate[]> {
  const rows = await db.prepare(
    `SELECT cb.id AS bundle_id,
            cb.domain AS domain,
            cb.version AS version,
            cb.cert_expires_at AS cert_expires_at,
            cb.created_at AS created_at,
            COALESCE(cb.fingerprint_sha256, '') AS fingerprint_sha256,
            COALESCE(cb.domains_json, '[]') AS domains_json,
            COALESCE(cb.cert_pem, '') AS cert_pem,
            COALESCE(cb.ca_pem, '') AS ca_pem
     FROM certificate_bundles cb
     WHERE cb.active = 1
     ORDER BY cb.domain ASC`,
  ).all<{
    bundle_id: string;
    domain: string;
    version: number;
    cert_expires_at: number;
    created_at: number;
    fingerprint_sha256: string;
    domains_json: string;
    cert_pem: string;
    ca_pem: string;
  }>();
  const out: AdminManagedCertificate[] = [];
  for (const row of rows.results) {
    const nodeRows = await db.prepare(
      `SELECT COALESCE(n.slug, n.id) AS node_id,
              latest.status AS status,
              latest.synced_at AS synced_at
       FROM node_certificate_bundles latest
       JOIN nodes n ON n.id = latest.node_id
       WHERE latest.bundle_id = ?
         AND latest.id = (
           SELECT newer.id
           FROM node_certificate_bundles newer
           WHERE newer.bundle_id = latest.bundle_id
             AND newer.node_id = latest.node_id
           ORDER BY newer.created_at DESC
           LIMIT 1
         )
       ORDER BY COALESCE(n.slug, n.id)`,
    )
      .bind(row.bundle_id)
      .all<{ node_id: string; status: string; synced_at: number | null }>();
    const nodes = nodeRows.results.map((node) => ({
      node_id: node.node_id,
      status: node.status,
      synced_at: node.synced_at,
    }));
    const syncedTimes = nodes.map((node) => node.synced_at).filter((value): value is number => typeof value === "number" && Number.isFinite(value));
    out.push({
      bundle_id: row.bundle_id,
      domain: row.domain,
      version: row.version,
      cert_expires_at: row.cert_expires_at,
      created_at: row.created_at,
      fingerprint_sha256: row.fingerprint_sha256,
      domains: parseDomainsJSON(row.domains_json, row.domain),
      cert_pem: row.cert_pem,
      ca_pem: row.ca_pem,
      sync_status: certificateAggregateStatus(nodes),
      synced_at: syncedTimes.length > 0 ? Math.min(...syncedTimes) : null,
      nodes,
    });
  }
  return out;
}

export async function syncManagedCertificatesToNodes(env: Env): Promise<{ synced: number; skipped: number }> {
  if (!env.DB) throw new Error("d1_required");
  const bundles = await activeManagedCertificateBundles(env.DB);
  const nodes = await listAdminNodes(env.DB);
  let synced = 0;
  let skipped = 0;
  for (const node of nodes) {
    const match = findCertificateBundleForDomain(bundles, node.domain);
    if (!match) {
      skipped += 1;
      continue;
    }
    try {
      const target = await certificateTarget(env.DB, node.internal_id ?? node.id);
      if (!target?.agent_encryption_public_key) {
        skipped += 1;
        continue;
      }
      await storeCertificateBundleForNode(env, target, match);
      synced += 1;
    } catch (error) {
      if (error instanceof Error && error.message === "node_encryption_key_required") {
        skipped += 1;
        continue;
      }
      throw error;
    }
  }
  return { synced, skipped };
}

export async function syncManagedCertificateToNode(env: Env, nodeID: string): Promise<{ synced: number; skipped: number; reason?: string }> {
  if (!env.DB) throw new Error("d1_required");
  const target = await certificateTarget(env.DB, nodeID);
  if (!target) return { synced: 0, skipped: 1, reason: "node_not_found" };
  const match = findCertificateBundleForDomain(await activeManagedCertificateBundles(env.DB), target.domain);
  if (!match) return { synced: 0, skipped: 1, reason: "certificate_not_found" };
  try {
    await storeCertificateBundleForNode(env, target, match);
    return { synced: 1, skipped: 0 };
  } catch (error) {
    if (error instanceof Error && error.message === "node_encryption_key_required") {
      return { synced: 0, skipped: 1, reason: "node_encryption_key_required" };
    }
    throw error;
  }
}

async function certificateTarget(db: SqlDatabase, nodeID: string): Promise<{ id: string; domain: string; agent_encryption_public_key: string | null } | null> {
  return db.prepare("SELECT id, domain, agent_encryption_public_key FROM nodes WHERE id = ? OR slug = ?").bind(nodeID, nodeID).first<{
    id: string;
    domain: string;
    agent_encryption_public_key: string | null;
  }>();
}

export async function activeManagedCertificateBundles(db: SqlDatabase): Promise<Array<{
  id: string;
  domain: string;
  domains: string[];
  cert_pem: string;
  key_pem: string;
  ca_pem: string;
  cert_expires_at: number;
}>> {
  const rows = await db.prepare(
    `SELECT cb.id AS bundle_id,
            cb.domain AS domain,
            COALESCE(cb.domains_json, '[]') AS domains_json,
            COALESCE(cb.cert_pem, '') AS cert_pem,
            COALESCE(cb.key_pem, '') AS key_pem,
            COALESCE(cb.ca_pem, '') AS ca_pem,
            cb.cert_expires_at
     FROM certificate_bundles cb
     WHERE cb.active = 1
     ORDER BY cb.domain ASC`,
  ).all<{
    bundle_id: string;
    domain: string;
    domains_json: string;
    cert_pem: string;
    key_pem: string;
    ca_pem: string;
    cert_expires_at: number;
  }>();
  return rows.results.map((row) => ({
    id: row.bundle_id,
    domain: row.domain,
    domains: parseDomainsJSON(row.domains_json, row.domain),
    cert_pem: row.cert_pem,
    key_pem: row.key_pem,
    ca_pem: row.ca_pem,
    cert_expires_at: row.cert_expires_at,
  }));
}

async function storeCertificateBundleForNode(
  env: Env,
  target: { id: string; domain: string; agent_encryption_public_key: string | null },
  bundle: { id: string; cert_pem: string; key_pem: string; ca_pem: string; cert_expires_at: number },
): Promise<{ node_bundle_id: string }> {
  const db = env.DB;
  if (!db) throw new Error("d1_required");
  if (!target.agent_encryption_public_key) throw new Error("node_encryption_key_required");
  const now = nowSeconds();
  const signed = await buildSignedCertificateBundle(env, {
    nodeID: target.id,
    domain: target.domain,
    certPEM: bundle.cert_pem,
    keyPEM: bundle.key_pem,
    caPEM: bundle.ca_pem,
    certExpiresAt: bundle.cert_expires_at,
  });
  const encrypted = await encryptForP256PublicKey(JSON.stringify(signed), target.agent_encryption_public_key);
  const nodeBundleID = `ncb_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
  const recipientKeyID = await p256KeyID(target.agent_encryption_public_key);
  await db.prepare(
    `INSERT INTO node_certificate_bundles (id, node_id, bundle_id, encrypted_payload, recipient_key_id, status, created_at, synced_at)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, NULL)`,
  )
    .bind(nodeBundleID, target.id, bundle.id, JSON.stringify(encrypted), recipientKeyID, now)
    .run();
  return { node_bundle_id: nodeBundleID };
}

export async function handleNodeControlCertBundle(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const auth = await authorizedNode(request, env);
  if (!auth) return json({ error: "invalid_node_token" }, { status: 401 });

  // Return the newest stored envelope. This is a pure read: the payload was
  // encrypted/signed once when the bundle was stored, and re-pulls must hand
  // back that same bytes. Status stays "pending" until the agent acknowledges
  // that it applied the bundle (POST /_lg/control/cert/ack), so a response
  // that never arrives, or an agent-side decrypt/apply failure, simply leaves
  // the row pending and the next poll retries it.
  const row = await env.DB.prepare(
    `SELECT id, bundle_id, encrypted_payload
     FROM node_certificate_bundles
     WHERE node_id = ?
     ORDER BY created_at DESC
     LIMIT 1`,
  )
    .bind(auth.nodeID)
    .first<NodeCertificateBundleRow>();
  if (!row) return json({ error: "cert_bundle_not_found" }, { status: 404 });
  return new Response(row.encrypted_payload, {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-lg-node-bundle-id": row.id,
      "x-lg-cert-bundle-id": row.bundle_id,
    },
  });
}

interface CertAckRequest {
  node_bundle_id?: string;
  bundle_id?: string;
  status?: string;
  error?: string;
}

/**
 * The agent calls this after it has actually applied (or failed to apply) a
 * certificate bundle. Only a successful apply marks the row "synced"; a
 * failure records the reason and leaves it retryable. Unknown/expired rows
 * are ignored so a stale agent cannot mark a newer bundle as synced.
 */
export async function handleNodeControlCertAck(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const auth = await authorizedNode(request, env);
  if (!auth) return json({ error: "invalid_node_token" }, { status: 401 });

  const body = await readJSON<CertAckRequest>(request);
  const nodeBundleID = body.node_bundle_id?.trim() || "";
  if (!nodeBundleID) return json({ error: "node_bundle_id_required" }, { status: 400 });
  const succeeded = body.status !== "failed";

  const row = await env.DB.prepare(
    `SELECT id FROM node_certificate_bundles WHERE id = ? AND node_id = ?`,
  )
    .bind(nodeBundleID, auth.nodeID)
    .first<{ id: string }>();
  if (!row) return json({ error: "cert_bundle_not_found" }, { status: 404 });

  if (succeeded) {
    await env.DB.prepare("UPDATE node_certificate_bundles SET status = 'synced', synced_at = ? WHERE id = ?")
      .bind(nowSeconds(), nodeBundleID)
      .run();
    // Record the applied certificate's new validity so operators can see what
    // the node is actually serving.
    const bundle = await env.DB.prepare(
      `SELECT cb.cert_expires_at AS cert_expires_at, cb.fingerprint_sha256 AS fingerprint_sha256
       FROM node_certificate_bundles ncb
       JOIN certificate_bundles cb ON cb.id = ncb.bundle_id
       WHERE ncb.id = ?`,
    )
      .bind(nodeBundleID)
      .first<{ cert_expires_at: number | null; fingerprint_sha256: string | null }>();
    const info = bundle
      ? `expires_at=${new Date((bundle.cert_expires_at ?? 0) * 1000).toISOString()} fingerprint=${(bundle.fingerprint_sha256 ?? "").slice(0, 24)}`
      : "";
    await recordNodeEvent(env.DB, { nodeID: auth.nodeID, type: "cert_applied", info });
  } else {
    // Keep it pending so the next poll re-delivers; record why for operators.
    workerWarn("cert.ack_failed", { node: auth.nodeID, node_bundle_id: nodeBundleID, reason: body.error || "apply_failed" });
  }
  return json({ ok: true, status: succeeded ? "synced" : "pending" });
}

async function buildSignedCertificateBundle(
  env: Env,
  input: { nodeID: string; domain: string; certPEM: string; keyPEM: string; caPEM: string; certExpiresAt: number },
): Promise<SignedCertificateBundle> {
  const configJwk = await getRuntimeJWK(env.DB, "LG_CONFIG_SIGN_JWK");
  const configKid = await kidFromJWK(configJwk);
  const payload: SignedCertificateBundle = {
    version: Date.now(),
    node_id: input.nodeID,
    domain: input.domain,
    issued_at: nowSeconds(),
    cert_expires_at: input.certExpiresAt,
    cert_pem: input.certPEM,
    key_pem: input.keyPEM,
    ca_pem: input.caPEM,
    config_kid: configKid,
    signature: "",
  };
  const signed = await signCompact({ ...payload }, configJwk);
  return { ...payload, signature: signed.split(".")[1] };
}

async function authorizedNode(request: Request, env: Env): Promise<{ nodeID: string } | null> {
  const auth = await validateNodeToken(env.DB, bearerToken(request));
  if (!auth) return null;
  const requestedNode = new URL(request.url).searchParams.get("node");
  if (requestedNode && requestedNode !== auth.nodeID) return null;
  return auth;
}

function normalizePEM(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed.includes(`-----BEGIN ${label}-----`) || !trimmed.includes(`-----END ${label}-----`)) return "";
  return `${trimmed}\n`;
}

function normalizePrivateKey(value: string): string {
  const trimmed = value.trim();
  if (!/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(trimmed) || !/-----END [A-Z ]*PRIVATE KEY-----$/.test(trimmed)) return "";
  return `${trimmed}\n`;
}

async function certificateFingerprintSHA256(certPEM: string): Promise<string> {
  // Fingerprint the leaf certificate only. A PEM chain concatenates multiple base64
  // blocks, each with its own trailing "=" padding — stripping all BEGIN/END markers and
  // joining them puts "=" mid-string, which atob() rejects. Decode just the first block.
  const match = certPEM.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!match) throw new Error("certificate_pem_invalid");
  const base64 = match[1].replace(/\s+/g, "");
  const der = Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
  return Array.from(digest).map((byte) => byte.toString(16).padStart(2, "0")).join(":");
}

function normalizeDomains(value: string[] | undefined, fallback: string): string[] {
  const domains = (value ?? [fallback])
    .map((domain) => domain.trim())
    .filter((domain, index, array) => domain.length > 0 && array.indexOf(domain) === index);
  return domains.length > 0 ? domains : [fallback];
}

function normalizeImportDomains(value: string[] | undefined, fallback: string[]): string[] {
  const source = value && value.length > 0 ? value : fallback;
  return source
    .map((domain) => domain.trim().replace(/^\.+|\.+$/g, ""))
    .filter((domain, index, array) => domain.length > 0 && array.indexOf(domain) === index);
}

function certificateBundleDomain(domains: string[]): string {
  return domains.find((domain) => domain.startsWith("*.")) ?? domains[0] ?? "managed";
}

function parseDomainsJSON(value: string, fallback: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return [fallback];
    const domains = parsed.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
    return domains.length > 0 ? domains : [fallback];
  } catch {
    return [fallback];
  }
}

export function findCertificateBundleForDomain<T extends { domain: string; domains: string[] }>(rows: T[], domain: string): T | null {
  for (const row of rows) {
    if (certificateDomainsMatch(row.domains, domain)) return row;
  }
  return null;
}

export function certificateDomainsMatch(patterns: string[], domain: string): boolean {
  const normalizedDomain = domain.trim().toLowerCase();
  for (const pattern of patterns) {
    const normalizedPattern = pattern.trim().toLowerCase();
    if (!normalizedPattern) continue;
    if (normalizedPattern === normalizedDomain) return true;
    if (normalizedPattern.startsWith("*.")) {
      // TLS wildcards cover exactly ONE label: *.example.com matches
      // a.example.com but NOT a.b.example.com. Require the remainder after
      // the wildcard label to be a single label.
      const suffix = normalizedPattern.slice(1); // ".example.com"
      if (normalizedDomain.endsWith(suffix) && normalizedDomain !== suffix.slice(1)) {
        const prefix = normalizedDomain.slice(0, normalizedDomain.length - suffix.length);
        if (prefix && !prefix.includes(".")) return true;
      }
    }
  }
  return false;
}

function certificateAggregateStatus(nodes: Array<{ status: string }>): string {
  if (nodes.length === 0) return "not_published";
  if (nodes.every((node) => node.status === "synced")) return "synced";
  if (nodes.some((node) => node.status === "synced")) return "partial";
  return "pending";
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
