import { sha256Hex } from "./signing";
import type { SqlDatabase } from "./runtime";

export interface DownloadLinkAuditInput {
  id: string;
  node: string;
  size: string;
  token: string;
  clientIP: string;
  createdAt: number;
  expiresAt: number;
}

export interface OperationAuditInput {
  id: string;
  operationType: "download_link" | "job" | "iperf_session" | "live_session";
  node: string;
  clientIP: string;
  status: string;
  metadata: Record<string, unknown>;
  createdAt: number;
  expiresAt?: number;
}

export async function recordDownloadLink(db: SqlDatabase | undefined, input: DownloadLinkAuditInput): Promise<void> {
  if (!db) return;
  const clientHash = (await sha256Hex(input.clientIP)).slice(0, 16);
  const tokenHash = await sha256Hex(input.token);
  await db
    .prepare(
      `INSERT INTO download_links (
        id, node_id, client_ip_hash, size, token_hash, status, created_at, expires_at, replaced_at,
        extension_count, last_extended_at, usage_count, last_used_at
      ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, NULL, 0, NULL, 0, NULL)`,
    )
    .bind(input.id, input.node, clientHash, input.size, tokenHash, input.createdAt, input.expiresAt)
    .run();
}

export async function recordDownloadLinkExtension(db: SqlDatabase, input: {
  id: string;
  node: string;
  clientHash: string;
  previousTokenHash: string;
  token: string;
  expiresAt: number;
  extendedAt: number;
  maxExtensions: number;
}): Promise<{ extension_count: number } | null> {
  const tokenHash = await sha256Hex(input.token);
  return db
    .prepare(
      `UPDATE download_links
       SET token_hash = ?, expires_at = ?, extension_count = extension_count + 1, last_extended_at = ?
       WHERE id = ?
         AND node_id = ?
         AND client_ip_hash = ?
         AND token_hash = ?
         AND status = 'active'
         AND expires_at > ?
         AND extension_count < ?
       RETURNING extension_count`,
    )
    .bind(
      tokenHash,
      input.expiresAt,
      input.extendedAt,
      input.id,
      input.node,
      input.clientHash,
      input.previousTokenHash,
      input.extendedAt,
      input.maxExtensions,
    )
    .first<{ extension_count: number }>();
}

export async function recordDownloadUse(db: SqlDatabase | undefined, input: {
  id: string;
  node: string;
  size: string;
  usedAt?: number;
}): Promise<{ usage_count: number } | null> {
  if (!db) return null;
  const usedAt = input.usedAt ?? Math.floor(Date.now() / 1000);
  const result = await db
    .prepare(
      `UPDATE download_links
       SET usage_count = usage_count + 1, last_used_at = ?
       WHERE id = ? AND node_id = ? AND status = 'active' AND expires_at > ?
       RETURNING usage_count`,
    )
    .bind(usedAt, input.id, input.node, usedAt)
    .first<{ usage_count: number }>();
  if (!result) return null;
  await recordOperation(db, {
    id: `dlu_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`,
    operationType: "download_link",
    node: input.node,
    clientIP: "node-sync",
    status: "used",
    metadata: { link_id: input.id, size: input.size, used_at: usedAt },
    createdAt: usedAt,
  });
  return result;
}

export async function recordOperation(db: SqlDatabase | undefined, input: OperationAuditInput): Promise<void> {
  if (!db) return;
  const clientHash = (await sha256Hex(input.clientIP)).slice(0, 16);
  await db
    .prepare(
      `INSERT INTO operation_audit (
        id, operation_type, node_id, client_ip_hash, status, metadata_json, created_at, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.id,
      input.operationType,
      input.node,
      clientHash,
      input.status,
      JSON.stringify(input.metadata),
      input.createdAt,
      input.expiresAt ?? null,
    )
    .run();
}

export async function expireOpenIperfSessions(db: SqlDatabase | undefined, now = Math.floor(Date.now() / 1000)): Promise<number> {
  if (!db) return 0;
  const rows = await db
    .prepare("SELECT id, expires_at FROM iperf_sessions WHERE status = 'open' AND expires_at IS NOT NULL AND expires_at <= ?")
    .bind(now)
    .all<{ id: string; expires_at: number }>();
  for (const row of rows.results) {
    await closeIperfSessionAudit(db, {
      id: row.id,
      status: "expired",
      reason: "ttl_expired",
      closedAt: row.expires_at || now,
    });
  }
  return rows.results.length;
}

export async function closeIperfSessionAudit(db: SqlDatabase | undefined, input: {
  id: string;
  status: string;
  reason?: string;
  closedAt?: number;
}): Promise<void> {
  if (!db) return;
  const closedAt = input.closedAt ?? Math.floor(Date.now() / 1000);
  await db
    .prepare("UPDATE iperf_sessions SET status = ?, closed_at = ? WHERE id = ?")
    .bind(input.status, closedAt, input.id)
    .run();
  await db
    .prepare("UPDATE operation_audit SET status = ?, metadata_json = ? WHERE id = ?")
    .bind(input.status, JSON.stringify({ close_reason: input.reason ?? input.status, closed_at: closedAt }), input.id)
    .run();
}
