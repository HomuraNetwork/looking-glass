import { bytesToBase64URL, sha256Hex } from "./signing";
import type { SqlDatabase } from "./runtime";

// 15 minutes: the init token is only meant to survive a single bootstrap
// attempt (install script → /_lg/control/config POST), not an hour of idle
// time. The plaintext token_value column is kept populated on purpose: it is
// the one-time display mechanism the admin panel uses to render the pull
// command after issuing (see activeNodeInitToken), and is cleared on
// consumption/revocation. The short TTL bounds that plaintext exposure window.
const INIT_TOKEN_TTL_SECONDS = 900;

export interface IssuedNodeInitToken {
  token: string;
  expires_at: number;
}

export interface ActiveNodeInitToken extends IssuedNodeInitToken {
  node_id: string;
}

interface NodeTokenRow {
  id: string;
  node_id: string;
  revoked_at: number | null;
}

export async function issueNodeInitToken(db: SqlDatabase, nodeID: string): Promise<IssuedNodeInitToken> {
  const now = nowSeconds();
  const token = opaqueToken("lginit");
  await db.batch([
    db
      .prepare(
        `UPDATE node_init_tokens
         SET consumed_at = ?, token_value = NULL
         WHERE node_id = ?
           AND consumed_at IS NULL`,
      )
      .bind(now, nodeID),
    db.prepare(
      `INSERT INTO node_init_tokens (id, node_id, token_hash, created_at, expires_at, consumed_at, token_value)
       VALUES (?, ?, ?, ?, ?, NULL, ?)`,
    )
      .bind(`nit_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`, nodeID, await sha256Hex(token), now, now + INIT_TOKEN_TTL_SECONDS, token),
  ]);
  return { token, expires_at: now + INIT_TOKEN_TTL_SECONDS };
}

export async function consumeNodeInitToken(db: SqlDatabase, token: string): Promise<{ nodeID: string } | null> {
  const now = nowSeconds();
  const row = await db
    .prepare(
      `UPDATE node_init_tokens
       SET consumed_at = ?, token_value = NULL
       WHERE token_hash = ?
         AND consumed_at IS NULL
         AND expires_at > ?
       RETURNING node_id`,
    )
    .bind(now, await sha256Hex(token), now)
    .first<{ node_id: string }>();
  if (!row) return null;
  return { nodeID: row.node_id };
}

export async function validateNodeInitToken(db: SqlDatabase | undefined, token: string): Promise<{ nodeID: string; expiresAt: number } | null> {
  if (!db || !token) return null;
  const now = nowSeconds();
  const row = await db
    .prepare(
      `SELECT node_id, expires_at
       FROM node_init_tokens
       WHERE token_hash = ?
         AND consumed_at IS NULL
         AND expires_at > ?`,
    )
    .bind(await sha256Hex(token), now)
    .first<{ node_id: string; expires_at: number }>();
  if (!row) return null;
  return { nodeID: row.node_id, expiresAt: row.expires_at };
}

export async function activeNodeInitToken(db: SqlDatabase | undefined, nodeID: string): Promise<ActiveNodeInitToken | null> {
  if (!db || !nodeID) return null;
  const now = nowSeconds();
  const row = await db
    .prepare(
      `SELECT node_id, token_value, expires_at
       FROM node_init_tokens
       WHERE node_id = ?
         AND token_value IS NOT NULL
         AND consumed_at IS NULL
         AND expires_at > ?
       ORDER BY created_at DESC
       LIMIT 1`,
    )
    .bind(nodeID, now)
    .first<{ node_id: string; token_value: string; expires_at: number }>();
  if (!row?.token_value) return null;
  return { node_id: row.node_id, token: row.token_value, expires_at: row.expires_at };
}

export async function issueNodeToken(db: SqlDatabase, nodeID: string): Promise<string> {
  const token = opaqueToken("lgnode");
  await db
    .prepare(
      `INSERT INTO node_tokens (id, node_id, token_hash, created_at, last_used_at, revoked_at)
       VALUES (?, ?, ?, ?, NULL, NULL)`,
    )
    .bind(`nt_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`, nodeID, await sha256Hex(token), nowSeconds())
    .run();
  return token;
}

export async function validateNodeToken(db: SqlDatabase | undefined, token: string): Promise<{ nodeID: string } | null> {
  if (!db || !token) return null;
  const row = await db
    .prepare(
      `SELECT id, node_id, revoked_at
       FROM node_tokens
       WHERE token_hash = ?`,
    )
    .bind(await sha256Hex(token))
    .first<NodeTokenRow>();
  if (!row || row.revoked_at !== null) return null;
  await db.prepare("UPDATE node_tokens SET last_used_at = ? WHERE id = ?").bind(nowSeconds(), row.id).run();
  return { nodeID: row.node_id };
}

export function bearerToken(request: Request): string {
  const header = request.headers.get("authorization") || "";
  if (!header.toLowerCase().startsWith("bearer ")) return "";
  return header.slice("bearer ".length).trim();
}

function opaqueToken(prefix: "lginit" | "lgnode"): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `${prefix}_${bytesToBase64URL(bytes)}`;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
