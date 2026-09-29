import type { SqlDatabase } from "./runtime";
export interface RetentionCounts {
  rate_limits: number;
  iperf_sessions: number;
  download_links: number;
  node_init_tokens: number;
  operation_audit: number;
}

/** Rows older than this that are already closed are swept from iperf_sessions. */
export const IPERF_RETENTION_SECONDS = 7 * 86400;
/** Grace window for expired rows: keep them this long past expiry before deleting. */
export const EXPIRY_GRACE_SECONDS = 86400;

const EMPTY_COUNTS: RetentionCounts = {
  rate_limits: 0,
  iperf_sessions: 0,
  download_links: 0,
  node_init_tokens: 0,
  operation_audit: 0,
};

/**
 * Cron-side retention sweep: bounded, best-effort deletes of stale rows.
 * Every statement is independent — one failing table must not block the
 * others, and any failure is reported in the returned counts (0) rather than
 * thrown, so the cron's certificate renewal is never affected.
 */
export async function runRetentionCleanup(
  db: SqlDatabase | undefined,
  now = Math.floor(Date.now() / 1000),
): Promise<RetentionCounts> {
  if (!db) return { ...EMPTY_COUNTS };
  const rateLimitCutoff = now - EXPIRY_GRACE_SECONDS;
  const iperfCutoff = now - IPERF_RETENTION_SECONDS;
  const statements: Array<{ table: keyof RetentionCounts; sql: string; cutoff: number }> = [
    { table: "rate_limits", sql: "DELETE FROM rate_limits WHERE reset_at < ?", cutoff: rateLimitCutoff },
    { table: "iperf_sessions", sql: "DELETE FROM iperf_sessions WHERE status != 'open' AND created_at < ?", cutoff: iperfCutoff },
    { table: "download_links", sql: "DELETE FROM download_links WHERE expires_at < ?", cutoff: rateLimitCutoff },
    { table: "node_init_tokens", sql: "DELETE FROM node_init_tokens WHERE expires_at < ?", cutoff: rateLimitCutoff },
    { table: "operation_audit", sql: "DELETE FROM operation_audit WHERE expires_at < ?", cutoff: rateLimitCutoff },
  ];
  const counts: RetentionCounts = { ...EMPTY_COUNTS };
  for (const statement of statements) {
    try {
      const result = await db.prepare(statement.sql).bind(statement.cutoff).run();
      counts[statement.table] = result.meta?.changes ?? 0;
    } catch {
      counts[statement.table] = 0;
    }
  }
  return counts;
}