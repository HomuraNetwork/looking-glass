import { sha256Hex } from "./signing";
import type { SqlDatabase } from "./runtime";

export interface RateLimitInput {
  db?: SqlDatabase;
  action: "download_link" | "iperf_session" | "admin_login" | "admin_login_global" | "job_token" | "live_session" | "live_command";
  node: string;
  clientIP: string;
  limit: number;
  windowSeconds: number;
  now?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  resetAt: number;
  remaining: number;
}

export async function consumeRateLimit(input: RateLimitInput): Promise<RateLimitResult> {
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const resetAt = now + input.windowSeconds;
  if (!input.db) {
    return { allowed: true, resetAt, remaining: input.limit - 1 };
  }

  const bucket = `${input.action}:${input.node}:${Math.floor(now / input.windowSeconds)}`;
  const key = await sha256Hex(`${bucket}:${input.clientIP}`);
  const row = await input.db
    .prepare(
      `INSERT INTO rate_limits (key, bucket, count, reset_at, updated_at)
       VALUES (?, ?, 1, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE
           WHEN rate_limits.reset_at <= ? THEN 1
           ELSE rate_limits.count + 1
         END,
         reset_at = CASE
           WHEN rate_limits.reset_at <= ? THEN excluded.reset_at
           ELSE rate_limits.reset_at
         END,
         updated_at = excluded.updated_at
       WHERE rate_limits.reset_at <= ? OR rate_limits.count < ?
       RETURNING count, reset_at`,
    )
    .bind(key, bucket, resetAt, now, now, now, now, input.limit)
    .first<{ count: number; reset_at: number }>();

  if (!row) return { allowed: false, resetAt, remaining: 0 };
  return { allowed: true, resetAt: row.reset_at, remaining: Math.max(0, input.limit - row.count) };
}
