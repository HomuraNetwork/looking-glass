import type { SqlDatabase } from "./runtime";

/**
 * Short-lived locks for steps that must not run concurrently across requests.
 *
 * A lock is a row in `task_locks`; it is held while `locked_until` is in the
 * future. Acquisition is one atomic upsert guarded on the stored expiry, so
 * when N requests race (e.g. every node pulls config at once) exactly one wins
 * and the rest no-op.
 *
 * Acquisition returns a fence (the locked_until it wrote). The holder passes
 * that fence back to `releaseTaskLock`, which only clears the row when the
 * stored value still matches — so a holder that overran its TTL and had the
 * lock stolen by someone else cannot clear the new holder's lock. (Releasing on
 * any stored value, or unconditionally, would clobber the thief's lock and let
 * a third caller start concurrently.)
 */

/** Acquire the named lock; returns the fence to pass to release, or null if held. */
export async function acquireTaskLock(db: SqlDatabase, name: string, ttlSeconds: number): Promise<number | null> {
  const now = nowSeconds();
  const lockedUntil = now + ttlSeconds;
  const result = await db
    .prepare(
      `INSERT INTO task_locks (name, locked_until, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET locked_until = excluded.locked_until, updated_at = excluded.updated_at
       WHERE task_locks.locked_until < ?`,
    )
    .bind(name, lockedUntil, now, now)
    .run();
  return (result.meta?.changes ?? 0) > 0 ? lockedUntil : null;
}

/**
 * Release a lock held by this caller, only if the stored fence still matches
 * (i.e. nobody else has taken it since). Best effort.
 */
export async function releaseTaskLock(db: SqlDatabase, name: string, fence: number): Promise<void> {
  await db
    .prepare("UPDATE task_locks SET locked_until = 0, updated_at = ? WHERE name = ? AND locked_until = ?")
    .bind(nowSeconds(), name, fence)
    .run();
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
