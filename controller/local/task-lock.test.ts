import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { applyMigrations } from "../src/db-bootstrap";
import { acquireTaskLock, releaseTaskLock } from "../src/task-lock";
import { wrapSqliteDatabase } from "./sqlite";

async function dbWithLocks() {
  const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
  await applyMigrations(db);
  return db;
}

/** Read the stored lock expiry directly (0 means free). */
async function storedExpiry(db: Awaited<ReturnType<typeof dbWithLocks>>, name: string): Promise<number> {
  const row = await db.prepare("SELECT locked_until FROM task_locks WHERE name = ?").bind(name).first<{ locked_until: number }>();
  return row?.locked_until ?? 0;
}

/**
 * The lock must serialize concurrent callers: when several nodes pull config at
 * once, only one may start a certificate order. Acquisition is a single atomic
 * upsert guarded on the stored expiry, so exactly one of N racing callers wins,
 * and release is fenced so a TTL-overrunning holder cannot clear the lock a
 * later caller has since taken.
 */
describe("task locks", () => {
  it("lets exactly one of many concurrent acquirers win", async () => {
    const db = await dbWithLocks();
    const results = await Promise.all(
      Array.from({ length: 8 }, () => acquireTaskLock(db, "job", 60)),
    );
    expect(results.filter((fence) => fence !== null)).toHaveLength(1);
  });

  it("cannot be re-acquired until it is released", async () => {
    const db = await dbWithLocks();
    const first = await acquireTaskLock(db, "job", 60);
    expect(first).not.toBeNull();
    expect(await acquireTaskLock(db, "job", 60)).toBeNull();
    await releaseTaskLock(db, "job", first!);
    expect(await acquireTaskLock(db, "job", 60)).not.toBeNull();
  });

  it("expires after its TTL so a crashed holder does not block forever", async () => {
    const db = await dbWithLocks();
    // A pre-existing expired lock (expiry in the past) can be taken again.
    await db.prepare("INSERT INTO task_locks (name, locked_until, updated_at) VALUES (?, ?, ?)").bind("job", 1, 1).run();
    expect(await acquireTaskLock(db, "job", 60)).not.toBeNull();
  });

  it("does not let a stale holder release the lock someone else took", async () => {
    const db = await dbWithLocks();
    const staleFence = await acquireTaskLock(db, "job", 60);
    expect(staleFence).not.toBeNull();
    // Simulate the holder overrunning its TTL and another caller taking over.
    const secondFence = await acquireTaskLock(db, "job", 9999);
    // (Not yet expired, so this returns null; force the takeover directly.)
    expect(secondFence).toBeNull();
    const forced = staleFence! + 1;
    await db.prepare("UPDATE task_locks SET locked_until = ? WHERE name = ?").bind(forced, "job").run();

    // The stale holder now releases with its old fence: it must NOT clear the
    // lock the new holder owns.
    await releaseTaskLock(db, "job", staleFence!);
    expect(await storedExpiry(db, "job")).toBe(forced);
    // The new holder's release (matching fence) does clear it.
    await releaseTaskLock(db, "job", forced);
    expect(await storedExpiry(db, "job")).toBe(0);
  });

  it("treats different lock names independently", async () => {
    const db = await dbWithLocks();
    expect(await acquireTaskLock(db, "a", 60)).not.toBeNull();
    expect(await acquireTaskLock(db, "b", 60)).not.toBeNull();
    expect(await acquireTaskLock(db, "a", 60)).toBeNull();
  });
});
