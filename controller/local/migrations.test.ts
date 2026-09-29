import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { applyMigrations, inspectDatabase } from "../src/db-bootstrap";
import { MIGRATIONS, SCHEMA_SQL } from "../src/db-schema";
import { wrapSqliteDatabase } from "./sqlite";

const ALL_MIGRATIONS = MIGRATIONS.map((migration) => migration.name);

describe("schema migrations", () => {
  it("ships a single release baseline", () => {
    expect(ALL_MIGRATIONS).toEqual(["0001_initial"]);
    expect(MIGRATIONS[0].sql).not.toMatch(/\b(?:ALTER|DROP|UPDATE)\b/i);
  });

  it("creates the full schema on an empty database and is idempotent", async () => {
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    const first = await applyMigrations(db);
    expect(first.applied).toEqual(ALL_MIGRATIONS);
    await expect(inspectDatabase(db)).resolves.toMatchObject({ status: "ready" });

    const second = await applyMigrations(db);
    expect(second.applied).toEqual([]);
    // The bookkeeping table records each migration exactly once.
    const rows = await db.prepare("SELECT name FROM schema_migrations ORDER BY name").all<{ name: string }>();
    expect(rows.results.map((row) => row.name)).toEqual(ALL_MIGRATIONS);
  });

  it("reports and applies pending migrations on a ready database", async () => {
    // A ready database (all tables present) whose bookkeeping was lost — the
    // state a pre-tracking release left behind. Readiness is by table presence,
    // so the runner must still surface the pending work and apply it, or new
    // migrations would silently never run. This is the local-runtime startup
    // path as well as the admin "apply update" path.
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    await applyMigrations(db);
    await expect(inspectDatabase(db)).resolves.toMatchObject({ status: "ready", pending_migrations: [] });

    await db.prepare("DROP TABLE schema_migrations").run();
    const pending = await inspectDatabase(db);
    expect(pending.status).toBe("ready");
    expect(pending.pending_migrations).toEqual(ALL_MIGRATIONS);

    // Re-applying is idempotent (CREATE IF NOT EXISTS / guarded ALTERs) and
    // records the migrations while preserving node records.
    const { applied } = await applyMigrations(db);
    expect(applied).toEqual(ALL_MIGRATIONS);
    await expect(inspectDatabase(db)).resolves.toMatchObject({ status: "ready", pending_migrations: [] });
  });

  it("creates the final node shape directly without retired columns", async () => {
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    await applyMigrations(db);
    const columns = await db.prepare("PRAGMA table_info(nodes)").all<{ name: string }>();
    const names = columns.results.map((column) => column.name);
    expect(names).toEqual(expect.arrayContaining(["port", "last_seen_at", "config_applied_version", "display_order", "build_id"]));
    expect(names).not.toContain("agent_port");
    expect(names).not.toContain("region");

    const indexes = await db.prepare("SELECT name FROM sqlite_master WHERE type = 'index'").all<{ name: string }>();
    expect(indexes.results.map((index) => index.name)).toEqual(
      expect.arrayContaining(["idx_nodes_slug", "idx_node_events_node_created", "idx_rate_limits_reset_at"]),
    );
  });

  it("tolerates a database that already has the combined schema but no migration bookkeeping", async () => {
    // e.g. bootstrapped by the release schema before the runner existed, or
    // provisioned out-of-band: the baseline is an idempotent no-op.
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    for (const statement of SCHEMA_SQL.split(";").map((s) => s.trim()).filter(Boolean)) {
      db.prepare(statement).run();
    }
    const { applied } = await applyMigrations(db);
    expect(applied).toEqual(ALL_MIGRATIONS);
    await expect(inspectDatabase(db)).resolves.toMatchObject({ status: "ready" });
  });

  it("does not lose a write reported successful while a batch is in flight", async () => {
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    await db.prepare("CREATE TABLE t (id TEXT PRIMARY KEY)").run();

    // A batch whose second statement fails, racing single writes.
    const failingBatch = db
      .batch([db.prepare("INSERT INTO t VALUES (?)").bind("batch-row"), db.prepare("INSERT INTO nonexistent VALUES (?)").bind("x")])
      .then(
        () => "committed" as const,
        () => "rolled-back" as const,
      );
    const singleWrite = db.prepare("INSERT INTO t VALUES (?)").bind("single-row").run().then(() => "written" as const);

    const [batchOutcome, writeOutcome] = await Promise.all([failingBatch, singleWrite]);
    expect(batchOutcome).toBe("rolled-back");
    expect(writeOutcome).toBe("written");

    // The failed batch is fully rolled back...
    const rows = await db.prepare("SELECT id FROM t ORDER BY id").all<{ id: string }>();
    expect(rows.results.map((row) => row.id)).toEqual(["single-row"]);
  });

  it("never interleaves concurrent batches into nested transactions", async () => {
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    await db.prepare("CREATE TABLE t (id TEXT PRIMARY KEY)").run();
    const batch = (prefix: string) => db.batch([db.prepare("INSERT INTO t VALUES (?)").bind(`${prefix}-1`), db.prepare("INSERT INTO t VALUES (?)").bind(`${prefix}-2`)]);
    const singles = Array.from({ length: 10 }, (_, index) => db.prepare("INSERT INTO t VALUES (?)").bind(`solo-${index}`).run().then(() => true, () => false));

    // Before the queue this raced: the awaits between batch statements let
    // other writes slip inside the open transaction (nested BEGIN errors, or
    // a ROLLBACK discarding a foreign write).
    await Promise.all([batch("a"), batch("b"), batch("c"), ...singles]);
    const rows = await db.prepare("SELECT id FROM t ORDER BY id").all<{ id: string }>();
    expect(rows.results).toHaveLength(16);
  });
});
