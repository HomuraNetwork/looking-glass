import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { wrapSqliteDatabase } from "../local/sqlite";

/**
 * The local runtime's SqlDatabase adapter. These exercise the D1-compatibility
 * details that differ from raw node:sqlite: lazy prepare (so a batch can be
 * built before its tables exist) and binding normalization.
 */
describe("node:sqlite SqlDatabase adapter", () => {
  it("supports the D1 batch pattern of building statements before running them", async () => {
    // A CREATE INDEX references a table that does not exist yet. prepare() must
    // not validate eagerly, or initializeDatabase's batch would throw.
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    const statements = [
      db.prepare("CREATE TABLE t (id TEXT PRIMARY KEY, n INTEGER)"),
      db.prepare("CREATE INDEX idx_t_n ON t (n)"),
    ];
    await db.batch(statements);
    const tables = await db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all<{ name: string }>();
    expect(tables.results.map((row) => row.name)).toContain("t");
  });

  it("normalizes undefined and boolean bindings like D1", async () => {
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    await db.prepare("CREATE TABLE t (a TEXT, b INTEGER, c INTEGER)").run();
    await db.prepare("INSERT INTO t VALUES (?, ?, ?)").bind("x", undefined, true).run();
    const row = await db.prepare("SELECT a, b, c FROM t").first<{ a: string; b: number | null; c: number }>();
    expect(row).toEqual({ a: "x", b: null, c: 1 });
  });

  it("reports changes from run()", async () => {
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    await db.prepare("CREATE TABLE t (id TEXT PRIMARY KEY)").run();
    const inserted = await db.prepare("INSERT INTO t VALUES (?)").bind("a").run();
    expect(inserted.meta.changes).toBe(1);
    const missed = await db.prepare("UPDATE t SET id = ? WHERE id = ?").bind("b", "zzz").run();
    expect(missed.meta.changes).toBe(0);
  });

  it("rolls a batch back atomically on failure", async () => {
    const db = wrapSqliteDatabase(new DatabaseSync(":memory:"));
    await db.prepare("CREATE TABLE t (id TEXT PRIMARY KEY)").run();
    await expect(
      db.batch([
        db.prepare("INSERT INTO t VALUES (?)").bind("a"),
        // Second statement violates the primary key and must roll the first back.
        db.prepare("INSERT INTO t VALUES (?)").bind("a"),
      ]),
    ).rejects.toThrow();
    const rows = await db.prepare("SELECT id FROM t").all<{ id: string }>();
    expect(rows.results).toEqual([]);
  });
});
