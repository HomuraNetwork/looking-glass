import { describe, expect, it } from "vitest";
import type { Env } from "../src/config";
import worker from "../src/index";
import { compactSqlStatement, inspectDatabase, initializeDatabase, splitSqlStatements } from "../src/db-bootstrap";
import { MIGRATIONS, SCHEMA_SQL } from "../src/db-schema";

const ALL_MIGRATIONS = MIGRATIONS.map((migration) => migration.name);

describe("D1 bootstrap", () => {
  it("returns db init state instead of failing admin session on an empty D1 database", async () => {
    const db = fakeSchemaD1([]);
    const response = await worker.fetch(new Request("http://worker.test/api/admin/session"), { DB: db } as Env);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      authenticated: false,
      onboarding_required: false,
      db_init_required: true,
      db_status: {
        status: "empty",
        table_count: 0,
      },
    });
  });

  it("treats Cloudflare-managed internal D1 tables as empty bootstrap state", async () => {
    const db = fakeSchemaD1(["_cf_KV"]);
    const response = await worker.fetch(new Request("http://worker.test/api/admin/session"), { DB: db } as Env);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      db_init_required: true,
      db_status: {
        status: "empty",
        table_count: 0,
        existing_tables: [],
      },
    });
  });

  it("rejects first admin setup until the database has been initialized", async () => {
    const db = fakeSchemaD1([]);
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/setup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "admin", password: "local-admin-pass" }),
      }),
      { DB: db } as Env,
    );

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: "db_init_required",
      db_status: { status: "empty" },
    });
  });

  it("initializes an empty database and seeds the default node profile", async () => {
    const db = fakeSchemaD1([]);
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/db/init", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
      { DB: db } as Env,
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      ok: true,
      db_status: { status: "ready" },
    });
    expect(db.runLog.some((sql) => sql.includes("CREATE TABLE IF NOT EXISTS admin_users"))).toBe(true);
    expect(db.execLog.some((sql) => sql.includes("CREATE TABLE"))).toBe(false);
    expect(db.seededDefaultProfile).toBe(true);
  });

  it("rejects an unauthenticated incompatible-DB reset with 401 and no confirmation leak", async () => {
    const db = fakeSchemaD1(["legacy_table"]);
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/db/init", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
      { DB: db } as Env,
    );

    // Destructive resets are admin-only: an unauthenticated caller gets 401
    // regardless of the confirmation body, and the confirm phrase (an
    // operator-side constant) is never echoed back by the API.
    expect(response.status).toBe(401);
    const body = JSON.stringify(await response.json());
    expect(body).not.toContain("RESET DATABASE");
    expect(body).not.toContain("confirm_phrase");
    expect(db.execLog.some((sql) => sql.startsWith("DROP TABLE"))).toBe(false);
    expect(db.runLog.some((sql) => sql.startsWith("DROP TABLE"))).toBe(false);
    expect(db.runLog.some((sql) => sql.includes("CREATE TABLE"))).toBe(false);
  });

  it("upgrades a legacy database in place for an authenticated admin without asking for a reset", async () => {
    // A database created by an older release (some tables, no migration
    // bookkeeping) is brought up to the current schema by applying pending
    // migrations — no tables or node rows are dropped, no reset confirmation
    // phrase required.
    const db = fakeSchemaD1(["nodes", "node_profiles", "project_settings"], { adminSession: true });
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/db/init", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: "hlg_admin=lgs_admin-session-token" },
        body: JSON.stringify({}),
      }),
      { DB: db } as Env,
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      ok: true,
      upgraded: true,
      db_status: { status: "ready" },
    });
    expect(db.runLog.some((sql) => sql.startsWith("DROP TABLE"))).toBe(false);
  });

  it("still returns db_init_confirmation_required when migrations cannot repair the schema", async () => {
    // A required table that no migration manages to create keeps the database
    // incompatible; only then is the destructive reset offered.
    const db = fakeSchemaD1(["legacy_table"], { adminSession: true, frozen: ["node_profiles"] });
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/db/init", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: "hlg_admin=lgs_admin-session-token" },
        body: JSON.stringify({}),
      }),
      { DB: db } as Env,
    );

    expect(response.status).toBe(409);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      error: "db_init_confirmation_required",
      db_status: { status: "incompatible" },
    });
    expect(JSON.stringify(body)).not.toContain("RESET DATABASE");
    expect(db.runLog.some((sql) => sql.startsWith("DROP TABLE"))).toBe(false);
  });

  it("resets an unrepairable database when confirmed by an authenticated admin", async () => {
    // admin_users is required but cannot be created (simulating an
    // unrepairable schema): the upgrade attempt fails, the operator confirms,
    // and the destructive reset runs while operator tables survive.
    const db = fakeSchemaD1(
      ["legacy_table", "_cf_KV", "other_operator_table", "nodes", "acme_pending_orders", "project_settings", "schema_migrations"],
      { adminSession: true, frozen: ["admin_users"] },
    );
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/db/init", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: "hlg_admin=lgs_admin-session-token" },
        body: JSON.stringify({ confirm: "RESET DATABASE" }),
      }),
      { DB: db } as Env,
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ ok: true, reset: true });
    // Only schema-owned tables are dropped; operator tables are preserved.
    expect(db.runLog).toContain('DROP TABLE IF EXISTS "nodes"');
    expect(db.runLog).toContain('DROP TABLE IF EXISTS "admin_users"');
    expect(db.runLog).toContain('DROP TABLE IF EXISTS "acme_pending_orders"');
    expect(db.runLog).toContain('DROP TABLE IF EXISTS "project_settings"');
    expect(db.runLog).toContain('DROP TABLE IF EXISTS "iperf_sessions"');
    expect(db.runLog).toContain('DROP TABLE IF EXISTS "schema_migrations"');
    const dropped = db.runLog.filter((sql) => sql.startsWith("DROP TABLE"));
    expect(dropped.some((sql) => sql.includes('"legacy_table"'))).toBe(false);
    expect(dropped.some((sql) => sql.includes('"_cf_KV"'))).toBe(false);
    expect(dropped.some((sql) => sql.includes('"other_operator_table"'))).toBe(false);
    const afterReset = await inspectDatabase(db);
    expect(afterReset.existing_tables).toContain("legacy_table");
    expect(afterReset.existing_tables).toContain("other_operator_table");
  });

  it("detects partial project schemas as incompatible", async () => {
    const db = fakeSchemaD1(["nodes", "project_settings"]);
    await expect(inspectDatabase(db)).resolves.toMatchObject({
      status: "incompatible",
      table_count: 2,
      missing_tables: expect.arrayContaining(["admin_users", "node_profiles"]),
    });
  });

  it("applies pending migrations to a ready database (the upgrade path)", async () => {
    // Reproduce the real upgrade scenario: the full current schema exists but
    // migration bookkeeping is missing, so every migration is "pending". A
    // ready database must still report that pending work and let an admin
    // apply it — the previous behaviour short-circuited on status === "ready"
    // and silently skipped new migrations.
    const db = fakeSchemaD1([], { adminSession: true });
    await initializeDatabase(db);
    await expect(inspectDatabase(db)).resolves.toMatchObject({ status: "ready", pending_migrations: [] });

    // Drop the bookkeeping to simulate a database upgraded before tracking
    // existed / a release that added migrations without backfilling the table.
    await db.prepare('DROP TABLE IF EXISTS "schema_migrations"').run();
    const pending = await inspectDatabase(db);
    expect(pending.status).toBe("ready");
    expect(pending.pending_migrations).toEqual(ALL_MIGRATIONS);
    db.runLog.length = 0;

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/db/init", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: "hlg_admin=lgs_admin-session-token" },
        body: JSON.stringify({}),
      }),
      { DB: db } as Env,
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      ok: true,
      applied: ALL_MIGRATIONS,
      db_status: { status: "ready", pending_migrations: [] },
    });
    // A ready upgrade must never drop tables.
    expect(db.runLog.some((sql) => sql.startsWith("DROP TABLE"))).toBe(false);
  });

  it("requires an authenticated admin to apply pending migrations on a ready database", async () => {
    const db = fakeSchemaD1([]);
    await initializeDatabase(db);
    await db.prepare('DROP TABLE IF EXISTS "schema_migrations"').run();
    db.runLog.length = 0;

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/db/init", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
      { DB: db } as Env,
    );
    // Schema changes on a live database are admin-only, even for in-place migrations.
    expect(response.status).toBe(401);
    expect(db.runLog.some((sql) => sql.includes("schema_migrations"))).toBe(false);
  });

  it("splits the multiline schema into complete SQL statements", () => {
    const statements = splitSqlStatements(SCHEMA_SQL);
    expect(statements[0]).toMatch(/^CREATE TABLE IF NOT EXISTS nodes \(/);
    expect(statements[0]).toContain("updated_at INTEGER NOT NULL");
    expect(statements[0]).not.toContain("CREATE UNIQUE INDEX");
    expect(statements.some((statement) => statement.startsWith("CREATE TABLE IF NOT EXISTS admin_users"))).toBe(true);
  });

  it("does not split semicolons inside quoted SQL literals", () => {
    expect(splitSqlStatements("INSERT INTO t VALUES ('a;b'); SELECT 1;")).toEqual([
      "INSERT INTO t VALUES ('a;b')",
      "SELECT 1",
    ]);
  });

  it("compacts multiline schema statements before sending them to D1", () => {
    const statement = splitSqlStatements(SCHEMA_SQL)[0];
    expect(compactSqlStatement(statement)).toMatch(/^CREATE TABLE IF NOT EXISTS nodes \( id TEXT PRIMARY KEY,/);
    expect(compactSqlStatement(statement)).not.toContain("\n");
    expect(compactSqlStatement("SELECT 'a  b'\nFROM t -- comment\nWHERE id = 1")).toBe("SELECT 'a  b' FROM t WHERE id = 1");
  });
});

interface FakeSchemaD1 extends D1Database {
  execLog: string[];
  runLog: string[];
  seededDefaultProfile: boolean;
  appliedMigrations: string[];
}

function fakeSchemaD1(
  initialTables: string[],
  options: { adminSession?: boolean; frozen?: string[] } = {},
): FakeSchemaD1 {
  let tableNames = [...initialTables];
  const appliedMigrations: string[] = [];
  const frozen = new Set(options.frozen ?? []);
  const execLog: string[] = [];
  const runLog: string[] = [];
  const db = {
    execLog,
    runLog,
    seededDefaultProfile: false,
    appliedMigrations,
    async exec(sql: string) {
      execLog.push(sql);
      if (/CREATE TABLE/i.test(sql)) throw new Error("schema_create_must_not_use_exec");
      applySql(sql);
      return { count: 1, duration: 0 };
    },
    async batch(statements: Array<{ run(): Promise<unknown> }>) {
      for (const statement of statements) await statement.run();
      return statements.map(() => ({ success: true, meta: d1Meta() } as D1Result));
    },
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return bound(sql, db, values);
        },
        ...bound(sql, db, []),
      };
    },
  } as FakeSchemaD1;
  return db;

  function applySql(sql: string) {
    const dropMatch = sql.match(/^DROP TABLE IF EXISTS "((?:[^"]|"")+)"/);
    if (dropMatch) {
      const table = dropMatch[1].replaceAll("\"\"", "\"");
      tableNames = tableNames.filter((name) => name !== table);
      if (table === "schema_migrations") appliedMigrations.length = 0;
    }
    for (const match of sql.matchAll(/CREATE TABLE IF NOT EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)/g)) {
      // "Frozen" tables model a schema the migration runner cannot repair:
      // they are never created, keeping the database incompatible after an
      // upgrade attempt so the destructive-reset branch stays reachable.
      if (frozen.has(match[1])) continue;
      if (!tableNames.includes(match[1])) tableNames.push(match[1]);
    }
  }

  function bound(sql: string, target: FakeSchemaD1, values: unknown[]) {
    return {
      async all<T>() {
        if (sql.includes("FROM sqlite_master")) {
          return {
            results: tableNames.slice().sort().map((name) => ({ name })) as T[],
            success: true,
            meta: d1Meta(),
          } as D1Result<T>;
        }
        if (sql.includes("FROM schema_migrations")) {
          return {
            results: appliedMigrations.map((name) => ({ name })) as T[],
            success: true,
            meta: d1Meta(),
          } as D1Result<T>;
        }
        return { results: [], success: true, meta: d1Meta() } as D1Result<T>;
      },
      async first<T>() {
        if (options.adminSession && sql.includes("FROM admin_sessions")) {
          return {
            session_id: "sess_fake",
            id: "adm_fake",
            username: "admin",
            role: "admin",
            expires_at: Math.floor(Date.now() / 1000) + 3600,
          } as T;
        }
        return null as T | null;
      },
      async run() {
        target.runLog.push(sql);
        applySql(sql);
        if (sql.includes("INSERT INTO schema_migrations")) {
          const name = values[0];
          if (typeof name === "string" && !appliedMigrations.includes(name)) appliedMigrations.push(name);
        }
        if (sql.includes("INSERT OR IGNORE INTO node_profiles")) {
          target.seededDefaultProfile = true;
        }
        return { success: true, meta: { changes: 1 } } as D1Result;
      },
    };
  }
}

function d1Meta(): D1Meta & Record<string, unknown> {
  return {
    duration: 0,
    size_after: 0,
    rows_read: 0,
    rows_written: 0,
    last_row_id: 0,
    changed_db: false,
    changes: 0,
  };
}
