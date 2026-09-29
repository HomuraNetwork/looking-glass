import { adminSessionFromRequest } from "./admin-auth";
import { Env } from "./config";
import { dbBindingMissing, json, methodNotAllowed } from "./http";
import { MIGRATIONS } from "./db-schema";
import { workerLog } from "./log";
import type { SqlDatabase, SqlStatement } from "./runtime";

export const DB_RESET_CONFIRM_PHRASE = "RESET DATABASE";

/**
 * Tracks which schema migrations a database has already applied. It is owned by
 * the migration runner (not part of REQUIRED_TABLES: it may exist before the
 * rest of the schema) and is dropped together with the schema-owned tables on
 * a destructive reset.
 */
export const SCHEMA_MIGRATIONS_TABLE = "schema_migrations";

export const DEFAULT_NODE_PROFILE = {
  features: ["generate204", "download", "ping", "mtr", "traceroute", "nexttrace", "iperf3"],
  limits: {
    download_concurrency: 2,
    iperf_active_sessions: 10,
    job_concurrency_per_ip: 1,
    job_timeout_sec: 45,
    job_max_output_bytes: 65536,
    allowed_download_sizes: ["10M", "100M", "1G"],
    iperf_port_min: 30000,
    iperf_port_max: 39999,
    iperf_ttl_seconds: 180,
    iperf_max_duration: 40,
    iperf_max_parallel: 10,
    iperf_max_runs: 4,
    iperf_run_budget: 200,
    token_ipv4_prefix: 24,
    token_ipv6_prefix: 48,
    allowed_control_ttl: 300,
  },
} as const;

const REQUIRED_TABLES = [
  "nodes",
  "node_profiles",
  "enroll_tokens",
  "certificate_bundles",
  "node_certificate_bundles",
  "iperf_sessions",
  "rate_limits",
  "download_links",
  "operation_audit",
  "audit_logs",
  "admin_users",
  "admin_sessions",
  "used_totp_codes",
  "project_settings",
  "runtime_secrets",
  "node_init_tokens",
  "node_tokens",
  "acme_pending_orders",
  "node_events",
] as const;

export interface DatabaseStatus {
  status: "ready" | "empty" | "incompatible";
  table_count: number;
  existing_tables: string[];
  missing_tables: string[];
  /**
   * Migrations that have not been recorded in schema_migrations yet. A
   * database can be "ready" (every required table exists) and still have
   * pending work — readiness is judged by table presence, not by which
   * migrations ran, so a release that adds migrations leaves a ready database
   * with pending upgrades. The admin UI surfaces these and applies them via
   * POST /api/admin/db/init.
   */
  pending_migrations: string[];
}

interface InitBody {
  confirm?: string;
}

export async function handleAdminDatabaseInit(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const body = await readInitBody(request);
  const status = await inspectDatabase(env.DB);

  // An empty database has nothing to protect yet: initialize it without auth
  // (the D1 binding itself is the trust boundary during first-run setup).
  if (status.status === "empty") {
    const next = await initializeDatabase(env.DB);
    workerLog("admin.db.init", { before: status.status, table_count: next.table_count });
    return json({ ok: true, db_status: next });
  }

  // Anything beyond the first-run empty case is admin-only: an authenticated
  // admin session is required before the schema is touched. This includes the
  // ready path, because applying pending migrations IS a schema change.
  const admin = await adminSessionFromRequest(request, env.DB);
  if (!admin) return json({ error: "unauthorized" }, { status: 401 });

  // Always attempt a NON-destructive upgrade, even when the database already
  // looks "ready" (every required table present). Readiness is judged by table
  // presence, not by which migrations have run, so a release that adds new
  // migrations or columns leaves a ready database with pending work that this
  // pass must apply. A migration may remove explicitly retired columns while
  // preserving node rows and the rest of the schema.
  const { applied } = await applyMigrations(env.DB);
  if (applied.length > 0) await ensureDefaultNodeProfile(env.DB);
  const upgraded = await inspectDatabase(env.DB);
  if (upgraded.status === "ready") {
    workerLog("admin.db.init", { before: status.status, upgraded: status.status !== "ready", applied: applied.length, table_count: upgraded.table_count });
    return json({ ok: true, db_status: upgraded, upgraded: status.status !== "ready", applied });
  }

  // The schema is still unrecognizable (tables/columns no migration can
  // reconcile). A destructive reset remains available, but only behind the
  // confirmation phrase (DB_RESET_CONFIRM_PHRASE above), which is
  // deliberately never returned by the API — the operator must already know
  // it out of band.
  if (body.confirm !== DB_RESET_CONFIRM_PHRASE) {
    return json(
      {
        error: "db_init_confirmation_required",
        db_status: upgraded,
        message: "This database does not match the Looking Glass schema and could not be upgraded in place. Confirming will drop existing tables and initialize this project.",
      },
      { status: 409 },
    );
  }
  const next = await initializeDatabase(env.DB, { reset: true });
  workerLog("admin.db.init", { before: status.status, reset: true, table_count: next.table_count });
  return json({ ok: true, db_status: next, reset: true });
}

export async function inspectDatabase(db: SqlDatabase): Promise<DatabaseStatus> {
  const rows = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
    .all<{ name: string }>();
  const existingTables = (rows.results ?? []).map((row) => row.name).filter(isUserTable).sort();
  const missingTables = REQUIRED_TABLES.filter((table) => !existingTables.includes(table));
  const pendingMigrations = await pendingMigrationsFor(db, existingTables);
  if (existingTables.length === 0) {
    return {
      status: "empty",
      table_count: 0,
      existing_tables: [],
      missing_tables: [...REQUIRED_TABLES],
      pending_migrations: pendingMigrations,
    };
  }
  return {
    status: missingTables.length === 0 ? "ready" : "incompatible",
    table_count: existingTables.length,
    existing_tables: existingTables,
    missing_tables: missingTables,
    pending_migrations: pendingMigrations,
  };
}

/**
 * Migrations not yet recorded in schema_migrations. A missing tracking table
 * means nothing has been recorded: every migration is pending (they are all
 * IF NOT EXISTS / guarded, so applying them against an existing schema is a
 * safe no-op). This is what lets a "ready" database still report upgrade work.
 */
async function pendingMigrationsFor(db: SqlDatabase, existingTables: string[]): Promise<string[]> {
  if (!existingTables.includes(SCHEMA_MIGRATIONS_TABLE)) return MIGRATIONS.map((migration) => migration.name);
  try {
    const rows = await db.prepare(`SELECT name FROM ${SCHEMA_MIGRATIONS_TABLE}`).all<{ name: string }>();
    const applied = new Set((rows.results ?? []).map((row) => row.name));
    return MIGRATIONS.filter((migration) => !applied.has(migration.name)).map((migration) => migration.name);
  } catch {
    return [];
  }
}

export function databaseReady(status: DatabaseStatus): boolean {
  return status.status === "ready";
}

export function dbInitRequiredResponse(status: DatabaseStatus): Response {
  return json({ error: "db_init_required", db_status: status }, { status: 409 });
}

export async function initializeDatabase(db: SqlDatabase, options: { reset?: boolean } = {}): Promise<DatabaseStatus> {
  if (options.reset) await dropUserTables(db);
  // Apply every pending migration, each as one atomic batch so a partially-
  // applied migration is never left behind if an intermediate statement fails.
  const { applied } = await applyMigrations(db);
  if (applied.length > 0) await ensureDefaultNodeProfile(db);
  return inspectDatabase(db);
}

/**
 * Bring a database up to the current schema by applying pending migrations.
 *
 * Existing tables and rows are preserved, though a migration may remove an
 * explicitly retired column. Each migration runs in one transaction together
 * with its bookkeeping row, so a failed migration is rolled back and retried
 * on the next start. These properties make re-running safe on databases that
 * predate migration tracking:
 *
 *  - 0001 (and every later baseline) only uses CREATE ... IF NOT EXISTS, so
 *    running it against existing tables is a no-op.
 *  - ALTER TABLE ADD/DROP COLUMN has no IF [NOT] EXISTS in SQLite, so
 *    statements are guarded: columns are added only when missing and dropped
 *    only when present.
 */
export async function applyMigrations(db: SqlDatabase): Promise<{ applied: string[] }> {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS ${SCHEMA_MIGRATIONS_TABLE} (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`,
    )
    .run();
  const appliedRows = await db
    .prepare(`SELECT name FROM ${SCHEMA_MIGRATIONS_TABLE}`)
    .all<{ name: string }>();
  const applied = new Set((appliedRows.results ?? []).map((row) => row.name));

  const newlyApplied: string[] = [];
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.name)) continue;
    const statements: SqlStatement[] = [];
    for (const raw of splitSqlStatements(migration.sql)) {
      const statement = await guardedStatement(db, compactSqlStatement(raw));
      if (statement) statements.push(statement);
    }
    statements.push(
      db
        .prepare(`INSERT INTO ${SCHEMA_MIGRATIONS_TABLE} (name, applied_at) VALUES (?, ?)`)
        .bind(migration.name, Math.floor(Date.now() / 1000)),
    );
    await db.batch(statements);
    newlyApplied.push(migration.name);
  }
  return { applied: newlyApplied };
}

/**
 * Prepare one migration statement, or null when a guarded ALTER is already
 * satisfied by the current schema.
 */
async function guardedStatement(db: SqlDatabase, statement: string): Promise<SqlStatement | null> {
  const addColumn = /^ALTER\s+TABLE\s+("[^"]+"|\w+)\s+ADD\s+COLUMN\s+("[^"]+"|\w+)/i.exec(statement);
  if (addColumn) {
    if (await columnExists(db, addColumn[1], addColumn[2])) return null;
    return db.prepare(statement);
  }
  const dropColumn = /^ALTER\s+TABLE\s+("[^"]+"|\w+)\s+DROP\s+COLUMN\s+("[^"]+"|\w+)/i.exec(statement);
  if (dropColumn && !(await columnExists(db, dropColumn[1], dropColumn[2]))) return null;
  return db.prepare(statement);
}

async function columnExists(db: SqlDatabase, table: string, column: string): Promise<boolean> {
  try {
    await db.prepare(`SELECT ${column} FROM ${table} LIMIT 1`).first();
    return true;
  } catch {
    // An unknown column is exactly the "missing" case; the ALTER runs.
    return false;
  }
}

export async function ensureDefaultNodeProfile(db: SqlDatabase): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      `INSERT OR IGNORE INTO node_profiles (id, name, config_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind("default", "Default profile", JSON.stringify(DEFAULT_NODE_PROFILE), now, now)
    .run();
}

async function dropUserTables(db: SqlDatabase): Promise<void> {
  // Drop only the tables this schema owns: operator tables unrelated to
  // Looking Glass (and Cloudflare-internal ones like _cf_KV) must survive a
  // destructive reset. schema_migrations is included so a reset also forgets
  // which migrations ran — otherwise a re-initialized database would skip them.
  const owned = [...REQUIRED_TABLES, SCHEMA_MIGRATIONS_TABLE];
  await db.batch(owned.map((table) => db.prepare(`DROP TABLE IF EXISTS ${quoteSqliteIdentifier(table)}`)));
}

function quoteSqliteIdentifier(value: string): string {
  return `"${value.replaceAll("\"", "\"\"")}"`;
}

function isUserTable(name: unknown): name is string {
  return typeof name === "string" && !name.startsWith("sqlite_") && !name.startsWith("_cf_");
}

export function splitSqlStatements(sql: string): string[] {
  const statements: string[] = [];
  let start = 0;
  let quote: "'" | "\"" | "`" | null = null;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < sql.length; index++) {
    const char = sql[index];
    const next = sql[index + 1];

    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (char === quote) {
        if (next === quote) {
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (char === "-" && next === "-") {
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      index += 1;
      continue;
    }
    if (char === "'" || char === "\"" || char === "`") {
      quote = char;
      continue;
    }
    if (char === ";") {
      const statement = sql.slice(start, index).trim();
      if (statement) statements.push(statement);
      start = index + 1;
    }
  }
  const tail = sql.slice(start).trim();
  if (tail) statements.push(tail);
  return statements;
}

export function compactSqlStatement(sql: string): string {
  let out = "";
  let quote: "'" | "\"" | "`" | null = null;
  let lineComment = false;
  let blockComment = false;
  let pendingSpace = false;
  for (let index = 0; index < sql.length; index++) {
    const char = sql[index];
    const next = sql[index + 1];

    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (pendingSpace) {
        out += " ";
        pendingSpace = false;
      }
      out += char;
      if (char === quote) {
        if (next === quote) {
          out += next;
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }
    if (char === "-" && next === "-") {
      lineComment = true;
      index += 1;
      pendingSpace = out.length > 0;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      index += 1;
      pendingSpace = out.length > 0;
      continue;
    }
    if (char === "'" || char === "\"" || char === "`") {
      if (pendingSpace) {
        out += " ";
        pendingSpace = false;
      }
      quote = char;
      out += char;
      continue;
    }
    if (/\s/.test(char)) {
      pendingSpace = out.length > 0;
      continue;
    }
    if (pendingSpace) {
      out += " ";
      pendingSpace = false;
    }
    out += char;
  }
  return out.trim();
}

async function readInitBody(request: Request): Promise<InitBody> {
  if (!request.headers.get("content-type")?.includes("application/json")) return {};
  try {
    return (await request.json()) as InitBody;
  } catch {
    return {};
  }
}
