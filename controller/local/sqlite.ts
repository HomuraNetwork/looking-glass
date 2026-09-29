import type { SqlDatabase, SqlResult, SqlStatement } from "../src/runtime";

/**
 * A SqlDatabase backed by Node's built-in `node:sqlite` (DatabaseSync).
 *
 * node:sqlite is synchronous, so every call resolves immediately — wrapping it
 * in promises keeps the SqlDatabase contract identical to D1's. Adapter details
 * that matter:
 *
 *  - prepare() is LAZY. node:sqlite validates SQL at prepare() time, so a
 *    `CREATE INDEX ... ON <table>` prepared before its table exists would throw
 *    immediately. D1 prepares lazily, and callers (e.g. initializeDatabase)
 *    rely on that when they build a batch of statements before running any of
 *    them. We therefore defer the real prepare until execution.
 *  - node:sqlite rejects `undefined` and `boolean` bind values; D1 coerces
 *    them. We normalize: `undefined` -> null, `boolean` -> 0/1.
 *  - node:sqlite has no batch(); D1's batch runs statements in an implicit
 *    transaction, so we reproduce that with BEGIN/COMMIT (ROLLBACK on error).
 */
interface SyncStatement {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get(...params: unknown[]): Record<string, unknown> | undefined;
  all(...params: unknown[]): Array<Record<string, unknown>>;
}

interface SyncDatabase {
  prepare(sql: string): SyncStatement;
  exec(sql: string): void;
  close(): void;
}

export interface NodeSqliteOptions {
  /** Database file path, or ":memory:" for an ephemeral database. */
  path: string;
}

export function createNodeSqliteDatabase(options: NodeSqliteOptions): SqlDatabase {
  // Loaded lazily so importing this module never hard-fails on a Node without
  // node:sqlite; the error surfaces where the database is actually created.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { DatabaseSync } = require("node:sqlite") as { DatabaseSync: new (path: string) => SyncDatabase };
  return wrapSqliteDatabase(new DatabaseSync(options.path));
}

/**
 * Adapt a node:sqlite database to the runtime's SqlDatabase contract.
 *
 * node:sqlite is synchronous, but every await in the core is a chance for
 * another request handler to run. Two concurrent batches would interleave
 * BEGIN/COMMIT/ROLLBACK statements on the shared connection (nested-
 * transaction errors, or a failed batch rolling back writes another caller
 * already saw confirmed), and a lone write sneaking between a batch's
 * statements would join its transaction. So every operation goes through a
 * write-ahead queue: batches execute atomically inside one queued job, and
 * statements run inside a batch use a raw fast-path that bypasses the queue.
 */
export function wrapSqliteDatabase(db: SyncDatabase): SqlDatabase {
  let tail: Promise<unknown> = Promise.resolve();
  function enqueue<T>(job: () => Promise<T>): Promise<T> {
    const run = () => job();
    const next = tail.then(run, run);
    tail = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  return {
    prepare(query: string): SqlStatement {
      // Defer the real prepare; see the module comment on lazy preparation.
      return makeStatement(() => db.prepare(query), [], enqueue);
    },
    async batch<T = unknown>(statements: SqlStatement[]): Promise<SqlResult<T>[]> {
      return enqueue(async () => {
        const results: SqlResult<T>[] = [];
        db.exec("BEGIN");
        try {
          for (const statement of statements) {
            results.push((await rawRun(statement)) as SqlResult<T>);
          }
          db.exec("COMMIT");
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
        return results;
      });
    },
  };
}

/**
 * Execute a statement outside the queue. Only valid inside a queued job (the
 * batch loop), where the transaction is already owned by this job.
 */
function rawRun(statement: SqlStatement): Promise<SqlResult<unknown>> {
  const raw = (statement as { __rawRun?: () => Promise<SqlResult<unknown>> }).__rawRun;
  if (!raw) throw new Error("batch statements must come from the same runtime adapter");
  return raw();
}

function makeStatement(
  getStatement: () => SyncStatement,
  boundValues: unknown[],
  enqueue: <T>(job: () => Promise<T>) => Promise<T>,
): SqlStatement {
  const args = () => normalizeBindings(boundValues);
  const rawFirst = async <T = Record<string, unknown>>(): Promise<T | null> => {
    const row = getStatement().get(...args());
    return (row ?? null) as T | null;
  };
  const rawAll = async <T = Record<string, unknown>>(): Promise<SqlResult<T>> => ({
    success: true,
    results: getStatement().all(...args()) as T[],
    meta: {},
  });
  const rawRunStatement = async <T = Record<string, unknown>>(): Promise<SqlResult<T>> => {
    const result = getStatement().run(...args());
    return {
      success: true,
      results: [] as T[],
      meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) },
    };
  };
  // __rawRun is the queue-bypassing fast path batch() uses for its own
  // statements; it is not part of the public SqlStatement contract.
  const statement: SqlStatement & { __rawRun: () => Promise<SqlResult<unknown>> } = {
    bind(...values: unknown[]): SqlStatement {
      // Binding replaces (not appends) previously bound values, matching D1.
      return makeStatement(getStatement, values, enqueue);
    },
    first<T = Record<string, unknown>>(): Promise<T | null> {
      return enqueue(() => rawFirst<T>());
    },
    all<T = Record<string, unknown>>(): Promise<SqlResult<T>> {
      return enqueue(() => rawAll<T>());
    },
    run<T = Record<string, unknown>>(): Promise<SqlResult<T>> {
      return enqueue(() => rawRunStatement<T>());
    },
    __rawRun: () => rawRunStatement(),
  };
  return statement;
}

function normalizeBindings(values: unknown[]): unknown[] {
  return values.map((value) => {
    if (value === undefined) return null;
    if (typeof value === "boolean") return value ? 1 : 0;
    return value;
  });
}
