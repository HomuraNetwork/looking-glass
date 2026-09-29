import { describe, expect, it } from "vitest";
import { EXPIRY_GRACE_SECONDS, IPERF_RETENTION_SECONDS, runRetentionCleanup } from "../src/retention";

interface FakeD1 extends D1Database {
  statements: Array<{ sql: string; values: unknown[] }>;
  failSQL: (sql: string) => boolean;
}

function fakeD1(options: { failSQL?: (sql: string) => boolean; changes?: number } = {}): FakeD1 {
  const statements: Array<{ sql: string; values: unknown[] }> = [];
  return {
    statements,
    failSQL: options.failSQL ?? (() => false),
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async run() {
              statements.push({ sql, values });
              if (options.failSQL?.(sql)) throw new Error("boom");
              return { success: true, meta: { changes: options.changes ?? 3 } } as D1Result;
            },
          };
        },
      };
    },
  } as unknown as FakeD1;
}

describe("runRetentionCleanup", () => {
  it("runs a bounded DELETE per retained table with the right cutoffs", async () => {
    const db = fakeD1({ changes: 7 });
    const now = 1_000_000;
    const counts = await runRetentionCleanup(db, now);

    expect(counts).toEqual({
      rate_limits: 7,
      iperf_sessions: 7,
      download_links: 7,
      node_init_tokens: 7,
      operation_audit: 7,
    });
    const bySQL = db.statements.map((statement) => statement.sql);
    expect(bySQL.some((sql) => sql.startsWith("DELETE FROM rate_limits"))).toBe(true);
    expect(bySQL.some((sql) => sql.includes("DELETE FROM iperf_sessions") && sql.includes("status != 'open'") && sql.includes("created_at <"))).toBe(true);
    expect(bySQL.some((sql) => sql.includes("DELETE FROM download_links") && sql.includes("expires_at <"))).toBe(true);
    expect(bySQL.some((sql) => sql.includes("DELETE FROM node_init_tokens") && sql.includes("expires_at <"))).toBe(true);
    expect(bySQL.some((sql) => sql.includes("DELETE FROM operation_audit") && sql.includes("expires_at <"))).toBe(true);
    expect(db.statements.every((statement) => statement.values.length === 1)).toBe(true);

    const byTable = (table: string) => db.statements.find((statement) => statement.sql.includes(`FROM ${table}`))!;
    expect(byTable("rate_limits").values[0]).toBe(now - EXPIRY_GRACE_SECONDS);
    expect(byTable("iperf_sessions").values[0]).toBe(now - IPERF_RETENTION_SECONDS);
    expect(byTable("download_links").values[0]).toBe(now - EXPIRY_GRACE_SECONDS);
    expect(byTable("node_init_tokens").values[0]).toBe(now - EXPIRY_GRACE_SECONDS);
    expect(byTable("operation_audit").values[0]).toBe(now - EXPIRY_GRACE_SECONDS);
  });

  it("keeps open iperf sessions and never deletes them by status", async () => {
    const db = fakeD1();
    await runRetentionCleanup(db, 1_000_000);
    const iperf = db.statements.find((statement) => statement.sql.includes("DELETE FROM iperf_sessions"))!;
    expect(iperf.sql).toContain("status != 'open'");
  });

  it("is non-fatal when a statement fails and still runs the others", async () => {
    const db = fakeD1({ failSQL: (sql) => sql.includes("DELETE FROM iperf_sessions") });
    const counts = await runRetentionCleanup(db, 1_000_000);
    expect(counts.iperf_sessions).toBe(0);
    expect(counts.rate_limits).toBe(3);
    expect(counts.download_links).toBe(3);
    expect(counts.node_init_tokens).toBe(3);
    expect(counts.operation_audit).toBe(3);
    expect(db.statements).toHaveLength(5);
  });

  it("is a no-op without a DB binding", async () => {
    const counts = await runRetentionCleanup(undefined);
    expect(counts).toEqual({
      rate_limits: 0,
      iperf_sessions: 0,
      download_links: 0,
      node_init_tokens: 0,
      operation_audit: 0,
    });
  });
});