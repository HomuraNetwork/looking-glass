import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { applyMigrations } from "../src/db-bootstrap";
import { listAdminNodes, listNodes, reorderNodes } from "../src/db";
import { wrapSqliteDatabase } from "./sqlite";

async function db() {
  const database = wrapSqliteDatabase(new DatabaseSync(":memory:"));
  await applyMigrations(database);
  return database;
}

async function insertNode(database: Awaited<ReturnType<typeof db>>, id: string, order: number | null = null): Promise<void> {
  await database
    .prepare(
      `INSERT INTO nodes (id, slug, domain, display_name, display_label, profile_id, enabled, hidden, maintenance, dynamic_ip, display_order, agent_public_key, capabilities, created_at, updated_at)
       VALUES (?, ?, ?, ?, '', 'default', 1, 0, 0, 0, ?, 'k', '["ping"]', 0, 0)`,
    )
    .bind(id, id, `${id}.example.com`, id, order)
    .run();
}

const ids = (nodes: Array<{ id: string }>) => nodes.map((node) => node.id);

describe("node display order", () => {
  it("sorts by display_order, with null last and slug as tiebreak", async () => {
    const database = await db();
    await insertNode(database, "b", 2);
    await insertNode(database, "a", 1);
    await insertNode(database, "z", null);
    await insertNode(database, "c", null);
    // Ordered rows first (1,2), then unordered rows in slug order.
    expect(ids(await listAdminNodes(database))).toEqual(["a", "b", "c", "z"]);
    expect(ids(await listNodes(database))).toEqual(["a", "b", "c", "z"]);
  });

  it("reorders by assigning contiguous ranks top-first", async () => {
    const database = await db();
    await insertNode(database, "a", 1);
    await insertNode(database, "b", 2);
    await insertNode(database, "c", 3);
    await reorderNodes(database, ["c", "a", "b"]);
    const nodes = await listAdminNodes(database);
    expect(ids(nodes)).toEqual(["c", "a", "b"]);
    expect(nodes.map((node) => node.display_order)).toEqual([1, 2, 3]);
  });

  it("places previously-unordered nodes when they are included in a reorder", async () => {
    const database = await db();
    await insertNode(database, "a", 1);
    await insertNode(database, "b", null);
    await reorderNodes(database, ["b", "a"]);
    expect(ids(await listAdminNodes(database))).toEqual(["b", "a"]);
  });

  it("leaves nodes not listed in a partial reorder in place", async () => {
    const database = await db();
    await insertNode(database, "a", 1);
    await insertNode(database, "b", 2);
    await insertNode(database, "c", 3);
    // Only reorder two; "c" keeps its rank.
    await reorderNodes(database, ["b", "a"]);
    const nodes = await listAdminNodes(database);
    expect(nodes.find((node) => node.id === "c")?.display_order).toBe(3);
  });
});
