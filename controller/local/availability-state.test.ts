import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { applyMigrations } from "../src/db-bootstrap";
import { latestAvailabilityByNode, recordAvailability } from "../src/node-events";
import { wrapSqliteDatabase } from "./sqlite";

async function db() {
  const database = wrapSqliteDatabase(new DatabaseSync(":memory:"));
  await applyMigrations(database);
  return database;
}

/**
 * The admin node list shows each node's liveness from these rows. The lookup
 * must return the LATEST up/down per node (not an arbitrary one) so an
 * uninstalled node eventually reads as offline, and must be empty for a node
 * that has never flipped.
 */
describe("latest availability per node", () => {
  it("returns the newest up/down state per node", async () => {
    const database = await db();
    await recordAvailability(database, "n1", false, "agent_offline", 100);
    await recordAvailability(database, "n1", true, "", 200);
    await recordAvailability(database, "n2", false, "cert_invalid", 150);

    const states = await latestAvailabilityByNode(database, ["n1", "n2", "n3"]);
    expect(states.get("n1")).toMatchObject({ available: true, reason: "", at: 200 });
    expect(states.get("n2")).toMatchObject({ available: false, reason: "cert_invalid", at: 150 });
    // A node with no flip is absent, so the UI can show "unknown".
    expect(states.has("n3")).toBe(false);
  });

  it("reflects an uninstalled node going down", async () => {
    const database = await db();
    await recordAvailability(database, "gone", true, "", 100);
    expect((await latestAvailabilityByNode(database, ["gone"])).get("gone")?.available).toBe(true);
    // The agent stops polling; the next probe flips it down.
    await recordAvailability(database, "gone", false, "agent_offline", 9000);
    expect((await latestAvailabilityByNode(database, ["gone"])).get("gone")).toMatchObject({
      available: false,
      reason: "agent_offline",
    });
  });

  it("returns an empty map for no node ids", async () => {
    const database = await db();
    expect((await latestAvailabilityByNode(database, [])).size).toBe(0);
  });
});
