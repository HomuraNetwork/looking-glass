import { describe, expect, it } from "vitest";
import { listNodeEvents, recordAvailability, recordNodeEvent } from "../src/node-events";

interface EventRow {
  id: string;
  node_id: string;
  type: string;
  info: string | null;
  created_at: number;
}

function eventD1(): { db: D1Database; events: EventRow[] } {
  const events: EventRow[] = [];
  const db = {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async run() {
              if (sql.includes("INSERT INTO node_events")) {
                events.push({
                  id: String(values[0]),
                  node_id: String(values[1]),
                  type: String(values[2]),
                  info: values[3] === null ? null : String(values[3]),
                  created_at: Number(values[4]),
                });
                return { success: true, meta: { changes: 1 } };
              }
              return { success: true, meta: { changes: 0 } };
            },
            async first<T>() {
              if (sql.includes("type IN ('up', 'down')")) {
                const match = events
                  .filter((event) => event.node_id === String(values[0]) && (event.type === "up" || event.type === "down"))
                  .sort((a, b) => b.created_at - a.created_at)[0];
                return (match ? { type: match.type, info: match.info } : null) as T | null;
              }
              return null as T | null;
            },
            async all<T>() {
              if (sql.includes("FROM node_events")) {
                const rows = events
                  .filter((event) => event.node_id === String(values[0]))
                  .sort((a, b) => b.created_at - a.created_at)
                  .slice(0, Number(values[1]));
                return { results: rows as T[], success: true };
              }
              return { results: [] as T[], success: true };
            },
          };
        },
      };
    },
  } as unknown as D1Database;
  return { db, events };
}

describe("node events", () => {
  it("records edge events with info", async () => {
    const { db, events } = eventD1();
    await recordNodeEvent(db, { nodeID: "n1", type: "cert_applied", info: "expires_at=2030-01-01 fingerprint=ab:cd", now: 100 });
    await recordNodeEvent(db, { nodeID: "n1", type: "agent_started", info: "0.4.0", now: 101 });
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({ node_id: "n1", type: "cert_applied", created_at: 100 });
    expect(events[0].info).toContain("expires_at=2030-01-01");
  });

  it("writes an availability flip only when the state actually changes", async () => {
    const { db, events } = eventD1();
    // First observation down -> recorded.
    expect(await recordAvailability(db, "n1", false, "timeout", 10)).toBe(true);
    // Still down with the same reason -> not repeated.
    expect(await recordAvailability(db, "n1", false, "timeout", 11)).toBe(false);
    // Recovers -> up.
    expect(await recordAvailability(db, "n1", true, "", 12)).toBe(true);
    // Still up -> not repeated.
    expect(await recordAvailability(db, "n1", true, "", 13)).toBe(false);
    const types = events.filter((event) => event.type === "up" || event.type === "down").map((event) => event.type);
    expect(types).toEqual(["down", "up"]);
    expect(events[0].info).toBe("timeout");
  });

  it("re-records a still-down node when the reason drifts", async () => {
    const { db, events } = eventD1();
    // An agent that stops polling first looks cert_invalid (fresh last_seen)
    // and later agent_offline (stale last_seen). The UI needs the newer reason,
    // so a reason change must write even though the state is still "down".
    expect(await recordAvailability(db, "n1", false, "cert_invalid", 10)).toBe(true);
    expect(await recordAvailability(db, "n1", false, "agent_offline", 11)).toBe(true);
    const downs = events.filter((event) => event.type === "down");
    expect(downs.map((event) => event.info)).toEqual(["cert_invalid", "agent_offline"]);
  });

  it("lists recent events newest first", async () => {
    const { db } = eventD1();
    await recordNodeEvent(db, { nodeID: "n1", type: "down", info: "a", now: 1 });
    await recordNodeEvent(db, { nodeID: "n1", type: "up", info: "b", now: 2 });
    await recordNodeEvent(db, { nodeID: "n2", type: "down", info: "other", now: 3 });
    const rows = await listNodeEvents(db, "n1");
    expect(rows.map((row) => row.type)).toEqual(["up", "down"]);
  });

  it("is a no-op without a database", async () => {
    expect(await recordAvailability(undefined, "n1", false, "x", 1)).toBe(false);
    await expect(recordNodeEvent(undefined, { nodeID: "n1", type: "up" })).resolves.toBeUndefined();
  });
});
