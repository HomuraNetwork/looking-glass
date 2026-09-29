import { describe, expect, it, vi } from "vitest";
import { AGENT_FRESH_WINDOW_SECONDS, probeNodeAvailability, reportNodeUnavailable, sweepStaleNodes } from "../src/availability";
import type { Env } from "../src/config";

interface NodeRow {
  id: string;
  domain: string;
  enabled: number;
  hidden: number;
  last_seen_at: number | null;
}

interface EventRow {
  node_id: string;
  type: string;
  info: string | null;
  created_at: number;
}

function availabilityD1(nodes: NodeRow[], events: EventRow[] = [], settings: Record<string, string> = {}) {
  const nodeRows = () =>
    nodes.map((n) => ({
      id: n.id,
      slug: n.id,
      domain: n.domain,
      domain_v4: null,
      domain_v6: null,
      display_name: n.id,
      display_label: null,
      public_ipv4: null,
      public_ipv6: null,
      description: null,
      buy_url: null,
      buy_label: null,
      bgp_url: null,
      profile_id: "default",
      capabilities: null,
      maintenance: 0,
      dynamic_ip: 0,
      enabled: n.enabled,
      hidden: n.hidden,
      config_version: 1,
      version: null,
      created_at: 0,
      updated_at: 0,
      last_seen_at: n.last_seen_at,
    }));
  const db = {
    prepare(sql: string) {
      const self = {
        async all<T>() {
          if (sql.includes("FROM nodes") && sql.includes("last_seen_at <")) {
            const threshold = Number((arguments as unknown as unknown[])[0]);
            const rows = nodes
              .filter((n) => n.enabled === 1 && n.hidden === 0 && n.last_seen_at !== null && n.last_seen_at < threshold)
              .map((n) => ({ id: n.id }));
            return { results: rows as T[], success: true };
          }
          if (sql.includes("FROM nodes")) {
            return { results: nodeRows() as T[], success: true };
          }
          return { results: [] as T[], success: true };
        },
        async first<T>() {
          return null as T | null;
        },
        async run() {
          return { success: true, meta: { changes: 1 } };
        },
        bind(...values: unknown[]) {
          return {
            async first<T>() {
              if (sql.includes("FROM nodes") && sql.includes("last_seen_at")) {
                const node = nodes.find((n) => n.id === String(values[0]));
                return (node ? { last_seen_at: node.last_seen_at } : null) as T | null;
              }
              if (sql.includes("FROM project_settings")) {
                const value = settings[String(values[0])];
                return (value ? { value_json: value } : null) as T | null;
              }
              if (sql.includes("type IN ('up', 'down')")) {
                const lastEvent = events
                  .filter((e) => e.node_id === String(values[0]) && (e.type === "up" || e.type === "down"))
                  .sort((a, b) => b.created_at - a.created_at)[0];
                return (lastEvent ? { type: lastEvent.type } : null) as T | null;
              }
              return null as T | null;
            },
            async all<T>() {
              if (sql.includes("FROM nodes") && sql.includes("last_seen_at <")) {
                const threshold = Number(values[0]);
                const rows = nodes
                  .filter((n) => n.enabled === 1 && n.hidden === 0 && n.last_seen_at !== null && n.last_seen_at < threshold)
                  .map((n) => ({ id: n.id }));
                return { results: rows as T[], success: true };
              }
              return { results: [] as T[], success: true };
            },
            async run() {
              if (sql.includes("INSERT INTO node_events")) {
                events.push({
                  node_id: String(values[1]),
                  type: String(values[2]),
                  info: values[3] === null ? null : String(values[3]),
                  created_at: Number(values[4]),
                });
              }
              return { success: true, meta: { changes: 1 } };
            },
          };
        },
      };
      return self as unknown;
    },
  } as unknown as D1Database;
  return { db, nodes, events, settings };
}

function envWith(db: D1Database): Env {
  return { DB: db } as unknown as Env;
}

const NOW = 1_800_000_000;

describe("availability probe", () => {
  it("marks reachable nodes up and unreachable-fresh nodes down as cert_invalid", async () => {
    const { db, events } = availabilityD1([
      { id: "n1", domain: "n1.test", enabled: 1, hidden: 0, last_seen_at: NOW - 60 },
      { id: "n2", domain: "n2.test", enabled: 1, hidden: 0, last_seen_at: NOW - 5 },
    ]);
    // n1 reachable, n2 unreachable (but seen recently -> cert_invalid).
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.includes("n1.test")) return new Response(null, { status: 204 });
        throw new Error("connection refused");
      }),
    );
    try {
      const result = await probeNodeAvailability(envWith(db), NOW);
      expect(result.checked).toBe(2);
      expect(events.find((e) => e.node_id === "n1")?.type).toBe("up");
      const down = events.find((e) => e.node_id === "n2" && e.type === "down");
      expect(down?.info).toBe("cert_invalid");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("classifies a stale last_seen_at as agent_offline", async () => {
    const { db, events } = availabilityD1([
      { id: "n1", domain: "n1.test", enabled: 1, hidden: 0, last_seen_at: NOW - (AGENT_FRESH_WINDOW_SECONDS + 60) },
    ]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("connection refused");
      }),
    );
    try {
      await probeNodeAvailability(envWith(db), NOW);
      expect(events.find((e) => e.type === "down")?.info).toBe("agent_offline");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("records nothing when the availability state does not change", async () => {
    const events: EventRow[] = [{ node_id: "n1", type: "up", info: null, created_at: NOW - 10 }];
    const { db } = availabilityD1([{ id: "n1", domain: "n1.test", enabled: 1, hidden: 0, last_seen_at: NOW }], events);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 204 })),
    );
    try {
      await probeNodeAvailability(envWith(db), NOW);
      expect(events.filter((e) => e.type === "up")).toHaveLength(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("reactive failure records availability without throwing", async () => {
    const { db, events } = availabilityD1([{ id: "n1", domain: "n1.test", enabled: 1, hidden: 0, last_seen_at: NOW - 60 }]);
    await reportNodeUnavailable(envWith(db), "n1", NOW);
    expect(events.find((e) => e.node_id === "n1")?.type).toBe("down");
  });

  it("sweeps nodes whose last_seen_at is stale", async () => {
    const { db, events } = availabilityD1([{ id: "n1", domain: "n1.test", enabled: 1, hidden: 0, last_seen_at: NOW - 3 * 60 * 60 }]);
    const changed = await sweepStaleNodes(envWith(db), NOW);
    expect(changed).toBe(1);
    expect(events.find((e) => e.type === "down")?.info).toBe("agent_offline");
  });
});
