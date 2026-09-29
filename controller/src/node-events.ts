import { workerLog } from "./log";
import type { SqlDatabase } from "./runtime";

/**
 * Edge event types recorded for a node. These are written on transitions only
 * (never per poll), so the table stays small and is kept indefinitely.
 *
 * - `up` / `down`        availability flips (info carries the reason)
 * - `agent_started`      agent process announced itself
 * - `cert_applied`       a certificate bundle was applied (info: expiry/fingerprint)
 * - `cert_nudge`         the controller asked the node to pull (info: bundle id)
 */
export type NodeEventType = "up" | "down" | "agent_started" | "cert_applied" | "cert_nudge";

export interface NodeEventInput {
  nodeID: string;
  type: NodeEventType;
  info?: string;
  now?: number;
}

function eventID(): string {
  return `evt_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
}

/** Append one edge event. Best-effort: a logging failure must never break a request. */
export async function recordNodeEvent(db: SqlDatabase | undefined, input: NodeEventInput): Promise<void> {
  if (!db) return;
  try {
    await db
      .prepare("INSERT INTO node_events (id, node_id, type, info, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(eventID(), input.nodeID, input.type, input.info ?? null, input.now ?? Math.floor(Date.now() / 1000))
      .run();
  } catch (error) {
    workerLog("node_events.write_failed", { node: input.nodeID, type: input.type, error: error instanceof Error ? error.message : String(error) });
  }
}

export interface NodeEventRow {
  id: string;
  node_id: string;
  type: string;
  info: string | null;
  created_at: number;
}

/** List recent events for a node, newest first. */
export async function listNodeEvents(db: SqlDatabase, nodeID: string, limit = 50): Promise<NodeEventRow[]> {
  const rows = await db
    .prepare("SELECT id, node_id, type, info, created_at FROM node_events WHERE node_id = ? ORDER BY created_at DESC LIMIT ?")
    .bind(nodeID, limit)
    .all<NodeEventRow>();
  return rows.results ?? [];
}

export interface NodeAvailabilityState {
  available: boolean;
  /** Reason for the last transition (e.g. cert_invalid, agent_offline). */
  reason: string;
  at: number;
}

/**
 * Latest up/down state per node, batched (no N+1). A node with no up/down event
 * yet is absent from the map — the UI shows "unknown" rather than guessing.
 */
export async function latestAvailabilityByNode(
  db: SqlDatabase,
  nodeIDs: string[],
): Promise<Map<string, NodeAvailabilityState>> {
  const states = new Map<string, NodeAvailabilityState>();
  const unique = [...new Set(nodeIDs)].filter(Boolean);
  // D1 caps bound parameters at 100; no extra parameters in this query.
  for (let offset = 0; offset < unique.length; offset += 100) {
    const batch = unique.slice(offset, offset + 100);
    const placeholders = batch.map(() => "?").join(",");
    const rows = await db
      .prepare(
        `SELECT node_id, type, info, created_at FROM node_events
         WHERE node_id IN (${placeholders}) AND type IN ('up', 'down')
         ORDER BY created_at ASC`,
      )
      .bind(...batch)
      .all<{ node_id: string; type: string; info: string | null; created_at: number }>();
    // Ascending order: later rows overwrite earlier ones, leaving the latest.
    for (const row of rows.results ?? []) {
      states.set(row.node_id, {
        available: row.type === "up",
        reason: row.info ?? "",
        at: row.created_at,
      });
    }
  }
  return states;
}

/**
 * Record an availability observation, writing an event only when the state or
 * the reason actually changes. Callers pass the observed state; the previous
 * state/reason are derived from the most recent up/down event so no extra
 * column is needed on `nodes`. Updating on a reason change (not just a flip)
 * matters because the reason drifts while a node stays down: an agent that
 * stops polling first looks like "cert_invalid" (fresh last_seen) and later
 * "agent_offline" (stale last_seen). Without this the UI would show the stale
 * first reason forever.
 */
export async function recordAvailability(db: SqlDatabase | undefined, nodeID: string, available: boolean, reason: string, now?: number): Promise<boolean> {
  if (!db) return false;
  const at = now ?? Math.floor(Date.now() / 1000);
  const last = await db
    .prepare("SELECT type, info FROM node_events WHERE node_id = ? AND type IN ('up', 'down') ORDER BY created_at DESC LIMIT 1")
    .bind(nodeID)
    .first<{ type: string; info: string | null }>();
  const current = last?.type === "up" ? true : last?.type === "down" ? false : null;
  if (current === available && (last?.info ?? "") === reason) return false;
  await recordNodeEvent(db, { nodeID, type: available ? "up" : "down", info: reason, now: at });
  return true;
}
