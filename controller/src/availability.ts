import type { Env } from "./config";
import { listAdminNodes } from "./db";
import { recordAvailability, recordNodeEvent } from "./node-events";
import { fetchNode } from "./node-transport";
import { getBooleanProjectSetting } from "./project-settings";
import { workerLog } from "./log";
import type { SqlDatabase } from "./runtime";

/**
 * Availability detection.
 *
 * "Available" means the node can actually serve users. A node that is up but
 * has no valid certificate cannot be reached and cannot issue tokens, so it
 * counts as unavailable — the reason distinguishes the two cases for
 * diagnostics only.
 *
 * Two signals feed the same up/down state:
 *  - a periodic probe (worker -> agent /generate_204, HTTPS only), and
 *  - reactive reports from real user-facing failures/successes.
 * State is only written on a flip, so the event table stays small.
 */

/**
 * last_seen_at freshness that still counts as "the agent is running": within
 * this window a probe failure is attributed to a missing/invalid certificate
 * rather than an offline agent.
 */
export const AGENT_FRESH_WINDOW_SECONDS = 10 * 60;

export interface ProbeResult {
  checked: number;
  changed: number;
}

/** Probe every eligible node once and record availability flips. */
export async function probeNodeAvailability(env: Env, now = Math.floor(Date.now() / 1000)): Promise<ProbeResult> {
  if (!env.DB) return { checked: 0, changed: 0 };
  const nodes = (await listAdminNodes(env.DB)).filter((node) => node.enabled && !node.hidden);
  let changed = 0;
  for (const node of nodes) {
    const ok = await probeNode(node.domain, node.port);
    const reason = ok ? "" : await failureReason(env, node.internal_id, now);
    if (await recordAvailability(env.DB, node.internal_id, ok, reason, now)) changed += 1;
  }
  if (changed > 0) workerLog("availability.probe_complete", { checked: nodes.length, changed });
  return { checked: nodes.length, changed };
}

async function probeNode(domain: string, port = 443): Promise<boolean> {
  try {
    const response = await fetchNode({
      domain,
      port,
      path: "/generate_204",
      init: { signal: AbortSignal.timeout(5000) },
    });
    return response.status === 204 || response.status === 200;
  } catch {
    return false;
  }
}

/** Distinguish "alive but unusable" (missing cert) from "agent offline". */
async function failureReason(env: Env, nodeID: string, now: number): Promise<string> {
  const row = await env.DB!.prepare("SELECT last_seen_at FROM nodes WHERE id = ?").bind(nodeID).first<{ last_seen_at: number | null }>();
  const seen = row?.last_seen_at ?? null;
  if (seen !== null && now - seen <= AGENT_FRESH_WINDOW_SECONDS) return "cert_invalid";
  return "agent_offline";
}

/**
 * Reactive availability: a user-facing request to a node failed. Best-effort
 * and never throws into the request path.
 */
export async function reportNodeUnavailable(env: Env, nodeID: string, now = Math.floor(Date.now() / 1000)): Promise<void> {
  if (!env.DB) return;
  try {
    const reason = await failureReason(env, nodeID, now);
    await recordAvailability(env.DB, nodeID, false, reason, now);
  } catch {
    // Availability tracking must never break a request.
  }
}

/** Reactive recovery: a user-facing request to a node succeeded. */
export async function reportNodeAvailable(env: Env, nodeID: string): Promise<void> {
  if (!env.DB) return;
  try {
    await recordAvailability(env.DB, nodeID, true, "");
  } catch {
    // Availability tracking must never break a request.
  }
}

/**
 * Fallback sweep: nodes whose last_seen_at is stale and that are not already
 * marked down are recorded down. This catches nodes the probe could not even
 * attempt (e.g. disabled mid-flight) and keeps state converging if probes are
 * skipped.
 */
export async function sweepStaleNodes(env: Env, now = Math.floor(Date.now() / 1000)): Promise<number> {
  if (!env.DB) return 0;
  const threshold = now - 2 * 60 * 60;
  const rows = await env.DB
    .prepare(
      `SELECT id FROM nodes
       WHERE enabled = 1 AND hidden = 0
         AND last_seen_at IS NOT NULL AND last_seen_at < ?
         AND id NOT IN (SELECT node_id FROM node_events WHERE type = 'down' AND created_at >= last_seen_at)`,
    )
    .bind(threshold)
    .all<{ id: string }>();
  let changed = 0;
  for (const row of rows.results ?? []) {
    await recordNodeEvent(env.DB, { nodeID: row.id, type: "down", info: "agent_offline", now });
    changed += 1;
  }
  return changed;
}

/** Whether periodic probing is enabled (default on). */
export async function availabilityProbeEnabled(db: SqlDatabase | undefined): Promise<boolean> {
  return getBooleanProjectSetting(db, "LG_AVAILABILITY_PROBE");
}
