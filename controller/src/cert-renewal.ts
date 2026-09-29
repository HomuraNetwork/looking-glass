import type { Env } from "./config";
import { listAdminNodes } from "./db";
import { activeManagedCertificateBundles, certificateDomainsMatch } from "./certificates";
import { recordNodeEvent } from "./node-events";
import { triggerNodeSync } from "./node-trigger";
import { workerLog, workerWarn } from "./log";
import type { SqlDatabase } from "./runtime";

/**
 * How many times (per cron pass series) the controller nudges a node whose
 * certificate is close to expiring, and how far ahead renewal starts. The
 * controller only records a nudge — the agent still pulls on its own schedule —
 * so these bound log noise and alerting, not correctness.
 */
export const CERT_NUDGE_MAX_ATTEMPTS = 6;
/** Start nudging when a node's certificate has this much validity left. */
export const CERT_NUDGE_WINDOW_SECONDS = 7 * 24 * 60 * 60;

export interface CertNudgeResult {
  checked: number;
  nudged: number;
  failed: number;
}

/**
 * Nudge nodes whose certificate is nearing expiry so they pick up a renewed
 * bundle promptly rather than waiting for the healthy poll interval. Attempts
 * are counted via cert_nudge events; after CERT_NUDGE_MAX_ATTEMPTS within the
 * window a node is reported as an alert instead of nudged again.
 */
export async function nudgeExpiringCertificateNodes(env: Env, now = Math.floor(Date.now() / 1000)): Promise<CertNudgeResult> {
  if (!env.DB) return { checked: 0, nudged: 0, failed: 0 };
  const bundles = await activeManagedCertificateBundles(env.DB);
  if (bundles.length === 0) return { checked: 0, nudged: 0, failed: 0 };

  const nodes = await listAdminNodes(env.DB);
  let checked = 0;
  let nudged = 0;
  let failed = 0;
  for (const node of nodes) {
    const match = bundles.find((bundle) => certificateDomainsMatch(bundle.domains, node.domain));
    if (!match) continue;
    if (match.cert_expires_at - now > CERT_NUDGE_WINDOW_SECONDS) continue;
    checked += 1;

    const attempts = await recentNudgeCount(env.DB, node.internal_id, now - CERT_NUDGE_WINDOW_SECONDS);
    if (attempts >= CERT_NUDGE_MAX_ATTEMPTS) {
      workerWarn("cert.nudge_exhausted", { node: node.internal_id, attempts });
      continue;
    }
    const result = await triggerNodeSync(env, node);
    if (result.ok) {
      nudged += 1;
      await recordNodeEvent(env.DB, { nodeID: node.internal_id, type: "cert_nudge", info: match.id, now });
    } else {
      failed += 1;
      // A failed nudge still counts toward the attempt budget so a persistently
      // unreachable node escalates instead of being retried forever.
      await recordNodeEvent(env.DB, { nodeID: node.internal_id, type: "cert_nudge", info: `failed:${result.error ?? "unknown"}`, now });
    }
  }
  if (checked > 0) workerLog("cert.nudge_complete", { checked, nudged, failed });
  return { checked, nudged, failed };
}

async function recentNudgeCount(db: SqlDatabase, nodeID: string, since: number): Promise<number> {
  const row = await db
    .prepare("SELECT COUNT(*) AS count FROM node_events WHERE node_id = ? AND type = 'cert_nudge' AND created_at >= ?")
    .bind(nodeID, since)
    .first<{ count: number }>();
  return row?.count ?? 0;
}
