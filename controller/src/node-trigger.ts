import { signedAgentRequest } from "./admin";
import type { Env } from "./config";
import { fetchNode, nodeOrigin } from "./node-transport";
import { workerWarn } from "./log";

/**
 * Ask a node to sync immediately instead of waiting for its periodic poll.
 *
 * This is the "push triggers a pull" mechanism: the worker never sends
 * configuration or certificates directly — it POSTs /_lg/control/cert/reload
 * (admin-signed) and the agent pulls on its own. It only works while the node
 * has a valid certificate; a node without one is unreachable by design and
 * recovers through its own retry loop.
 *
 * Failures are non-fatal and intentionally do NOT mark the node down: a reload
 * miss is usually transient (agent restarting, brief network blip) and
 * availability is tracked by the dedicated probe. Callers may log the result.
 */
export async function triggerNodeSync(
  env: Env,
  node: { internal_id?: string; id: string; domain: string; port?: number },
): Promise<{ ok: boolean; error?: string }> {
  const nodeID = node.internal_id ?? node.id;
  try {
    const request = await signedAgentRequest(env.DB, {
      method: "POST",
      url: `${nodeOrigin(node.domain, node.port)}/_lg/control/cert/reload`,
      path: "/_lg/control/cert/reload",
      nodeID,
      body: "",
    });
    const response = await fetchNode({
      domain: node.domain,
      port: node.port,
      path: "/_lg/control/cert/reload",
      init: request,
    });
    if (!response.ok) {
      return { ok: false, error: `reload_http_${response.status}` };
    }
    return { ok: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : "reload_failed";
    workerWarn("node.trigger_sync_failed", { node: nodeID, error: message });
    return { ok: false, error: message };
  }
}
