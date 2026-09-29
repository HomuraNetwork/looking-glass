import { Env } from "./config";
import { getAdminNode, PublicNode } from "./db";
import { deleteDNSRecord, upsertDNSRecord } from "./dns";
import { workerWarn } from "./log";
import { getStringProjectSetting } from "./project-settings";
import { getRuntimeSecret } from "./runtime-secrets";
import { isIPAddress } from "./ip-guard";

export interface NodeIPReport {
  publicIPv4?: string;
  publicIPv6?: string;
  syncDNS?: boolean;
}

export interface NodeIPSyncResult {
  node: PublicNode;
  changed: boolean;
  dns?: {
    records: Array<{ type: "A" | "AAAA"; name: string; content: string; action: string }>;
    deleted: Array<{ type: "A" | "AAAA"; name: string; action: string }>;
  };
}

export async function syncNodePublicIPs(env: Env, nodeID: string, report: NodeIPReport = {}): Promise<NodeIPSyncResult | null> {
  if (!env.DB) return null;
  const current = await getAdminNode(env.DB, nodeID);
  if (!current) return null;
  const internalNodeID = current.internal_id;

  // Optimistic concurrency: the UPDATE only applies when the stored IPs still
  // match the state this report was computed from (IS handles NULLs). A
  // concurrent report that already moved the state re-runs resolveReportedIP
  // once so both reports converge instead of the last writer blindly clobbering.
  let node = current;
  let changed = false;
  for (let attempt = 0; attempt < 2; attempt++) {
    const nextIPv4 = resolveReportedIP(node.public_ipv4 ?? "", report.publicIPv4, node.dynamic_ip);
    const nextIPv6 = resolveReportedIP(node.public_ipv6 ?? "", report.publicIPv6, node.dynamic_ip);
    if (nextIPv4 === (node.public_ipv4 ?? "") && nextIPv6 === (node.public_ipv6 ?? "")) break;
    const result = await env.DB.prepare(
      `UPDATE nodes
       SET public_ipv4 = ?,
           public_ipv6 = ?,
           config_version = config_version + 1,
           updated_at = ?
       WHERE id = ?
         AND public_ipv4 IS ?
         AND public_ipv6 IS ?`,
    )
      .bind(
        nextIPv4 || null,
        nextIPv6 || null,
        Math.floor(Date.now() / 1000),
        internalNodeID,
        node.public_ipv4 ?? null,
        node.public_ipv6 ?? null,
      )
      .run();
    if ((result.meta?.changes ?? 0) > 0) {
      changed = true;
      node = (await getAdminNode(env.DB, internalNodeID)) ?? node;
      break;
    }
    const reread = await getAdminNode(env.DB, internalNodeID);
    if (!reread) {
      node = current;
      changed = false;
      break;
    }
    node = reread;
  }

  let dns: NodeIPSyncResult["dns"];
  if (report.syncDNS !== false && changed) {
    try {
      dns = await syncNodeDNS(env, node, current) ?? undefined;
    } catch (error) {
      workerWarn("dns.sync_failed", { node: internalNodeID, error: error instanceof Error ? error.message : String(error) });
      dns = undefined;
    }
  }
  return { node, changed, ...(dns ? { dns } : {}) };
}

export async function syncNodeDNS(
  env: Env,
  node: Pick<PublicNode, "domain" | "domain_v4" | "domain_v6" | "public_ipv4" | "public_ipv6">,
  oldNode: Pick<PublicNode, "domain" | "domain_v4" | "domain_v6" | "public_ipv4" | "public_ipv6"> | null,
): Promise<{ records: Array<{ type: "A" | "AAAA"; name: string; content: string; action: string }>; deleted: Array<{ type: "A" | "AAAA"; name: string; action: string }> } | null> {
  const credentials = await dnsCredentials(env);
  if (!credentials) return null;

  const desired = recordsFromSavedNode(node);
  const records: Array<{ type: "A" | "AAAA"; name: string; content: string; action: string }> = [];
  for (const record of desired) {
    records.push(await upsertDNSRecord(credentials.token, credentials.zoneID, record) as { type: "A" | "AAAA"; name: string; content: string; action: string });
  }

  const desiredKeys = new Set(desired.map(dnsRecordKey));
  const stale = oldNode ? recordsFromSavedNode(oldNode).filter((record) => !desiredKeys.has(dnsRecordKey(record))) : [];
  const deleted: Array<{ type: "A" | "AAAA"; name: string; action: string }> = [];
  for (const record of stale) {
    deleted.push(...(await deleteDNSRecord(credentials.token, credentials.zoneID, record)) as Array<{ type: "A" | "AAAA"; name: string; action: string }>);
  }

  return { records, deleted };
}

function recordsFromSavedNode(node: Pick<PublicNode, "domain" | "domain_v4" | "domain_v6" | "public_ipv4" | "public_ipv6">): Array<{ type: "A" | "AAAA"; name: string; content: string }> {
  const records: Array<{ type: "A" | "AAAA"; name: string; content: string }> = [];
  if (node.public_ipv4) {
    records.push({ type: "A", name: node.domain, content: node.public_ipv4 });
    if (node.domain_v4) records.push({ type: "A", name: node.domain_v4, content: node.public_ipv4 });
  }
  if (node.public_ipv6) {
    records.push({ type: "AAAA", name: node.domain, content: node.public_ipv6 });
    if (node.domain_v6) records.push({ type: "AAAA", name: node.domain_v6, content: node.public_ipv6 });
  }
  return records;
}

function dnsRecordKey(record: Pick<{ type: "A" | "AAAA"; name: string }, "type" | "name">): string {
  return `${record.type}:${record.name}`;
}

async function dnsCredentials(env: Env): Promise<{ token: string; zoneID: string } | null> {
  const token = await getRuntimeSecret(env.DB, "CLOUDFLARE_DNSUPDATE_API_KEY");
  const zoneID = await getStringProjectSetting(env.DB, "CLOUDFLARE_ZONE_ID");
  if (!token || !zoneID) return null;
  return { token, zoneID };
}

function resolveReportedIP(current: string, reported: string | undefined, dynamicIP: boolean): string {
  const next = normalizeIP(reported);
  if (!next) return current;
  if (!current) return next;
  return dynamicIP && current !== next ? next : current;
}

function normalizeIP(value?: string): string {
  const trimmed = value?.trim() || "";
  if (!trimmed) return "";
  const normalized = trimmed.toLowerCase();
  return isValidNodeIP(normalized) ? normalized : "";
}

export function isValidNodeIP(value: string): boolean {
  return isIPAddress(value);
}
