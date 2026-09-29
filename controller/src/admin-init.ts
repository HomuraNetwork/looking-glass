import { requireAdmin } from "./admin-auth";
import { Env } from "./config";
import { upsertNode } from "./db";
import { nodeDomainsFromBases } from "./dns";
import { getDNSSettings } from "./dns-settings";
import { json, readJSON } from "./http";
import { workerWarn } from "./log";
import { syncNodeDNS } from "./node-ip";

interface AdminNodeInitRequest {
  node_id?: string;
  display_name?: string;
  display_label?: string;
  public_ipv4?: string;
  public_ipv6?: string;
  buy_url?: string;
  buy_label?: string;
  dynamic_ip?: boolean;
  profile_id?: string;
  prefix?: string;
  single_base?: boolean;
  features?: string[];
}

export async function handleAdminNodeInit(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<AdminNodeInitRequest>(request);
  const nodeID = body.node_id?.trim().toLowerCase() || "";
  if (!nodeID || !body.display_name) {
    return json({ error: "node_init_required" }, { status: 400 });
  }
  const settings = await getDNSSettings(env.DB);
  if (!settings) return json({ error: "dns_settings_required" }, { status: 503 });

  const domains = nodeDomainsFromBases({
    nodeID,
    base: settings.base,
    v4Base: settings.v4_base,
    v6Base: settings.v6_base,
    singleBase: body.single_base ?? settings.single_base,
    prefix: body.prefix,
  });
  const node = {
    id: nodeID,
    domain: domains.domain,
    domain_v4: domains.domain_v4,
    domain_v6: domains.domain_v6,
    display_name: body.display_name,
    display_label: body.display_label || "",
    public_ipv4: body.public_ipv4,
    public_ipv6: body.public_ipv6,
    buy_url: body.buy_url || "",
    buy_label: body.buy_label || "",
    dynamic_ip: body.dynamic_ip,
    profile_id: body.profile_id || "default",
    features: body.features,
  };
  const saved = await upsertNode(env.DB, node);
  let dns: Awaited<ReturnType<typeof syncNodeDNS>> | undefined;
  if (body.public_ipv4 || body.public_ipv6) {
    try {
      dns = await syncNodeDNS(env, saved, null);
    } catch (error) {
      workerWarn("dns.sync_failed", { node: nodeID, error: error instanceof Error ? error.message : String(error) });
      dns = undefined;
    }
  }
  return json({ node: saved, ...(dns ? { dns } : {}) });
}
