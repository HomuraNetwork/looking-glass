import { Env } from "./config";
import { requireAdmin } from "./admin-auth";
import { deleteNode, getAdminNode, listAdminNodes, NodeUpsert, reorderNodes, upsertNode } from "./db";
import { workerLog } from "./log";
import { importManagedCertificateBundles, listAdminManagedCertificates, nodeCertificateStates, syncManagedCertificatesToNodes } from "./certificates";
import { getDNSSettings, saveDNSSettings } from "./dns-settings";
import { dnsRecordsForNode, nodeDomainsFromBases, upsertDNSRecord } from "./dns";
import { json, methodNotAllowed, readJSON, RequestError } from "./http";
import { activeNodeInitToken, issueNodeInitToken } from "./node-tokens";
import { getAgentInstallConfig, agentReleaseInfo, buildNodeInitPayload } from "./agent-download";
import { fetchNode, nodeOrigin } from "./node-transport";
import { syncNodeDNS } from "./node-ip";
import { latestAvailabilityByNode, listNodeEvents } from "./node-events";
import { reportNodeAvailable, reportNodeUnavailable } from "./availability";
import { triggerNodeSync } from "./node-trigger";
import {
  getBooleanProjectSetting,
  getStringProjectSetting,
  isProjectSettingKey,
  listProjectSettingStatus,
  projectSettingStatus,
  resetProjectSetting,
  setProjectSetting,
} from "./project-settings";
import {
  generateRuntimeSecretValue,
  getRuntimeSecret,
  isRuntimeSecretKey,
  listRuntimeSecretStatus,
  runtimeSecretStatus,
  setRuntimeSecret,
} from "./runtime-secrets";
import {
  ACMERequestError, managedCertificateDomains,
  beginManagedCertificateOrder, finalizeManagedCertificateOrder, cancelManagedCertificateOrder, pendingCertificateOrder,
  withCertificateIssuanceLock,
  requestZeroSSLEABCredentials,
} from "./acme";
import { isSafePublicLink } from "./safe-url";

function validTCPPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535;
}

export async function handleAdminNodes(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  if (request.method === "GET") return json({ nodes: await attachActiveInitTokens(env, await listAdminNodes(env.DB), new URL(request.url).origin) });
  if (request.method === "DELETE") {
    const body = await readJSON<{ id?: string }>(request);
    const id = body.id?.trim() || "";
    if (!id) return json({ error: "id_required" }, { status: 400 });
    const node = await getAdminNode(env.DB, id);
    const deleted = node ? await deleteNode(env.DB, node.internal_id) : false;
    if (!deleted) return json({ error: "node_not_found" }, { status: 404 });
    return json({ deleted: true, id });
  }
  if (request.method !== "POST") return methodNotAllowed();

  const body = await readJSON<Partial<NodeUpsert> & { internal_id?: string; auto_dns?: boolean; dns_mode?: "id" | "prefix" | "full"; dns_prefix?: string }>(request);
  const nodeSlug = body.id?.trim().toLowerCase() || "";
  if (!nodeSlug || !body.domain || !body.display_name) {
    return json({ error: "id_domain_display_name_required" }, { status: 400 });
  }
  if (body.buy_url !== undefined && !isSafePublicLink(body.buy_url)) {
    return json({ error: "invalid_node_action_url" }, { status: 400 });
  }
  if (body.auto_dns === true && !(await dnsCredentials(env))) return json({ error: "dns_config_required" }, { status: 503 });
  const oldNode = await getAdminNode(env.DB, body.internal_id || nodeSlug);
  if (body.port !== undefined && !validTCPPort(body.port)) return json({ error: "invalid_node_port" }, { status: 400 });
  const settings = body.auto_dns === true ? await getDNSSettings(env.DB) : null;
  if (body.auto_dns === true && !settings) return json({ error: "dns_settings_required" }, { status: 503 });
  const generatedDomains =
    body.auto_dns === true && settings
      ? nodeDomainsFromBases({
          nodeID: nodeSlug,
          base: settings.base,
          v4Base: settings.v4_base,
          v6Base: settings.v6_base,
          singleBase: settings.single_base,
          prefix: body.dns_mode === "prefix" ? body.dns_prefix : undefined,
        })
      : null;

  const node = await upsertNode(env.DB, {
    internal_id: oldNode?.internal_id ?? body.internal_id,
    id: nodeSlug,
    domain: generatedDomains?.domain ?? body.domain,
    port: body.port,
    domain_v4: generatedDomains?.domain_v4 ?? body.domain_v4,
    domain_v6: generatedDomains?.domain_v6 ?? body.domain_v6,
    display_name: body.display_name,
    display_label: body.display_label,
    // Only pass IP fields when the request explicitly includes them: the
    // upsert must not wipe agent-detected IPs when the admin edit omits them.
    ...(typeof body.public_ipv4 === "string" ? { public_ipv4: body.public_ipv4 } : {}),
    ...(typeof body.public_ipv6 === "string" ? { public_ipv6: body.public_ipv6 } : {}),
    description: body.description ?? "",
    buy_url: body.buy_url ?? "",
    buy_label: body.buy_label ?? "",
    bgp_url: body.bgp_url ?? "",
    profile_id: body.profile_id ?? "default",
    enabled: body.enabled,
    hidden: body.hidden,
    maintenance: body.maintenance,
    dynamic_ip: body.dynamic_ip,
    ...(typeof body.display_order === "number" || body.display_order === null ? { display_order: body.display_order } : {}),
    features: body.features,
  }).catch((error: unknown) => {
    // UNIQUE violations (slug/domain) are client errors, not crashes.
    if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
      const column = error.message.split("UNIQUE constraint failed:")[1]?.trim() || "";
      throw new RequestError(409, column.includes("slug") ? "node_slug_exists" : "node_domain_exists");
    }
    throw error;
  });
  const saved = (await getAdminNode(env.DB, node.internal_id)) ?? node;
  const dns = body.auto_dns === true ? await syncNodeDNS(env, saved, oldNode) : undefined;
  const init = oldNode ? null : await issueNodeInitToken(env.DB, saved.internal_id);
  const install = init ? await getAgentInstallConfig(env.DB) : null;
  // Nudge the node so a config change takes effect promptly; failures are
  // non-fatal (a node without a valid certificate recovers on its own).
  if (oldNode) void triggerNodeSync(env, saved);
  return json({
    node: { ...saved, active_init: await activeNodeInitToken(env.DB, saved.internal_id) ?? undefined },
    ...(init && install ? { init: { ...init, ...install, ...(await buildNodeInitPayload(env, new URL(request.url).origin, init.token)) } } : {}),
    ...(dns ? { dns } : {}),
  });
}

/**
 * Reorder the node list. Body: { order: string[] } of node ids/slugs, top
 * first. Assigns sequential display_order values and returns the updated list.
 */
export async function handleAdminNodeReorder(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<{ order?: unknown }>(request);
  const order = Array.isArray(body.order) ? body.order.filter((id): id is string => typeof id === "string" && id.trim().length > 0) : [];
  if (order.length === 0) return json({ error: "order_required" }, { status: 400 });
  const changed = await reorderNodes(env.DB, order);
  workerLog("admin.nodes.reordered", { count: order.length, changed });
  return json({ ok: true, changed, nodes: await attachActiveInitTokens(env, await listAdminNodes(env.DB), new URL(request.url).origin) });
}

/**
 * True when a node is not running the build the controller distributes.
 *
 * Ids are opaque (agent-source commit SHAs), so any difference is "outdated";
 * we cannot order them. Two cases must NOT be flagged:
 *  - we do not know our own build (no manifest id / "unknown") — nothing to
 *    compare against;
 *  - the node has never reported a version — it has no agent yet, so there is
 *    nothing to update (a freshly created but unenrolled node).
 *
 * A node that has reported a version but no build id is running an agent from
 * before the build-id feature existed, which is by definition not the current
 * build, so it IS flagged.
 */
export function isAgentOutdated(
  node: { version?: string | null; build_id?: string | null },
  releaseBuild: string | null,
): boolean {
  if (!releaseBuild || releaseBuild === "unknown") return false;
  if (!node.version) return false;
  if (!node.build_id || node.build_id === "unknown") return true;
  return node.build_id !== releaseBuild;
}

export async function attachActiveInitTokens<T extends { id: string; internal_id?: string; build_id?: string | null }>(
  env: Env,
  nodes: T[],
  origin: string,
): Promise<Array<T & {
  active_init?: NonNullable<Awaited<ReturnType<typeof activeNodeInitToken>>> &
    Awaited<ReturnType<typeof getAgentInstallConfig>> &
    Partial<Awaited<ReturnType<typeof buildNodeInitPayload>>>;
}>> {
  const db = env.DB!;
  // One batched lookup instead of one query per node (N+1 before): fetch the
  // newest unconsumed, unexpired init token per node in a single statement.
  const nodeIDs = [...new Set(nodes.map((node) => node.internal_id ?? node.id))].filter(Boolean);
  const active = new Map<string, { node_id: string; token: string; expires_at: number }>();
  // D1 permits at most 100 bound parameters. Keep one slot for expires_at,
  // leaving 99 node IDs per statement at the boundary.
  for (let offset = 0; offset < nodeIDs.length; offset += 99) {
    const batch = nodeIDs.slice(offset, offset + 99);
    const placeholders = batch.map(() => "?").join(",");
    const rows = await db
      .prepare(
        `SELECT node_id, token_value, expires_at
         FROM node_init_tokens
         WHERE node_id IN (${placeholders})
           AND token_value IS NOT NULL
           AND consumed_at IS NULL
           AND expires_at > ?
         ORDER BY created_at DESC`,
      )
      .bind(...batch, Math.floor(Date.now() / 1000))
      .all<{ node_id: string; token_value: string; expires_at: number }>();
    for (const row of rows.results ?? []) {
      if (!row.token_value || active.has(row.node_id)) continue;
      active.set(row.node_id, { node_id: row.node_id, token: row.token_value, expires_at: row.expires_at });
    }
  }
  // Build the pull command server-side (the single source of truth for the
  // install options) so the frontend never has to hardcode binary/service
  // names that would drift from the defaults.
  if (nodes.length === 0) return [];
  const [installDefaults, certStates, availability, release] = await Promise.all([
    getAgentInstallConfig(db),
    nodeCertificateStates(db, nodes.map((node) => node.internal_id ?? node.id)),
    latestAvailabilityByNode(db, nodes.map((node) => node.internal_id ?? node.id)),
    agentReleaseInfo({ ASSETS: env.ASSETS }, origin),
  ]);
  const initPayloads = new Map<string, Awaited<ReturnType<typeof buildNodeInitPayload>>>();
  await Promise.all(nodes.map(async (node) => {
    const key = node.internal_id ?? node.id;
    const match = active.get(key);
    if (match) {
      initPayloads.set(key, await buildNodeInitPayload(env, origin, match.token, release));
    }
  }));
  return nodes.map((node) => {
    const key = node.internal_id ?? node.id;
    const match = active.get(key);
    const initPayload = initPayloads.get(key);
    return {
      ...node,
      certificate: certStates.get(key) ?? null,
      availability: availability.get(key) ?? null,
      update_available: isAgentOutdated(node, release.build_id),
      active_init: match
        ? { ...match, ...installDefaults, ...(initPayload ?? {}) }
        : undefined,
    };
  });
}

export async function handleAdminNodeEvents(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  if (request.method !== "GET") return methodNotAllowed();

  const url = new URL(request.url);
  const nodeID = url.searchParams.get("node")?.trim() || "";
  if (!nodeID) return json({ error: "node_required" }, { status: 400 });
  const node = await getAdminNode(env.DB, nodeID);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });
  const limitRaw = Number(url.searchParams.get("limit") || "50");
  const limit = Number.isFinite(limitRaw) ? Math.min(200, Math.max(1, Math.trunc(limitRaw))) : 50;
  return json({ node_id: node.id, events: await listNodeEvents(env.DB, node.internal_id, limit) });
}

export async function handleAdminNodeInitToken(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });

  const body = await readJSON<{ node_id?: string }>(request);
  const nodeID = body.node_id?.trim() || "";
  if (!nodeID) return json({ error: "node_id_required" }, { status: 400 });

  const node = await getAdminNode(env.DB, nodeID);
  if (!node) return json({ error: "node_not_found" }, { status: 404 });

  const init = await issueNodeInitToken(env.DB, node.internal_id);
  const install = await getAgentInstallConfig(env.DB);
  return json({
    node,
    init: { ...init, ...install, ...(await buildNodeInitPayload(env, new URL(request.url).origin, init.token)) },
  });
}

export async function handleAdminDNSSettings(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (request.method === "GET") return json({ settings: await getDNSSettings(env.DB) });
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<Partial<AdminNodeDNSInput>>(request);
  // In single-base mode the IPv4/IPv6 domains are derived from `base` with
  // -v4/-v6 suffixes, so v4_base/v6_base are irrelevant (the panel disables
  // those inputs). Requiring them there was the bug: the panel submits them
  // empty and every save failed with dns_settings_required.
  const singleBase = body.single_base === true;
  if (!body.base || (!singleBase && (!body.v4_base || !body.v6_base))) {
    return json({ error: "dns_settings_required" }, { status: 400 });
  }
  const settings = await saveDNSSettings(env.DB, {
    base: body.base,
    v4_base: singleBase ? "" : (body.v4_base ?? ""),
    v6_base: singleBase ? "" : (body.v6_base ?? ""),
    single_base: singleBase,
  });
  return json({ settings });
}

export async function handleAdminNodeCheck(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<{ id?: string; domain?: string; port?: number }>(request);
  const node = body.id ? await getAdminNode(env.DB, body.id) : null;
  const domain = (node?.domain || body.domain || "").trim();
  if (!domain) return json({ error: "id_or_domain_required" }, { status: 400 });
  const port = node?.port ?? body.port ?? 443;
  if (!validTCPPort(port)) return json({ error: "invalid_node_port" }, { status: 400 });
  const result = await checkNodeHealth({ env, nodeID: node?.internal_id ?? (body.id?.trim() || ""), domain, port });
  // Feed the result into the persistent availability state so the list badge
  // reflects a manual check immediately, not only after the next cron pass.
  // reportNode* derive the failure reason the same way the probe does.
  if (node) {
    if (result.healthy) await reportNodeAvailable(env, node.internal_id);
    else await reportNodeUnavailable(env, node.internal_id);
  }
  return json(result);
}

interface AdminNodeDNSInput {
  base: string;
  v4_base: string;
  v6_base: string;
  single_base?: boolean;
}

export async function handleAdminNodeDNS(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  const credentials = await dnsCredentials(env);
  if (!credentials) return json({ error: "dns_config_required" }, { status: 503 });
  const body = await readJSON<{
    node_id: string;
    prefix?: string;
    domain?: string;
    domain_v4?: string;
    domain_v6?: string;
    ipv4: string;
    ipv6: string;
  }>(request);
  const nodeID = body.node_id?.trim().toLowerCase() || "";
  if (!nodeID || !body.ipv4 || !body.ipv6) return json({ error: "node_ip_required" }, { status: 400 });
  const settings = await getDNSSettings(env.DB);
  if (!settings) return json({ error: "dns_settings_required" }, { status: 503 });
  const input = {
    nodeID,
    base: settings.base,
    v4Base: settings.v4_base,
    v6Base: settings.v6_base,
    singleBase: settings.single_base,
    prefix: body.prefix,
    domain: body.domain,
    domainV4: body.domain_v4,
    domainV6: body.domain_v6,
  };
  const records = [];
  for (const record of dnsRecordsForNode({ ...input, ipv4: body.ipv4, ipv6: body.ipv6 })) {
    records.push(await upsertDNSRecord(credentials.token, credentials.zoneID, record));
  }
  return json({ domains: nodeDomainsFromBases(input), records });
}

async function dnsCredentials(env: Env): Promise<{ token: string; zoneID: string } | null> {
  const token = await getRuntimeSecret(env.DB, "CLOUDFLARE_DNSUPDATE_API_KEY");
  const zoneID = await getStringProjectSetting(env.DB, "CLOUDFLARE_ZONE_ID");
  if (!token || !zoneID) return null;
  return { token, zoneID };
}

interface NodeCheckResult {
  healthy: boolean;
  domain: string;
  checked_at: number;
  checks: {
    generate_204: EndpointCheck;
    info: EndpointCheck;
  };
}

interface EndpointCheck {
  ok: boolean;
  status?: number;
  duration_ms: number;
  error?: string;
  node?: string;
  domain?: string;
}

export async function checkNodeHealth(input: { env: Env; nodeID: string; domain: string; port?: number }, fetcher?: typeof fetch): Promise<NodeCheckResult> {
  const generate204 = await checkEndpoint(input, "/generate_204", 204, fetcher);
  const info = await checkInfo(input, "/info", fetcher);
  return {
    healthy: generate204.ok && info.ok,
    domain: input.domain,
    checked_at: Math.floor(Date.now() / 1000),
    checks: {
      generate_204: generate204,
      info,
    },
  };
}

async function checkEndpoint(input: { env: Env; nodeID: string; domain: string; port?: number }, path: string, expectedStatus: number, fetcher?: typeof fetch): Promise<EndpointCheck> {
  const started = Date.now();
  try {
    const response = fetcher
      ? await fetcher(new URL(path, nodeOrigin(input.domain, input.port)), { signal: AbortSignal.timeout(5000) })
      : await fetchNode({
          domain: input.domain,
          port: input.port,
          path,
          init: { signal: AbortSignal.timeout(5000) },
        });
    return { ok: response.status === expectedStatus, status: response.status, duration_ms: Date.now() - started };
  } catch (error) {
    return { ok: false, duration_ms: Date.now() - started, error: error instanceof Error ? error.message : "fetch_failed" };
  }
}

async function checkInfo(input: { env: Env; nodeID: string; domain: string; port?: number }, path: string, fetcher?: typeof fetch): Promise<EndpointCheck> {
  const started = Date.now();
  try {
    const response = fetcher
      ? await fetcher(new URL(path, nodeOrigin(input.domain, input.port)), { signal: AbortSignal.timeout(5000) })
      : await fetchNode({
          domain: input.domain,
          port: input.port,
          path,
          init: { signal: AbortSignal.timeout(5000) },
        });
    const payload = response.headers.get("content-type")?.includes("application/json") ? ((await response.json()) as { node?: string; domain?: string }) : {};
    return {
      ok: response.status === 200,
      status: response.status,
      duration_ms: Date.now() - started,
      node: payload.node,
      domain: payload.domain,
    };
  } catch (error) {
    return { ok: false, duration_ms: Date.now() - started, error: error instanceof Error ? error.message : "fetch_failed" };
  }
}

export async function handleAdminRuntimeSecrets(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (request.method === "GET") return json({ secrets: await listRuntimeSecretStatus(env.DB) });
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<{ key?: string; value?: string; reset?: boolean; generate?: boolean; confirm?: string; override?: boolean }>(request);
  if (!body.key || !isRuntimeSecretKey(body.key)) return json({ error: "invalid_secret_key" }, { status: 400 });
  if (body.reset === true) {
    return json({ error: "secret_reset_disabled" }, { status: 400 });
  }
  const current = await runtimeSecretStatus(env.DB, body.key);
  if (current.configured && body.override !== true) return json({ error: "secret_override_required" }, { status: 409 });
  if (body.generate === true) {
    if (body.confirm !== body.key) return json({ error: "generate_confirmation_required" }, { status: 400 });
    try {
      await setRuntimeSecret(env.DB, body.key, await generateRuntimeSecretValue(body.key));
    } catch (error) {
      if (error instanceof Error && error.message === "secret_not_generatable") return json({ error: "secret_not_generatable" }, { status: 400 });
      throw error;
    }
    return json(await runtimeSecretStatus(env.DB, body.key));
  }
  const value = body.value?.trim();
  if (!value) return json({ error: "secret_value_required" }, { status: 400 });
  try {
    await setRuntimeSecret(env.DB, body.key, value);
  } catch (error) {
    if (error instanceof Error && error.message === "secret_value_required") return json({ error: "secret_value_required" }, { status: 400 });
    return json({ error: "invalid_secret_value" }, { status: 400 });
  }
  return json(await runtimeSecretStatus(env.DB, body.key));
}

export async function handleAdminCertificates(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });

  if (request.method === "GET") {
    const dnsSettings = await getDNSSettings(env.DB);
    return json({
      certificates: await listAdminManagedCertificates(env.DB),
      managed_domains: dnsSettings ? managedCertificateDomains(dnsSettings) : [],
      pending_order: await pendingCertificateOrder(env),
    });
  }

  if (request.method !== "POST") return methodNotAllowed();
  const body = await readJSON<{
    action?: string;
    cert_pem?: string;
    key_pem?: string;
    ca_pem?: string;
    cert_expires_at?: number;
    domains?: string[];
    email?: string;
  }>(request);
  if (body.action === "reissue") {
    try {
      const locked = await withCertificateIssuanceLock(env, () => beginManagedCertificateOrder(env, fetch));
      const result = locked.ran ? locked.value : { status: "skipped", reason: "issuance_in_progress" };
      return json(await withCertificateDebug(env, "reissue", result));
    } catch (error) {
      const reason = error instanceof Error ? error.message : "certificate_reissue_failed";
      return json(await withCertificateDebug(env, "reissue", { status: "failed", reason, error: reason }, error), { status: 502 });
    }
  }
  if (body.action === "begin") {
    try {
      // Share the issuance lock with the pull/cron flow so a manual begin
      // cannot race an automatic one into two CA orders.
      const locked = await withCertificateIssuanceLock(env, () => beginManagedCertificateOrder(env, fetch));
      const result = locked.ran ? locked.value : { status: "skipped", reason: "issuance_in_progress" };
      return json(await withCertificateDebug(env, "begin", result));
    } catch (error) {
      const reason = error instanceof Error ? error.message : "certificate_begin_failed";
      return json(await withCertificateDebug(env, "begin", { status: "failed", reason, error: reason }, error), { status: 502 });
    }
  }
  if (body.action === "finalize") {
    try {
      const locked = await withCertificateIssuanceLock(env, () => finalizeManagedCertificateOrder(env, fetch));
      const result = locked.ran ? locked.value : { status: "skipped", reason: "issuance_in_progress" };
      return json(await withCertificateDebug(env, "finalize", result));
    } catch (error) {
      const reason = error instanceof Error ? error.message : "certificate_finalize_failed";
      return json(await withCertificateDebug(env, "finalize", { status: "failed", reason, error: reason }, error), { status: 502 });
    }
  }
  if (body.action === "cancel") {
    return json(await withCertificateDebug(env, "cancel", await cancelManagedCertificateOrder(env)));
  }
  if (body.action === "sync") {
    const result = await syncManagedCertificatesToNodes(env);
    return json(await withCertificateDebug(env, "sync", result));
  }
  if (body.action === "zerossl_eab_register") {
    const provider = await getStringProjectSetting(env.DB, "ACME_PROVIDER");
    if (provider !== "zerossl") return json({ error: "acme_provider_not_zerossl" }, { status: 400 });
    const email = body.email?.trim() || "";
    if (!email) return json({ error: "acme_account_email_required" }, { status: 400 });
    try {
      const result = await requestZeroSSLEABCredentials(email);
      await setProjectSetting(env.DB, "ACME_ACCOUNT_EMAIL", result.email);
      await setProjectSetting(env.DB, "ACME_EAB_KEY_ID", result.keyID);
      await setProjectSetting(env.DB, "ACME_EAB_ALG", result.alg);
      await setRuntimeSecret(env.DB, "ACME_EAB_HMAC_KEY", result.hmacKey);
      return json(await withCertificateDebug(env, "sync", {
        status: "registered",
        provider: "zerossl",
        email: result.email,
        eab_key_id: result.keyID,
        eab_alg: result.alg,
        account_email_setting: await projectSettingStatus(env.DB, "ACME_ACCOUNT_EMAIL"),
        eab_key_id_setting: await projectSettingStatus(env.DB, "ACME_EAB_KEY_ID"),
        eab_alg_setting: await projectSettingStatus(env.DB, "ACME_EAB_ALG"),
        eab_hmac_secret: await runtimeSecretStatus(env.DB, "ACME_EAB_HMAC_KEY"),
      }));
    } catch (error) {
      const reason = error instanceof Error ? error.message : "zerossl_eab_registration_failed";
      return json(
        await withCertificateDebug(env, "sync", { status: "failed", reason, error: reason }, error),
        { status: error instanceof ACMERequestError ? 502 : 400 },
      );
    }
  }
  if (body.action === "import") {
    const dnsSettings = await getDNSSettings(env.DB);
    try {
      const result = await importManagedCertificateBundles(env, body, dnsSettings ? managedCertificateDomains(dnsSettings) : []);
      if (result.status === "imported") await setProjectSetting(env.DB, "ACME_ENABLED", false);
      // Nudge every node so the freshly imported certificate is picked up now.
      if (result.status === "imported") void nudgeAllNodes(env);
      return json(await withCertificateDebug(env, "import", { ...result, acme_enabled: false }));
    } catch (error) {
      const reason = error instanceof Error ? error.message : "certificate_import_failed";
      if (reason === "certificate_pem_required" || reason === "certificate_expiry_required" || reason === "certificate_domains_required") {
        return json(await withCertificateDebug(env, "import", { error: reason }, error), { status: 400 });
      }
      if (reason === "d1_required") return json(await withCertificateDebug(env, "import", { error: reason }, error), { status: 503 });
      throw error;
    }
  }
  return json({ error: "invalid_certificate_action" }, { status: 400 });
}

/** Fire-and-forget nudge to every node (used after a certificate import). */
async function nudgeAllNodes(env: Env): Promise<void> {
  if (!env.DB) return;
  for (const node of await listAdminNodes(env.DB)) {
    if (node.enabled && !node.hidden) void triggerNodeSync(env, node);
  }
}

async function withCertificateDebug<T extends object>(
  env: Env,
  action: "reissue" | "sync" | "import" | "begin" | "finalize" | "cancel",
  result: T,
  error?: unknown,
): Promise<T & { debug?: Record<string, unknown> }> {
  if (!(await certificateDebugEnabled(env))) return result;
  return {
    ...result,
    debug: await certificateDebugPayload(env, action, result as Record<string, unknown>, error),
  };
}

async function certificateDebugEnabled(env: Env): Promise<boolean> {
  return await getBooleanProjectSetting(env.DB, "LG_WORKER_DEBUG_LOGS") || await getBooleanProjectSetting(env.DB, "LG_DEBUG_STREAMS");
}

async function certificateDebugPayload(
  env: Env,
  action: "reissue" | "sync" | "import" | "begin" | "finalize" | "cancel",
  result: Record<string, unknown>,
  error?: unknown,
): Promise<Record<string, unknown>> {
  const dnsSettings = env.DB ? await getDNSSettings(env.DB) : null;
  const [
    acmeEnabled,
    workerDebugLogs,
    debugStreams,
    provider,
    accountEmail,
    directoryURL,
    renewBeforeDays,
    eabKeyID,
    eabAlgorithm,
    zoneID,
    accountJWK,
    eabHMACKey,
    dnsToken,
  ] = await Promise.all([
    getBooleanProjectSetting(env.DB, "ACME_ENABLED"),
    getBooleanProjectSetting(env.DB, "LG_WORKER_DEBUG_LOGS"),
    getBooleanProjectSetting(env.DB, "LG_DEBUG_STREAMS"),
    getStringProjectSetting(env.DB, "ACME_PROVIDER"),
    getStringProjectSetting(env.DB, "ACME_ACCOUNT_EMAIL"),
    getStringProjectSetting(env.DB, "ACME_DIRECTORY_URL"),
    getStringProjectSetting(env.DB, "ACME_RENEW_BEFORE_DAYS"),
    getStringProjectSetting(env.DB, "ACME_EAB_KEY_ID"),
    getStringProjectSetting(env.DB, "ACME_EAB_ALG"),
    getStringProjectSetting(env.DB, "CLOUDFLARE_ZONE_ID"),
    runtimeSecretStatus(env.DB, "ACME_ACCOUNT_JWK"),
    runtimeSecretStatus(env.DB, "ACME_EAB_HMAC_KEY"),
    runtimeSecretStatus(env.DB, "CLOUDFLARE_DNSUPDATE_API_KEY"),
  ]);

  return {
    action,
    at: new Date().toISOString(),
    settings: {
      source: acmeEnabled ? "acme" : "manual",
      acme_enabled: acmeEnabled,
      provider: provider || "",
      account_email_configured: Boolean(accountEmail),
      directory_url: directoryURL || "",
      renew_before_days: renewBeforeDays || "",
      eab_key_id: eabKeyID || "",
      eab_key_id_configured: Boolean(eabKeyID),
      eab_algorithm: eabAlgorithm || "",
      worker_debug_logs: workerDebugLogs,
      debug_streams: debugStreams,
    },
    runtime_secrets: {
      acme_account_jwk: secretDebugStatus(accountJWK),
      acme_eab_hmac_key: secretDebugStatus(eabHMACKey),
      cloudflare_dns_token: secretDebugStatus(dnsToken),
    },
    dns: {
      settings_configured: Boolean(dnsSettings),
      zone_id_configured: Boolean(zoneID),
      managed_domains: dnsSettings ? managedCertificateDomains(dnsSettings) : [],
    },
    result,
    ...(error ? { error: serializeCertificateDebugError(error) } : {}),
  };
}

function secretDebugStatus(secret: Awaited<ReturnType<typeof runtimeSecretStatus>>): Record<string, unknown> {
  return {
    configured: secret.configured,
    source: secret.source,
    can_generate: secret.can_generate,
  };
}

function serializeCertificateDebugError(error: unknown): Record<string, unknown> {
  if (error instanceof ACMERequestError) {
    return {
      name: error.name,
      message: error.message,
      status: error.status,
      method: error.method,
      url: error.url,
      response_body: error.responseBody,
      problem: error.problem,
    };
  }
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack?.split("\n").slice(0, 6).join("\n"),
    };
  }
  return { message: String(error) };
}

export async function handleAdminProjectSettings(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdmin(request, env);
  if (auth) return auth;
  if (request.method === "GET") return json({ settings: await listProjectSettingStatus(env.DB) });
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return json({ error: "d1_required" }, { status: 503 });
  const body = await readJSON<{ key?: string; value?: unknown; reset?: boolean; confirm?: string }>(request);
  if (!body.key || !isProjectSettingKey(body.key)) return json({ error: "invalid_setting_key" }, { status: 400 });
  if (body.reset === true) {
    if (body.confirm !== body.key) return json({ error: "reset_confirmation_required" }, { status: 400 });
    await resetProjectSetting(env.DB, body.key);
    return json(await projectSettingStatus(env.DB, body.key));
  }
  try {
    await setProjectSetting(env.DB, body.key, body.value);
  } catch (error) {
    if (error instanceof Error && error.message === "setting_value_required") return json({ error: "setting_value_required" }, { status: 400 });
    return json({ error: "invalid_setting_value" }, { status: 400 });
  }
  return json(await projectSettingStatus(env.DB, body.key));
}
