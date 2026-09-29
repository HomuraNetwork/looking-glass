import type { SqlDatabase, SqlResult } from "./runtime";
export interface PublicNode {
  internal_id: string;
  id: string;
  domain: string;
  /** HTTPS port the Worker uses to reach the node (or its reverse proxy). */
  port: number;
  domain_v4?: string;
  domain_v6?: string;
  display_name: string;
  /** Free-text location / subtitle (legacy `region` was merged into this). */
  display_label?: string;
  features: string[];
  has_ipv4: boolean;
  has_ipv6: boolean;
  maintenance: boolean;
  dynamic_ip: boolean;
  public_ipv4?: string;
  public_ipv6?: string;
  description?: string;
  action_url?: string;
  action_label?: string;
  buy_url?: string;
  buy_label?: string;
  bgp_url?: string;
}
export interface AdminNode extends PublicNode {
  profile_id: string;
  enabled: boolean;
  hidden: boolean;
  config_version: number;
  /**
   * Config bundle version the agent last reported as applied (the revision it
   * is actually serving). Undefined/0 means the node has never confirmed a
   * config; compare with config_version to tell whether it is up to date.
   */
  config_applied_version?: number;
  /** Operator-controlled list position; lower sorts first, null sorts last. */
  display_order?: number | null;
  version?: string;
  /**
   * Build timestamp the agent last reported (its own build identity). Compared
   * against the distributed manifest to flag nodes needing an upgrade.
   */
  build_id?: string | null;
  created_at: number;
  updated_at: number;
  last_seen_at?: number;
  active_init?: {
    node_id: string;
    token: string;
    expires_at: number;
  };
}

interface NodeRow {
  id: string;
  slug?: string | null;
  domain: string;
  port?: number | null;
  domain_v4: string | null;
  domain_v6: string | null;
  display_name: string;
  display_label: string | null;
  public_ipv4: string | null;
  public_ipv6: string | null;
  description: string | null;
  buy_url: string | null;
  buy_label: string | null;
  bgp_url: string | null;
  profile_id: string | null;
  profile_config_json?: string | null;
  capabilities: string | null;
  maintenance: number;
  dynamic_ip: number;
}

interface AdminNodeRow extends NodeRow {
  enabled: number;
  hidden: number;
  config_version: number;
  config_applied_version: number | null;
  display_order: number | null;
  version: string | null;
  build_id: string | null;
  created_at: number;
  updated_at: number;
  last_seen_at?: number | null;
}

export interface NodeUpsert {
  internal_id?: string;
  id: string;
  domain: string;
  port?: number;
  domain_v4?: string;
  domain_v6?: string;
  display_name: string;
  display_label?: string;
  public_ipv4?: string;
  public_ipv6?: string;
  description?: string;
  buy_url?: string;
  buy_label?: string;
  bgp_url?: string;
  profile_id?: string;
  enabled?: boolean;
  hidden?: boolean;
  maintenance?: boolean;
  dynamic_ip?: boolean;
  /** Operator list position; undefined keeps the existing value. */
  display_order?: number | null;
  features?: string[];
}

export async function listNodes(db: SqlDatabase): Promise<PublicNode[]> {
  const result = await db
    .prepare(
      `SELECT nodes.id, domain, port, domain_v4, domain_v6, display_name, display_label, public_ipv4, public_ipv6,
              COALESCE(nodes.slug, nodes.id) AS slug,
              description, buy_url, buy_label, bgp_url,
              profile_id, capabilities, maintenance, dynamic_ip, node_profiles.config_json AS profile_config_json
       FROM nodes
       LEFT JOIN node_profiles ON node_profiles.id = COALESCE(nodes.profile_id, 'default')
       WHERE enabled = 1 AND hidden = 0 AND agent_public_key IS NOT NULL
       ORDER BY (nodes.display_order IS NULL), nodes.display_order ASC, COALESCE(nodes.slug, nodes.id)`,
    )
    .all<NodeRow>();
  return result.results.map(nodeRowToPublic);
}

export async function getNode(db: SqlDatabase | undefined, nodeID: string): Promise<PublicNode | null> {
  if (!db) return null;
  const row = await db
    .prepare(
      `SELECT nodes.id, domain, port, domain_v4, domain_v6, display_name, display_label, public_ipv4, public_ipv6,
              COALESCE(nodes.slug, nodes.id) AS slug,
              description, buy_url, buy_label, bgp_url,
              profile_id, capabilities, maintenance, dynamic_ip, node_profiles.config_json AS profile_config_json
       FROM nodes
       LEFT JOIN node_profiles ON node_profiles.id = COALESCE(nodes.profile_id, 'default')
       WHERE (nodes.id = ? OR nodes.slug = ?) AND enabled = 1 AND hidden = 0 AND agent_public_key IS NOT NULL`,
    )
    .bind(nodeID, nodeID)
    .first<NodeRow>();
  return row ? nodeRowToPublic(row) : null;
}

export async function listAdminNodes(db: SqlDatabase): Promise<AdminNode[]> {
  const result = await db
    .prepare(
      `SELECT nodes.id, domain, port, domain_v4, domain_v6, display_name, display_label, public_ipv4, public_ipv6,
              COALESCE(nodes.slug, nodes.id) AS slug,
              description, buy_url, buy_label, bgp_url, profile_id, enabled, hidden,
              maintenance, dynamic_ip, config_version, config_applied_version, display_order, version, build_id, capabilities, nodes.created_at AS created_at, nodes.updated_at AS updated_at, nodes.last_seen_at AS last_seen_at,
              node_profiles.config_json AS profile_config_json
       FROM nodes
       LEFT JOIN node_profiles ON node_profiles.id = COALESCE(nodes.profile_id, 'default')
       ORDER BY (nodes.display_order IS NULL), nodes.display_order ASC, COALESCE(nodes.slug, nodes.id)`,
    )
    .all<AdminNodeRow>();
  return result.results.map(nodeRowToAdmin);
}

export async function getAdminNode(db: SqlDatabase | undefined, nodeID: string): Promise<AdminNode | null> {
  if (!db) return null;
  const row = await db
    .prepare(
      `SELECT nodes.id, domain, port, domain_v4, domain_v6, display_name, display_label, public_ipv4, public_ipv6,
              COALESCE(nodes.slug, nodes.id) AS slug,
              description, buy_url, buy_label, bgp_url, profile_id, enabled, hidden,
              maintenance, dynamic_ip, config_version, config_applied_version, display_order, version, build_id, capabilities, nodes.created_at AS created_at, nodes.updated_at AS updated_at,
              node_profiles.config_json AS profile_config_json
       FROM nodes
       LEFT JOIN node_profiles ON node_profiles.id = COALESCE(nodes.profile_id, 'default')
       WHERE nodes.id = ? OR nodes.slug = ?`,
    )
    .bind(nodeID, nodeID)
    .first<AdminNodeRow>();
  return row ? nodeRowToAdmin(row) : null;
}

export async function upsertNode(db: SqlDatabase, input: NodeUpsert): Promise<PublicNode> {
  const now = Math.floor(Date.now() / 1000);
  const slug = normalizeNodeSlug(input.id);
  const existing = input.internal_id ? await getAdminNode(db, input.internal_id) : await getAdminNode(db, slug);
  const profileID = input.profile_id ?? "default";
  const features = input.features && input.features.length > 0 ? input.features : await defaultFeaturesForProfile(db, profileID);
  const row = {
    id: existing?.internal_id ?? (input.internal_id?.trim() || crypto.randomUUID()),
    slug,
    domain: input.domain,
    port: input.port ?? existing?.port ?? 443,
    domain_v4: input.domain_v4 ?? null,
    domain_v6: input.domain_v6 ?? null,
    display_name: input.display_name,
    display_label: input.display_label ?? null,
    // Admin edits that omit the IP fields must not wipe agent-detected IPs:
    // only overwrite when the caller explicitly provided a value.
    public_ipv4: input.public_ipv4 !== undefined ? input.public_ipv4 : (existing?.public_ipv4 ?? null),
    public_ipv6: input.public_ipv6 !== undefined ? input.public_ipv6 : (existing?.public_ipv6 ?? null),
    description: input.description ?? null,
    buy_url: input.buy_url ?? null,
    buy_label: input.buy_label ?? null,
    bgp_url: input.bgp_url ?? null,
    profile_id: profileID,
    enabled: input.enabled === false ? 0 : 1,
    hidden: input.hidden === true ? 1 : 0,
    maintenance: input.maintenance === true ? 1 : 0,
    dynamic_ip: input.dynamic_ip === true ? 1 : 0,
    config_version: 1,
    // Preserve the operator's ordering across edits; a new node without an
    // explicit order stays null and sorts last until it is placed.
    display_order: input.display_order !== undefined ? input.display_order : (existing?.display_order ?? null),
    // Preserve the version string reported by the agent instead of inventing
    // one on every admin edit; it is unknown until the node first reports.
    version: existing?.version ?? null,
    capabilities: JSON.stringify(features),
    created_at: now,
    updated_at: now,
  };

  if (existing) {
    await db
      .prepare(
        `UPDATE nodes
         SET slug = ?,
             domain = ?,
             port = ?,
             domain_v4 = ?,
             domain_v6 = ?,
             display_name = ?,
             display_label = ?,
             public_ipv4 = ?,
             public_ipv6 = ?,
             description = ?,
             buy_url = ?,
             buy_label = ?,
             bgp_url = ?,
             profile_id = ?,
             enabled = ?,
             hidden = ?,
             maintenance = ?,
             dynamic_ip = ?,
             config_version = config_version + 1,
             display_order = ?,
             capabilities = ?,
             updated_at = ?
         WHERE id = ?`,
      )
      .bind(
        row.slug,
        row.domain,
        row.port,
        row.domain_v4,
        row.domain_v6,
        row.display_name,
        row.display_label,
        row.public_ipv4,
        row.public_ipv6,
        row.description,
        row.buy_url,
        row.buy_label,
        row.bgp_url,
        row.profile_id,
        row.enabled,
        row.hidden,
        row.maintenance,
        row.dynamic_ip,
        row.display_order,
        row.capabilities,
        row.updated_at,
        row.id,
      )
      .run();
    return (await getNode(db, row.id)) ?? nodeRowToPublic(row);
  }

  // Race-safe create: a concurrent double-create must upsert instead of
  // colliding on the primary key and returning a 500.
  await db
    .prepare(
      `INSERT INTO nodes (
        id, slug, domain, port, domain_v4, domain_v6, display_name, display_label, public_ipv4, public_ipv6,
        description, buy_url, buy_label, bgp_url, profile_id, enabled, hidden,
        maintenance, dynamic_ip, display_order, config_version, agent_public_key, agent_encryption_public_key, version, capabilities, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        slug = excluded.slug,
        domain = excluded.domain,
        port = excluded.port,
        domain_v4 = excluded.domain_v4,
        domain_v6 = excluded.domain_v6,
        display_name = excluded.display_name,
        display_label = excluded.display_label,
        public_ipv4 = excluded.public_ipv4,
        public_ipv6 = excluded.public_ipv6,
        description = excluded.description,
        buy_url = excluded.buy_url,
        buy_label = excluded.buy_label,
        bgp_url = excluded.bgp_url,
        profile_id = excluded.profile_id,
        enabled = excluded.enabled,
        hidden = excluded.hidden,
        maintenance = excluded.maintenance,
        dynamic_ip = excluded.dynamic_ip,
        display_order = excluded.display_order,
        config_version = config_version + 1,
        capabilities = excluded.capabilities,
        updated_at = excluded.updated_at`,
    )
    .bind(
      row.id,
      row.slug,
      row.domain,
      row.port,
      row.domain_v4,
      row.domain_v6,
      row.display_name,
      row.display_label,
      row.public_ipv4,
      row.public_ipv6,
      row.description,
      row.buy_url,
      row.buy_label,
      row.bgp_url,
      row.profile_id,
      row.enabled,
      row.hidden,
      row.maintenance,
      row.dynamic_ip,
      row.display_order,
      row.config_version,
      row.version,
      row.capabilities,
      row.created_at,
      row.updated_at,
    )
    .run();
  return nodeRowToPublic(row);
}

function nodeRowToPublic(row: NodeRow): PublicNode {
  return {
    internal_id: row.id,
    id: publicNodeID(row),
    domain: row.domain,
    port: row.port ?? 443,
    domain_v4: row.domain_v4 ?? undefined,
    domain_v6: row.domain_v6 ?? undefined,
    display_name: row.display_name,
    display_label: row.display_label ?? undefined,
    features: row.capabilities ? parseFeatures(row.capabilities) : featuresFromProfileConfig(row.profile_config_json),
    has_ipv4: Boolean(row.public_ipv4),
    has_ipv6: Boolean(row.public_ipv6),
    maintenance: row.maintenance === 1,
    dynamic_ip: row.dynamic_ip === 1,
    public_ipv4: row.public_ipv4 ?? undefined,
    public_ipv6: row.public_ipv6 ?? undefined,
    description: row.description ?? undefined,
    action_url: row.buy_url ?? undefined,
    action_label: row.buy_label ?? undefined,
    buy_url: row.buy_url ?? undefined,
    buy_label: row.buy_label ?? undefined,
    bgp_url: row.bgp_url ?? undefined,
  };
}

export async function defaultFeaturesForProfile(db: SqlDatabase, profileID = "default"): Promise<string[]> {
  const row = await db.prepare("SELECT config_json FROM node_profiles WHERE id = ?").bind(profileID).first<{ config_json: string }>();
  const features = featuresFromProfileConfig(row?.config_json);
  if (features.length > 0 || profileID === "default") return features;
  const fallback = await db.prepare("SELECT config_json FROM node_profiles WHERE id = ?").bind("default").first<{ config_json: string }>();
  return featuresFromProfileConfig(fallback?.config_json);
}

function parseFeatures(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
  } catch {
    return [];
  }
}

function featuresFromProfileConfig(value: string | null | undefined): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value) as { features?: unknown };
    return Array.isArray(parsed.features) ? parsed.features.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
  } catch {
    return [];
  }
}

function nodeRowToAdmin(row: AdminNodeRow): AdminNode {
  return {
    ...nodeRowToPublic(row),
    profile_id: row.profile_id ?? "default",
    enabled: row.enabled !== 0,
    hidden: row.hidden === 1,
    config_version: row.config_version ?? 1,
    config_applied_version: row.config_applied_version ?? 0,
    display_order: row.display_order ?? null,
    version: row.version ?? undefined,
    build_id: row.build_id ?? null,
    created_at: row.created_at ?? 0,
    updated_at: row.updated_at ?? 0,
    last_seen_at: row.last_seen_at ?? undefined,
  };
}

/**
 * Assign display_order 1..N following the given node order, in one batch.
 * Accepts internal ids or slugs. Ids not present are ignored; nodes not listed
 * keep their existing order (so a partial reorder does not clobber the rest).
 */
export async function reorderNodes(db: SqlDatabase, orderedIDs: string[]): Promise<number> {
  const statements = orderedIDs.map((nodeID, index) =>
    db
      .prepare("UPDATE nodes SET display_order = ?, updated_at = ? WHERE id = ? OR slug = ?")
      .bind(index + 1, Math.floor(Date.now() / 1000), nodeID, nodeID),
  );
  if (statements.length === 0) return 0;
  const results = await db.batch(statements);
  return results.reduce((sum, result) => sum + (result.meta?.changes ?? 0), 0);
}

export async function deleteNode(db: SqlDatabase, nodeID: string): Promise<boolean> {  const now = Math.floor(Date.now() / 1000);
  const nodesDelete = db.prepare("DELETE FROM nodes WHERE id = ? OR slug = ?").bind(nodeID, nodeID);
  // Revoke tokens and purge node-scoped rows atomically with the node delete
  // so a concurrent agent sync cannot resurrect orphaned references.
  // (operation_audit has no per-row cleanup: its rows expire on their own TTL.)
  const result = await db.batch([
    db
      .prepare("UPDATE node_tokens SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL")
      .bind(now, nodeID),
    db.prepare("DELETE FROM node_init_tokens WHERE node_id = ?").bind(nodeID),
    db.prepare("DELETE FROM enroll_tokens WHERE node_id = ?").bind(nodeID),
    db.prepare("DELETE FROM download_links WHERE node_id = ?").bind(nodeID),
    db.prepare("DELETE FROM iperf_sessions WHERE node_id = ?").bind(nodeID),
    db.prepare("DELETE FROM node_certificate_bundles WHERE node_id = ?").bind(nodeID),
    nodesDelete,
  ]);
  const deleteResult = result[result.length - 1] as SqlResult | undefined;
  return (deleteResult?.meta?.changes ?? 0) > 0;
}

function publicNodeID(row: Pick<NodeRow, "id" | "slug">): string {
  return row.slug?.trim() || row.id;
}

function normalizeNodeSlug(value: string): string {
  const slug = value.trim().toLowerCase();
  if (!slug) throw new Error("node_id_required");
  return slug;
}
