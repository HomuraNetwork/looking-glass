import type { SqlDatabase } from "./runtime";
export interface PublicNavItem {
  label: string;
  href: string;
  active?: boolean;
  disabled?: boolean;
  badge?: string;
  external?: boolean;
}

export interface PublicBrandingConfig {
  site_name: string;
  logo_text: string;
  logo_image_url: string | null;
  brand_name: string;
  show_brand_name: boolean;
  nav_items: PublicNavItem[];
  theme: string;
  page_title: string | null;
  favicon_url: string | null;
  page_title_mode: "site_only" | "site_brand" | "brand_site" | "custom";
  meta_description: string | null;
  meta_keywords: string | null;
  og_image_url: string | null;
  twitter_image_url: string | null;
}

export const DEFAULT_AGENT_INSTALL_DIR = "/opt/looking-glass";
export const DEFAULT_AGENT_BINARY_NAME = "hlg-agent";
export const DEFAULT_AGENT_SERVICE_NAME = "hlg-agent";
export const DEFAULT_AGENT_RUN_USER = "root";

export const DEFAULT_PUBLIC_NAV_ITEMS: PublicNavItem[] = [
  { label: "Looking Glass", href: "/", active: true },
];

export const PROJECT_SETTING_DEFINITIONS = [
  { key: "CLOUDFLARE_ZONE_ID", label: "Cloudflare Zone ID", type: "string" },
  { key: "TURNSTILE_SITE_KEY", label: "Turnstile Site Key", type: "string" },
  { key: "TURNSTILE_ENFORCED", label: "Enforce Turnstile (fail closed without secret)", type: "boolean", defaultValue: false },
  { key: "LG_BLOCK_PRIVATE_IPS", label: "Block Private IPs", type: "boolean", defaultValue: true },
  { key: "LG_DEBUG_STREAMS", label: "Debug Streams", type: "boolean", defaultValue: false },
  { key: "LG_WORKER_DEBUG_LOGS", label: "Worker Debug Logs", type: "boolean", defaultValue: false },
  { key: "LG_AVAILABILITY_PROBE", label: "Probe Node Availability", type: "boolean", defaultValue: true },
  { key: "ACME_ENABLED", label: "ACME Auto Certificates", type: "boolean", defaultValue: false },
  { key: "ACME_PROVIDER", label: "ACME Provider", type: "string", defaultValue: "letsencrypt" },
  { key: "ACME_ACCOUNT_EMAIL", label: "ACME Account Email", type: "string", defaultValue: "" },
  { key: "ACME_DIRECTORY_URL", label: "ACME Directory URL", type: "string", defaultValue: "https://acme-v02.api.letsencrypt.org/directory" },
  { key: "ACME_RENEW_BEFORE_DAYS", label: "ACME Renew Before Days", type: "string", defaultValue: "30" },
  { key: "ACME_EAB_KEY_ID", label: "ACME EAB Key ID", type: "string", defaultValue: "" },
  { key: "ACME_EAB_ALG", label: "ACME EAB Algorithm", type: "string", defaultValue: "HS256" },
  { key: "PUBLIC_SITE_NAME", label: "Site Name", type: "string", defaultValue: "Looking Glass" },
  { key: "PUBLIC_LOGO_TEXT", label: "Logo Text", type: "string", defaultValue: "LG" },
  { key: "PUBLIC_LOGO_IMAGE_URL", label: "Logo Image URL", type: "string", defaultValue: "" },
  { key: "PUBLIC_BRAND_NAME", label: "Brand Name", type: "string", defaultValue: "" },
  { key: "PUBLIC_SHOW_BRAND_NAME", label: "Show Brand Name", type: "boolean", defaultValue: false },
  { key: "PUBLIC_NAV_ITEMS", label: "Public Navigation", type: "json", defaultValue: DEFAULT_PUBLIC_NAV_ITEMS },
  { key: "PUBLIC_THEME", label: "Theme", type: "string", defaultValue: "homura" },
  { key: "PUBLIC_PAGE_TITLE", label: "Page Title (browser tab)", type: "string", defaultValue: "" },
  { key: "PUBLIC_FAVICON_URL", label: "Favicon URL", type: "string", defaultValue: "" },
  { key: "PUBLIC_PAGE_TITLE_MODE", label: "Page Title Mode", type: "string", defaultValue: "site_only" },
  { key: "PUBLIC_META_DESCRIPTION", label: "Meta Description", type: "string", defaultValue: "" },
  { key: "PUBLIC_META_KEYWORDS", label: "Meta Keywords", type: "string", defaultValue: "" },
  { key: "PUBLIC_OG_IMAGE_URL", label: "Open Graph Image URL", type: "string", defaultValue: "" },
  { key: "PUBLIC_TWITTER_IMAGE_URL", label: "Twitter Card Image URL", type: "string", defaultValue: "" },
  { key: "AGENT_INSTALL_DIR", label: "Agent Install Directory", type: "string", defaultValue: DEFAULT_AGENT_INSTALL_DIR },
  { key: "AGENT_BINARY_NAME", label: "Agent Binary Name", type: "string", defaultValue: DEFAULT_AGENT_BINARY_NAME },
  { key: "AGENT_SERVICE_NAME", label: "Agent Service Name", type: "string", defaultValue: DEFAULT_AGENT_SERVICE_NAME },
  { key: "AGENT_RUN_USER", label: "Agent Service User", type: "string", defaultValue: DEFAULT_AGENT_RUN_USER },
] as const satisfies ReadonlyArray<{
  key: string;
  label: string;
  type: "string" | "boolean" | "json";
  defaultValue?: string | boolean | PublicNavItem[];
}>;

export type ProjectSettingKey = (typeof PROJECT_SETTING_DEFINITIONS)[number]["key"];
export type ProjectSettingSource = "d1" | "default" | "none";
export type ProjectSettingValue = string | boolean | PublicNavItem[] | null;

export interface ProjectSettingStatus {
  key: ProjectSettingKey;
  label: string;
  type: "string" | "boolean" | "json";
  value: ProjectSettingValue;
  configured: boolean;
  source: ProjectSettingSource;
}

export function isProjectSettingKey(value: string): value is ProjectSettingKey {
  return PROJECT_SETTING_DEFINITIONS.some((definition) => definition.key === value);
}

export async function listProjectSettingStatus(db: SqlDatabase | undefined): Promise<ProjectSettingStatus[]> {
  const d1Values = await readD1ProjectSettings(db);
  return PROJECT_SETTING_DEFINITIONS.map((definition) => projectSettingStatusFromSources(definition.key, d1Values.get(definition.key as ProjectSettingKey)));
}

export async function projectSettingStatus(db: SqlDatabase | undefined, key: ProjectSettingKey): Promise<ProjectSettingStatus> {
  return projectSettingStatusFromSources(key, await readD1ProjectSetting(db, key));
}

export async function getStringProjectSetting(
  db: SqlDatabase | undefined,
  key: Extract<ProjectSettingKey, "CLOUDFLARE_ZONE_ID" | "TURNSTILE_SITE_KEY" | "ACME_PROVIDER" | "ACME_ACCOUNT_EMAIL" | "ACME_DIRECTORY_URL" | "ACME_RENEW_BEFORE_DAYS" | "ACME_EAB_KEY_ID" | "ACME_EAB_ALG" | "AGENT_INSTALL_DIR" | "AGENT_BINARY_NAME" | "AGENT_SERVICE_NAME" | "AGENT_RUN_USER">,
): Promise<string | undefined> {
  const status = await projectSettingStatus(db, key);
  return typeof status.value === "string" && status.value ? status.value : undefined;
}

export async function getBooleanProjectSetting(
  db: SqlDatabase | undefined,
  key: Extract<ProjectSettingKey, "LG_BLOCK_PRIVATE_IPS" | "LG_DEBUG_STREAMS" | "LG_WORKER_DEBUG_LOGS" | "ACME_ENABLED" | "TURNSTILE_ENFORCED" | "LG_AVAILABILITY_PROBE">,
): Promise<boolean> {
  return (await projectSettingStatus(db, key)).value === true;
}

export async function getPublicBrandingConfig(db: SqlDatabase | undefined): Promise<PublicBrandingConfig> {
  // One batched read instead of one D1 query per setting (~20 reads before);
  // statuses are computed from the map, keeping the same semantics.
  const d1Values = await readD1ProjectSettings(db);
  const brandingStatus = (key: ProjectSettingKey): ProjectSettingStatus =>
    projectSettingStatusFromSources(key, d1Values.get(key));
  const siteName = brandingStatus("PUBLIC_SITE_NAME");
  const logoText = brandingStatus("PUBLIC_LOGO_TEXT");
  const logoImageUrl = brandingStatus("PUBLIC_LOGO_IMAGE_URL");
  const brandName = brandingStatus("PUBLIC_BRAND_NAME");
  const showBrandName = brandingStatus("PUBLIC_SHOW_BRAND_NAME");
  const navItems = brandingStatus("PUBLIC_NAV_ITEMS");
  const theme = brandingStatus("PUBLIC_THEME");
  const pageTitle = brandingStatus("PUBLIC_PAGE_TITLE");
  const faviconUrl = brandingStatus("PUBLIC_FAVICON_URL");
  const pageTitleMode = brandingStatus("PUBLIC_PAGE_TITLE_MODE");
  const metaDescription = brandingStatus("PUBLIC_META_DESCRIPTION");
  const metaKeywords = brandingStatus("PUBLIC_META_KEYWORDS");
  const ogImageUrl = brandingStatus("PUBLIC_OG_IMAGE_URL");
  const twitterImageUrl = brandingStatus("PUBLIC_TWITTER_IMAGE_URL");
  const validMode = (m: string): PublicBrandingConfig["page_title_mode"] => {
    if (m === "site_only" || m === "site_brand" || m === "brand_site" || m === "custom") return m;
    return "site_only";
  };
  return {
    site_name: typeof siteName.value === "string" && siteName.value ? siteName.value : "Looking Glass",
    logo_text: typeof logoText.value === "string" && logoText.value ? logoText.value : "LG",
    logo_image_url: typeof logoImageUrl.value === "string" && logoImageUrl.value ? logoImageUrl.value : null,
    brand_name: typeof brandName.value === "string" ? brandName.value : "",
    show_brand_name: showBrandName.value === true,
    nav_items: Array.isArray(navItems.value) ? navItems.value : DEFAULT_PUBLIC_NAV_ITEMS,
    theme: typeof theme.value === "string" && theme.value ? theme.value : "homura",
    page_title: typeof pageTitle.value === "string" && pageTitle.value ? pageTitle.value : null,
    favicon_url: typeof faviconUrl.value === "string" && faviconUrl.value ? faviconUrl.value : null,
    page_title_mode: validMode(typeof pageTitleMode.value === "string" ? pageTitleMode.value : "site_only"),
    meta_description: typeof metaDescription.value === "string" && metaDescription.value ? metaDescription.value : null,
    meta_keywords: typeof metaKeywords.value === "string" && metaKeywords.value ? metaKeywords.value : null,
    og_image_url: typeof ogImageUrl.value === "string" && ogImageUrl.value ? ogImageUrl.value : null,
    twitter_image_url: typeof twitterImageUrl.value === "string" && twitterImageUrl.value ? twitterImageUrl.value : null,
  };
}

export async function setProjectSetting(db: SqlDatabase, key: ProjectSettingKey, value: unknown): Promise<void> {
  const normalized = normalizeProjectSettingValue(key, value);
  // URL-carrying branding fields are validated at save time only; legacy D1
  // rows with disallowed schemes stay readable and are dropped at render
  // time by the HTML injection instead of failing every request.
  if (typeof normalized === "string" && isBrandingImageURLKey(key) && normalized) {
    normalizeBrandingImageURL(normalized);
  }
  await db
    .prepare(
      `INSERT INTO project_settings (key, value_json, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
    )
    .bind(key, JSON.stringify(normalized), Math.floor(Date.now() / 1000))
    .run();
}

export async function resetProjectSetting(db: SqlDatabase, key: ProjectSettingKey): Promise<void> {
  await db.prepare("DELETE FROM project_settings WHERE key = ?").bind(key).run();
}

function projectSettingStatusFromSources(key: ProjectSettingKey, d1Value: unknown | undefined): ProjectSettingStatus {
  const definition = definitionForKey(key);
  if (d1Value !== undefined) {
    return status(key, normalizeProjectSettingValue(key, d1Value), "d1");
  }
  if ("defaultValue" in definition && definition.defaultValue !== undefined) return status(key, definition.defaultValue, "default");
  return status(key, null, "none");
}

function status(key: ProjectSettingKey, value: ProjectSettingValue, source: ProjectSettingSource): ProjectSettingStatus {
  const definition = definitionForKey(key);
  return {
    key,
    label: definition.label,
    type: definition.type,
    value,
    configured: source === "d1",
    source,
  };
}

async function readD1ProjectSettings(db: SqlDatabase | undefined): Promise<Map<ProjectSettingKey, unknown>> {
  const values = new Map<ProjectSettingKey, unknown>();
  if (!db) return values;
  let rows: { results: Array<{ key: string; value_json: string }> };
  try {
    rows = await db.prepare("SELECT key, value_json FROM project_settings").all<{ key: string; value_json: string }>();
  } catch {
    return values;
  }
  // One corrupt row must not discard every setting: parse per row and skip
  // values that fail to deserialize.
  for (const row of rows.results) {
    if (!isProjectSettingKey(row.key)) continue;
    try {
      values.set(row.key, JSON.parse(row.value_json) as unknown);
    } catch {
      continue;
    }
  }
  return values;
}

async function readD1ProjectSetting(db: SqlDatabase | undefined, key: ProjectSettingKey): Promise<unknown | undefined> {
  if (!db) return undefined;
  try {
    const row = await db.prepare("SELECT value_json FROM project_settings WHERE key = ?").bind(key).first<{ value_json: string }>();
    return row ? (JSON.parse(row.value_json) as unknown) : undefined;
  } catch {
    return undefined;
  }
}

function normalizeProjectSettingValue(key: ProjectSettingKey, value: unknown): string | boolean | PublicNavItem[] {
  const definition = definitionForKey(key);
  if (definition.type === "boolean") return normalizeBoolean(value);
  if (definition.type === "json") return normalizeJSONSettingValue(key, value);
  if (typeof value !== "string") throw new Error("invalid_setting_value");
  const normalized = value.trim();
  if (key === "AGENT_BINARY_NAME" || key === "AGENT_SERVICE_NAME" || key === "AGENT_RUN_USER") return normalizeAgentUnitSetting(normalized);
  if (key === "AGENT_INSTALL_DIR") return normalizeAgentInstallDir(normalized);
  const emptyAllowed =
    key === "PUBLIC_LOGO_TEXT" ||
    key === "ACME_ACCOUNT_EMAIL" ||
    key === "ACME_EAB_KEY_ID";
  if (!normalized && !emptyAllowed) throw new Error("setting_value_required");
  return normalized;
}

function normalizeAgentUnitSetting(value: string): string {
  if (!value) throw new Error("setting_value_required");
  if (!/^[A-Za-z0-9._-]+$/.test(value) || value === "." || value === "..") throw new Error("invalid_setting_value");
  return value;
}

function normalizeAgentInstallDir(value: string): string {
  if (!value) throw new Error("setting_value_required");
  if (!value.startsWith("/") || value.includes("\0") || /\s/.test(value)) throw new Error("invalid_setting_value");
  return value.replace(/\/+$/, "") || "/";
}

/**
 * Branding fields that end up inside URL-carrying HTML attributes (favicon,
 * OG/Twitter images) only accept https:// absolute URLs or site-relative
 * paths — the same protocol policy the HTML injection applies at render
 * time. Mirrors `safeHTMLURL` in index.ts.
 */
function isBrandingImageURLKey(key: ProjectSettingKey): boolean {
  return key === "PUBLIC_FAVICON_URL" || key === "PUBLIC_OG_IMAGE_URL" || key === "PUBLIC_TWITTER_IMAGE_URL";
}

function normalizeBrandingImageURL(value: string): string {
  // Reject protocol-relative URLs ("//evil.com"): they resolve against the
  // page scheme and leave the site, contradicting the https-or-relative
  // contract documented at the render site.
  if (value.startsWith("https://") || (value.startsWith("/") && !value.startsWith("//"))) return value;
  throw new Error("invalid_setting_value");
}
function normalizeJSONSettingValue(key: ProjectSettingKey, value: unknown): PublicNavItem[] {
  const parsed = typeof value === "string" ? JSON.parse(value) as unknown : value;
  if (key !== "PUBLIC_NAV_ITEMS" || !Array.isArray(parsed)) throw new Error("invalid_setting_value");
  const items = parsed.map((item) => normalizePublicNavItem(item)).filter(Boolean) as PublicNavItem[];
  if (items.length === 0) throw new Error("setting_value_required");
  return items.slice(0, 8);
}

function normalizePublicNavItem(value: unknown): PublicNavItem | null {
  if (!value || typeof value !== "object") return null;
  const source = value as Record<string, unknown>;
  const label = typeof source.label === "string" ? source.label.trim() : "";
  const href = typeof source.href === "string" ? source.href.trim() : "";
  if (!label || !href) return null;
  return {
    label: label.slice(0, 48),
    href: href.slice(0, 512),
    ...(source.active === true ? { active: true } : {}),
    ...(source.disabled === true ? { disabled: true } : {}),
    ...(typeof source.badge === "string" && source.badge.trim() ? { badge: source.badge.trim().slice(0, 16) } : {}),
    ...(source.external === true ? { external: true } : {}),
  };
}

function normalizeBoolean(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "1" || normalized === "true") return true;
    if (normalized === "0" || normalized === "false") return false;
  }
  throw new Error("invalid_setting_value");
}

function definitionForKey(key: ProjectSettingKey) {
  const definition = PROJECT_SETTING_DEFINITIONS.find((item) => item.key === key);
  if (!definition) throw new Error("invalid_setting_key");
  return definition;
}
