/** Default request timeout (15s) applied to every API fetch. */
const FETCH_TIMEOUT_MS = 15000;

/**
 * Wraps fetch with an AbortSignal.timeout(15000). If the caller provides its own
 * signal, both are combined: aborting either (or the timeout firing) aborts the
 * request. Replace bare fetch() calls with this so a hung request fails
 * predictably instead of hanging forever.
 */
export async function fetchWithTimeout(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const callerSignal = init?.signal;
  if (!callerSignal) {
    return fetch(input, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  }
  const controller = new AbortController();
  const timeoutSignal = AbortSignal.timeout(FETCH_TIMEOUT_MS);
  const abortFromCaller = () => controller.abort(callerSignal.reason);
  if (callerSignal.aborted) abortFromCaller();
  else callerSignal.addEventListener("abort", abortFromCaller, { once: true });
  timeoutSignal.addEventListener("abort", () => controller.abort(timeoutSignal.reason), { once: true });
  const cleanup = () => callerSignal.removeEventListener("abort", abortFromCaller);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    cleanup();
  }
}

/** Thrown by admin API helpers on a 401 so callers can reset to logged-out. */
export class AdminUnauthorizedError extends Error {
  constructor(message = "unauthorized") {
    super(message);
    this.name = "AdminUnauthorizedError";
  }
}

export function isUnauthorizedError(error: unknown): boolean {
  return error instanceof AdminUnauthorizedError
    || (error instanceof Error && error.message === "unauthorized");
}

export interface PublicNode {
  internal_id?: string;
  id: string;
  domain: string;
  /** HTTPS port the Worker uses to reach the node or reverse proxy. */
  port?: number;
  domain_v4?: string;
  domain_v6?: string;
  display_name?: string;
  display_label?: string;
  features?: string[];
  has_ipv4?: boolean;
  has_ipv6?: boolean;
  maintenance?: boolean;
  dynamic_ip?: boolean;
  public_ipv4?: string;
  public_ipv6?: string;
  description?: string;
  action_url?: string;
  action_label?: string;
  buy_url?: string;
  buy_label?: string;
  bgp_url?: string;
}

export const adminNodeFeatures = ["generate204", "download", "ping", "mtr", "traceroute", "nexttrace", "iperf3"] as const;

export type AdminNodeFeature = (typeof adminNodeFeatures)[number];

export function isAdminNodeFeature(feature: string): feature is AdminNodeFeature {
  return adminNodeFeatures.includes(feature as AdminNodeFeature);
}

export interface AdminNode extends PublicNode {
  profile_id: string;
  enabled: boolean;
  hidden: boolean;
  config_version: number;
  /** Config version the agent last confirmed serving; compare with config_version. */
  config_applied_version?: number;
  /** Build timestamp the agent last reported (its own build identity). */
  build_id?: string | null;
  /** True when the node's reported build predates the distributed one. */
  update_available?: boolean;
  /** Operator list position; lower sorts first, null sorts last. */
  display_order?: number | null;
  version?: string;
  created_at: number;
  updated_at: number;
  last_seen_at?: number;
  active_init?: {
    node_id: string;
    token: string;
    expires_at: number;
    pull_command: string;
    init_string?: string;
    manual?: AdminNodeManualInstall[];
    installDir?: string;
    dataDir?: string;
    binaryName?: string;
    serviceName?: string;
    runUser?: string;
  };
  /** Newest published certificate covering this node; null = self-signed. */
  certificate?: {
    domains: string[];
    cert_expires_at: number;
    status: string;
    synced_at: number | null;
  } | null;
  /** Latest availability flip; null = not yet determined. */
  availability?: {
    available: boolean;
    reason: string;
    at: number;
  } | null;
}

export interface AdminNodeFormInput {
  internal_id?: string;
  id: string;
  domain: string;
  port: number;
  domain_v4: string;
  domain_v6: string;
  display_name: string;
  display_label: string;
  public_ipv4: string;
  public_ipv6: string;
  description: string;
  buy_url: string;
  buy_label: string;
  bgp_url: string;
  dynamic_ip: boolean;
  profile_id: string;
  enabled: boolean;
  hidden: boolean;
  maintenance: boolean;
  features: AdminNodeFeature[];
}

export interface AdminDNSInput {
  node_id: string;
  prefix?: string;
  domain?: string;
  domain_v4?: string;
  domain_v6?: string;
  ipv4: string;
  ipv6: string;
}

export interface AdminNodeDNSOptions {
  enabled: boolean;
  mode: "id" | "prefix" | "full";
  prefix?: string;
}

export interface AdminDNSSettings {
  base: string;
  v4_base: string;
  v6_base: string;
  single_base: boolean;
}

export interface AdminRuntimeSecret {
  key: string;
  label: string;
  configured: boolean;
  source: "d1" | "env" | "none";
  can_generate: boolean;
}

export interface AdminProjectSetting {
  key: string;
  label: string;
  type: "string" | "boolean" | "json";
  value: string | boolean | PublicNavItem[] | null;
  configured: boolean;
  source: "d1" | "env" | "default" | "none";
}

export interface AdminDNSRecord {
  type: "A" | "AAAA";
  name: string;
  content: string;
  action: string;
}

export interface AdminNodeCheck {
  healthy: boolean;
  domain: string;
  checked_at: number;
  checks: {
    generate_204: EndpointCheck;
    info: EndpointCheck;
  };
}

export interface AdminNodeManualInstall {
  arch: "amd64" | "arm64";
  binary_url: string;
  sha256: string;
  size: number;
  steps: string[];
}

export interface AdminNodeInit {
  node_id?: string;
  token: string;
  expires_at: number;
  pull_command: string;
  init_string?: string;
  /** Per-arch manual install (download + checksum + init) steps. */
  manual?: AdminNodeManualInstall[];
  installDir?: string;
  dataDir?: string;
  binaryName?: string;
  serviceName?: string;
  runUser?: string;
}

export interface AdminManagedCertificate {
  bundle_id: string;
  domain: string;
  version: number;
  cert_expires_at: number;
  created_at: number;
  fingerprint_sha256: string;
  domains: string[];
  cert_pem: string;
  ca_pem: string;
  sync_status: string;
  synced_at: number | null;
  nodes: Array<{
    node_id: string;
    status: string;
    synced_at: number | null;
  }>;
}

export interface AdminCertificateImportInput {
  cert_pem: string;
  key_pem: string;
  ca_pem?: string;
  cert_expires_at: number;
  domains?: string[];
}

export type AdminCertificateDebug = Record<string, unknown>;

export class AdminCertificateActionError extends Error {
  readonly debug?: AdminCertificateDebug;
  readonly payload?: unknown;

  constructor(message: string, debug?: AdminCertificateDebug, payload?: unknown) {
    super(message);
    this.name = "AdminCertificateActionError";
    this.debug = debug;
    this.payload = payload;
  }
}

export interface AdminNodeSaveResult {
  node: AdminNode;
  init?: AdminNodeInit;
}

export interface AdminUser {
  id: string;
  username: string;
  role: string;
  has_totp: boolean;
  created_at: number;
  updated_at: number;
}

export interface DatabaseStatus {
  status: "ready" | "empty" | "incompatible";
  table_count: number;
  existing_tables: string[];
  missing_tables: string[];
  /** Migrations not yet applied; a ready DB can still have pending upgrades. */
  pending_migrations?: string[];
}

export interface AdminSession {
  authenticated: boolean;
  onboarding_required: boolean;
  db_init_required?: boolean;
  db_status?: DatabaseStatus;
  user: AdminUser | null;
  expires_at?: number;
}

export interface AdminLoginInput {
  username: string;
  password: string;
  totp_code?: string;
}

export interface AdminTotpSetup {
  secret: string;
  otpauth_url: string;
  user: AdminUser;
}

export interface EndpointCheck {
  ok: boolean;
  status?: number;
  duration_ms: number;
  error?: string;
  node?: string;
  domain?: string;
}

export interface TokenResponse {
  token: string;
  expires_at: number;
  node: string;
  domain: string;
  link_id?: string;
  sizes?: string[];
  extensions_remaining?: number;
}

export interface PublicConfig {
  branding?: {
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
  };
  challenge: {
    provider: "turnstile";
    site_key: string;
    required: boolean;
  };
  debug?: {
    streams: boolean;
  };
}

declare global {
  interface Window {
    /** Public config inlined into the HTML by the worker for flash-free first paint. */
    __LG_BOOT__?: PublicConfig;
  }
}

export interface PublicNavItem {
  label: string;
  href: string;
  active?: boolean;
  disabled?: boolean;
  badge?: string;
  external?: boolean;
}

export async function listNodes(): Promise<PublicNode[]> {
  const response = await fetchWithTimeout("/api/nodes");
  if (!response.ok) {
    const detail = await responseError(response, "Unable to load nodes");
    if (detail === "db_binding_missing" || detail === "db_init_required" || /D1 database binding is missing/i.test(detail)) {
      throw new Error("Not Available yet");
    }
    throw new Error(detail);
  }
  return (await response.json()) as PublicNode[];
}

export async function publicConfig(): Promise<PublicConfig> {
  const response = await fetchWithTimeout("/api/public-config");
  if (!response.ok) throw new Error("Unable to load public config");
  return (await response.json()) as PublicConfig;
}

export async function adminSession(): Promise<AdminSession> {
  const response = await fetchWithTimeout("/api/admin/session", { credentials: "same-origin" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load admin session"));
  return (await response.json()) as AdminSession;
}

export async function setupAdmin(input: AdminLoginInput): Promise<AdminSession> {
  return adminPostJSON<AdminSession>("/api/admin/setup", input);
}

export async function initAdminDatabase(confirm?: string): Promise<{ ok: boolean; db_status: DatabaseStatus; applied?: string[]; upgraded?: boolean; reset?: boolean }> {
  return adminPostJSON<{ ok: boolean; db_status: DatabaseStatus; applied?: string[]; upgraded?: boolean; reset?: boolean }>("/api/admin/db/init", confirm ? { confirm } : {});
}

export async function loginAdmin(input: AdminLoginInput): Promise<AdminSession> {
  return adminPostJSON<AdminSession>("/api/admin/login", input);
}

export async function logoutAdmin(): Promise<{ ok: boolean }> {
  return adminPostJSON<{ ok: boolean }>("/api/admin/logout", {});
}

export async function listAdminUsers(): Promise<AdminUser[]> {
  const response = await fetchWithTimeout("/api/admin/users", { credentials: "same-origin" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load admin users"));
  const body = (await response.json()) as { users: AdminUser[] };
  return body.users;
}

export async function createAdminUser(username: string, password: string): Promise<AdminUser> {
  const body = await adminPostJSON<{ user: AdminUser }>("/api/admin/users", { username, password });
  return body.user;
}

export async function resetAdminUserPassword(username: string, password: string): Promise<AdminUser> {
  const body = await adminPostJSON<{ user: AdminUser }>("/api/admin/users/password", { username, password });
  return body.user;
}

export async function deleteAdminUser(username: string): Promise<AdminUser> {
  const response = await fetchWithTimeout("/api/admin/users", {
    method: "DELETE",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username }),
  });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to delete admin user"));
  const body = (await response.json()) as { user: AdminUser };
  return body.user;
}

export async function setupAdminUserTotp(username: string, currentPassword: string, totpCode?: string): Promise<AdminTotpSetup> {
  return adminPostJSON<AdminTotpSetup>("/api/admin/users/totp/setup", { username, current_password: currentPassword, totp_code: totpCode });
}

export async function resetAdminUserTotp(username: string, currentPassword: string, totpCode?: string): Promise<AdminUser> {
  const body = await adminPostJSON<{ user: AdminUser }>("/api/admin/users/totp/reset", { username, current_password: currentPassword, totp_code: totpCode });
  return body.user;
}

export async function listAdminNodes(): Promise<AdminNode[]> {
  const response = await fetchWithTimeout("/api/admin/nodes", { credentials: "same-origin" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load admin nodes"));
  const body = (await response.json()) as { nodes: AdminNode[] };
  return body.nodes;
}

export async function upsertAdminNode(input: AdminNodeFormInput, dns?: AdminNodeDNSOptions): Promise<AdminNodeSaveResult> {
  const response = await fetchWithTimeout("/api/admin/nodes", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(buildAdminNodePayload(input, dns)),
  });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to save node"));
  return (await response.json()) as AdminNodeSaveResult;
}

/** Persist a new node order (top first) and return the refreshed list. */
export async function reorderAdminNodes(order: string[]): Promise<AdminNode[]> {
  const response = await fetchWithTimeout("/api/admin/nodes/reorder", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ order }),
  });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to reorder nodes"));
  const body = (await response.json()) as { nodes: AdminNode[] };
  return body.nodes;
}

export async function checkAdminNode(id: string): Promise<AdminNodeCheck> {
  return adminPostJSON<AdminNodeCheck>("/api/admin/nodes/check", { id });
}

export async function deleteAdminNode(id: string): Promise<{ deleted: boolean; id: string }> {
  const response = await fetchWithTimeout("/api/admin/nodes", {
    method: "DELETE",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ id }),
  });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to delete node"));
  return (await response.json()) as { deleted: boolean; id: string };
}

export async function issueAdminNodeInit(nodeID: string): Promise<AdminNodeInit> {
  const body = await adminPostJSON<{ init: AdminNodeInit }>("/api/admin/nodes/init", { node_id: nodeID });
  return body.init;
}

export interface PendingCertificateOrder {
  pending: boolean;
  status?: string;
  domains?: string[];
  created_at?: number;
  dns_records?: Array<{ name: string }>;
}

export async function listAdminCertificates(): Promise<{ certificates: AdminManagedCertificate[]; managed_domains: string[]; pending_order?: PendingCertificateOrder }> {
  const response = await fetchWithTimeout("/api/admin/certificates", { credentials: "same-origin" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load certificates"));
  return (await response.json()) as { certificates: AdminManagedCertificate[]; managed_domains: string[]; pending_order?: PendingCertificateOrder };
}

export async function syncAdminCertificates(): Promise<{ synced: number; skipped: number; debug?: AdminCertificateDebug }> {
  return adminCertificatePostJSON({ action: "sync" });
}

export async function beginAdminCertificateOrder(): Promise<{ status: string; reason?: string; domains?: string[]; dns_records?: Array<{ name: string; value: string }>; wait_seconds?: number; debug?: AdminCertificateDebug }> {
  return adminCertificatePostJSON({ action: "begin" });
}

export async function finalizeAdminCertificateOrder(): Promise<{ status: string; reason?: string; domains?: string[]; nodes?: number; debug?: AdminCertificateDebug }> {
  return adminCertificatePostJSON({ action: "finalize" });
}

export async function cancelAdminCertificateOrder(): Promise<{ status: string; debug?: AdminCertificateDebug }> {
  return adminCertificatePostJSON({ action: "cancel" });
}

export async function importAdminCertificate(input: AdminCertificateImportInput): Promise<{ status?: string; domains?: string[]; nodes?: number; skipped?: number; reason?: string; error?: string; acme_enabled?: boolean; debug?: AdminCertificateDebug }> {
  return adminCertificatePostJSON({ action: "import", ...input });
}

export async function registerZeroSSLEAB(email: string): Promise<{
  status: string;
  provider: string;
  email: string;
  eab_key_id: string;
  eab_alg: string;
  account_email_setting: AdminProjectSetting;
  eab_key_id_setting: AdminProjectSetting;
  eab_alg_setting: AdminProjectSetting;
  eab_hmac_secret: AdminRuntimeSecret;
  debug?: AdminCertificateDebug;
}> {
  return adminCertificatePostJSON({ action: "zerossl_eab_register", email });
}

export async function getAdminDNSSettings(): Promise<AdminDNSSettings | null> {
  const response = await fetchWithTimeout("/api/admin/dns-settings", { credentials: "same-origin" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load DNS settings"));
  const body = (await response.json()) as { settings: AdminDNSSettings | null };
  return body.settings;
}

export async function saveAdminDNSSettings(settings: AdminDNSSettings): Promise<AdminDNSSettings> {
  const response = await fetchWithTimeout("/api/admin/dns-settings", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(settings),
  });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to save DNS settings"));
  const body = (await response.json()) as { settings: AdminDNSSettings };
  return body.settings;
}

export async function listAdminRuntimeSecrets(): Promise<AdminRuntimeSecret[]> {
  const response = await fetchWithTimeout("/api/admin/runtime-secrets", { credentials: "same-origin" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load runtime secrets"));
  const body = (await response.json()) as { secrets: AdminRuntimeSecret[] };
  return body.secrets;
}

export async function saveAdminRuntimeSecret(key: string, value: string, override = false): Promise<AdminRuntimeSecret> {
  return adminPostJSON("/api/admin/runtime-secrets", { key, value, override });
}

export async function generateAdminRuntimeSecret(key: string, confirm: string, override = false): Promise<AdminRuntimeSecret> {
  return adminPostJSON("/api/admin/runtime-secrets", { key, generate: true, confirm, override });
}

export async function listAdminProjectSettings(): Promise<AdminProjectSetting[]> {
  const response = await fetchWithTimeout("/api/admin/project-settings", { credentials: "same-origin" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load project settings"));
  const body = (await response.json()) as { settings: AdminProjectSetting[] };
  return body.settings;
}

export async function saveAdminProjectSetting(key: string, value: string | boolean | PublicNavItem[]): Promise<AdminProjectSetting> {
  return adminPostJSON("/api/admin/project-settings", { key, value });
}

export async function resetAdminProjectSetting(key: string, confirm: string): Promise<AdminProjectSetting> {
  return adminPostJSON("/api/admin/project-settings", { key, reset: true, confirm });
}

export async function upsertAdminNodeDNS(input: AdminDNSInput): Promise<{ records: AdminDNSRecord[]; domains: { domain: string; domain_v4: string; domain_v6: string } }> {
  return adminPostJSON("/api/admin/nodes/dns", input);
}

export async function requestDownloadToken(node: string, turnstileToken: string, size?: string): Promise<TokenResponse> {
  return postJSON<TokenResponse>("/api/token/download", buildDownloadTokenPayload(node, turnstileToken, size));
}

export async function extendDownloadToken(node: string, linkID: string, token: string): Promise<TokenResponse> {
  return postJSON<TokenResponse>("/api/token/download/extend", { node, link_id: linkID, token });
}

export async function requestIperfSession(input: {
  node: string;
  mode: string;
  reverse: boolean;
  duration: number;
  parallel: number;
  turnstileToken: string;
}): Promise<{ session_id: string; host: string; port: number; command: string; expires_at: number; max_runs: number; mode?: "tcp" | "udp"; reverse?: boolean }> {
  return postJSON("/api/iperf/session", buildIperfSessionPayload(input));
}

export async function closeIperfSession(node: string, sessionID: string): Promise<{ ok: boolean; status?: string }> {
  return postJSON("/api/iperf/session/close", { node, session_id: sessionID });
}

export function buildDownloadTokenPayload(node: string, turnstileToken: string, size?: string) {
  return {
    node,
    turnstile_token: turnstileToken,
    ...(size ? { size } : {}),
  };
}

export function buildAdminNodePayload(input: AdminNodeFormInput, dns?: AdminNodeDNSOptions) {
  const payload: Record<string, unknown> = {
    id: input.id.trim(),
    internal_id: input.internal_id?.trim() || undefined,
    domain: input.domain.trim(),
    port: input.port,
    domain_v4: input.domain_v4.trim(),
    domain_v6: input.domain_v6.trim(),
    display_name: input.display_name.trim(),
    display_label: input.display_label.trim(),
    public_ipv4: input.public_ipv4.trim(),
    public_ipv6: input.public_ipv6.trim(),
    description: input.description.trim(),
    buy_url: input.buy_url.trim(),
    buy_label: input.buy_label.trim(),
    bgp_url: input.bgp_url.trim(),
    dynamic_ip: input.dynamic_ip,
    profile_id: input.profile_id.trim() || "default",
    enabled: input.enabled,
    hidden: input.hidden,
    maintenance: input.maintenance,
    features: normalizeAdminNodeFeatures(input.features),
  };
  if (dns) {
    payload.auto_dns = dns.enabled;
    if (dns.enabled) {
      payload.dns_mode = dns.mode;
      payload.dns_prefix = dns.prefix?.trim() || undefined;
    }
  }
  return payload;
}

function normalizeAdminNodeFeatures(features: AdminNodeFormInput["features"] | string): AdminNodeFeature[] {
  const values = Array.isArray(features) ? features : features.split(",");
  return values
    .map((feature) => feature.trim())
    .filter(isAdminNodeFeature);
}

export function buildIperfSessionPayload(input: {
  node: string;
  mode: string;
  reverse: boolean;
  duration: number;
  parallel: number;
  turnstileToken: string;
}) {
  return {
    node: input.node,
    mode: input.mode,
    reverse: input.reverse,
    duration: input.duration,
    parallel: input.parallel,
    direction: input.reverse ? "reverse" : "download",
    turnstile_token: input.turnstileToken,
  };
}

export function buildDownloadURL(node: Pick<PublicNode, "domain">, token: string, size: string): string {
  return `https://${node.domain}/download/${encodeURIComponent(token)}/${encodeURIComponent(size)}`;
}

export function buildJobWSURL(node: Pick<PublicNode, "id">, token: string): string {
  const params = new URLSearchParams({ node: node.id, token });
  return `${workerWSOrigin()}/api/jobs/ws?${params.toString()}`;
}

export interface LiveSessionResponse {
  token: string;
  expires_at: number;
  node: string;
  domain: string;
}

export async function requestLiveSession(node: string, turnstileToken?: string): Promise<LiveSessionResponse> {
  return postJSON<LiveSessionResponse>("/api/jobs/live-session", buildLiveSessionPayload(node, turnstileToken));
}

export function buildLiveSessionPayload(node: string, turnstileToken?: string) {
  return {
    node,
    turnstile_token: turnstileToken,
  };
}

export function buildLiveWSURL(node: Pick<PublicNode, "id">, token: string): string {
  const params = new URLSearchParams({ node: node.id, token });
  return `${workerWSOrigin()}/api/jobs/live?${params.toString()}`;
}

export function buildJobLiveWSURL(node: Pick<PublicNode, "id">): string {
  const params = new URLSearchParams({ node: node.id });
  return `${workerWSOrigin()}/api/jobs/live?${params.toString()}`;
}

export function buildIperfWSURL(node: Pick<PublicNode, "id">, sessionID: string): string {
  const params = new URLSearchParams({ node: node.id, session_id: sessionID });
  return `${workerWSOrigin()}/api/iperf/session/ws?${params.toString()}`;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const response = await fetchWithTimeout(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(await responseError(response, `${path} returned ${response.status}`));
  }
  return (await response.json()) as T;
}

async function adminPostJSON<T>(path: string, body: unknown): Promise<T> {
  const response = await fetchWithTimeout(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw adminApiError(await responseError(response, `${path} returned ${response.status}`));
  return (await response.json()) as T;
}

function adminApiError(message: string): Error {
  if (message === "unauthorized") return new AdminUnauthorizedError(message);
  return new Error(message);
}

async function adminCertificatePostJSON<T extends { debug?: AdminCertificateDebug }>(body: unknown): Promise<T> {
  const response = await fetchWithTimeout("/api/admin/certificates", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await responseJSON(response);
  if (!response.ok) {
    const message = responseMessage(payload, `/api/admin/certificates returned ${response.status}`);
    if (response.status === 401 || message === "unauthorized") throw new AdminUnauthorizedError();
    throw new AdminCertificateActionError(message, responseDebug(payload), payload);
  }
  return payload as T;
}

async function responseError(response: Response, fallback: string): Promise<string> {
  if (response.status === 401) return "unauthorized";
  let detail = fallback;
  try {
    const payload = (await response.json()) as { error?: string; message?: string };
    if (payload.error) detail = payload.error;
    if (payload.error === "db_binding_missing" && typeof payload.message === "string" && payload.message) {
      detail = payload.message;
    }
  } catch {}
  return detail;
}

async function responseJSON(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

function responseMessage(payload: unknown, fallback: string): string {
  if (!isPlainObject(payload)) return fallback;
  if (typeof payload.error === "string") return payload.error;
  if (typeof payload.reason === "string") return payload.reason;
  return fallback;
}

function responseDebug(payload: unknown): AdminCertificateDebug | undefined {
  if (!isPlainObject(payload) || !isPlainObject(payload.debug)) return undefined;
  return payload.debug;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function workerWSOrigin(): string {
  const location = globalThis.location;
  if (!location?.host) throw new Error("worker_origin_unavailable");
  return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}`;
}

export interface ClientInfo {
  ip: string;
  country: string;
  city: string;
  asn: string;
  asOrg: string;
  colo: string;
  httpProtocol: string;
  tlsVersion: string;
}

export async function fetchClientInfo(): Promise<ClientInfo> {
  const response = await fetchWithTimeout("/api/client-info");
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load client info"));
  return (await response.json()) as ClientInfo;
}

export interface ClientTraceInfo {
  visitScheme: string;
  http: string;
  colo: string;
  loc: string;
}

export async function fetchClientTraceInfo(): Promise<ClientTraceInfo> {
  const response = await fetchWithTimeout("/cdn-cgi/trace", { cache: "no-store" });
  if (!response.ok) throw adminApiError(await responseError(response, "Unable to load trace info"));
  const text = await response.text();
  const data = Object.fromEntries(
    text
      .trim()
      .split(/\r?\n/)
      .map((line) => line.split("=", 2))
      .filter(([key, value]) => key && value),
  ) as Record<string, string>;
  return {
    visitScheme: data.visit_scheme || "",
    http: data.http || "",
    colo: data.colo || "",
    loc: data.loc || "",
  };
}
