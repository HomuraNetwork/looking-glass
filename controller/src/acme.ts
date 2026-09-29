import { Env, ServiceConfigError } from "./config";
import { listAdminNodes } from "./db";
import { deleteDNSRecord, upsertDNSRecord } from "./dns";
import { getDNSSettings, DNSSettings } from "./dns-settings";
import { getBooleanProjectSetting, getStringProjectSetting } from "./project-settings";
import { getRuntimeSecret, setRuntimeSecret, generateRuntimeSecretValue } from "./runtime-secrets";
import { storeNodeCertificateBundle, activeManagedCertificateBundles, findCertificateBundleForDomain } from "./certificates";
import { acquireTaskLock, releaseTaskLock } from "./task-lock";
import { FlattenedSign, importJWK } from "jose";
import type { SqlDatabase } from "./runtime";

const DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory";
const DEFAULT_RENEW_BEFORE_DAYS = 30;
// Fallback validity when the CA's certificate expiry cannot be parsed. Only a
// last resort: the real NotAfter is read from the issued PEM.
const DEFAULT_CERT_VALIDITY_SECONDS = 89 * 24 * 60 * 60;
const ZEROSSL_EAB_ENDPOINT = "https://api.zerossl.com/acme/eab-credentials-email";

interface ACMEDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  meta?: {
    externalAccountRequired?: boolean;
  };
}

interface ACMEOrder {
  status: string;
  authorizations: string[];
  finalize: string;
  certificate?: string;
}

interface ACMEAuthorization {
  status: string;
  identifier: { type: string; value: string };
  challenges: Array<{ type: string; url: string; token: string; status?: string }>;
}

interface ACMEAccount {
  jwk: JsonWebKey;
  publicJWK: JsonWebKey;
  kid?: string;
}

interface ACMEClient {
  directory: ACMEDirectory;
  account: ACMEAccount;
  eab?: ACMEExternalAccountBinding;
  nonce?: string;
  fetcher: typeof fetch;
}

interface ACMEExternalAccountBinding {
  keyID: string;
  hmacKey: string;
  alg: "HS256" | "HS384" | "HS512";
}

interface ZeroSSLEABResponse {
  success?: boolean;
  eab_kid?: string;
  eab_hmac_key?: string;
  error?: unknown;
}

export class ACMERequestError extends Error {
  readonly status: number;
  readonly url: string;
  readonly method: string;
  readonly responseBody: string;
  readonly problem?: unknown;

  constructor(message: string, input: { status: number; url: string; method: string; responseBody: string; problem?: unknown }) {
    super(message);
    this.name = "ACMERequestError";
    this.status = input.status;
    this.url = input.url;
    this.method = input.method;
    this.responseBody = input.responseBody;
    this.problem = input.problem;
  }
}

export async function requestZeroSSLEABCredentials(
  email: string,
  fetcher: typeof fetch = fetch,
): Promise<{ email: string; keyID: string; hmacKey: string; alg: "HS256" }> {
  const normalizedEmail = email.trim().toLowerCase();
  if (!normalizedEmail || !normalizedEmail.includes("@")) throw new Error("acme_account_email_required");
  const response = await callFetch(fetcher, ZEROSSL_EAB_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: normalizedEmail }).toString(),
  });
  const responseBody = await response.text();
  let payload: ZeroSSLEABResponse | undefined;
  try {
    payload = responseBody ? JSON.parse(responseBody) as ZeroSSLEABResponse : undefined;
  } catch {
    payload = undefined;
  }
  if (!response.ok || payload?.success !== true || !payload.eab_kid || !payload.eab_hmac_key) {
    throw new ACMERequestError(`zerossl_eab_request_failed:${response.status}`, {
      status: response.status,
      url: ZEROSSL_EAB_ENDPOINT,
      method: "POST",
      responseBody: responseBody.slice(0, 8192),
      problem: payload?.error ?? payload,
    });
  }
  return {
    email: normalizedEmail,
    keyID: payload.eab_kid.trim(),
    hmacKey: payload.eab_hmac_key.trim(),
    alg: "HS256",
  };
}

export async function renewManagedCertificates(
  env: Env,
  fetcher: typeof fetch = fetch,
  options: { force?: boolean } = {},
): Promise<{ status: string; domains?: string[]; nodes?: number; reason?: string }> {
  return autoAdvanceCertificateIssuance(env, fetcher, options);
}

// ---- Staged (admin-driven) issuance -------------------------------------------------
// Splits issuance into short, separately-callable steps so the 180s DNS-propagation wait
// happens client-side rather than in one long-running serverless request:
//   begin  → create order, add DNS-01 TXT records, stash order state
//   (client waits ~180s for DNS propagation)
//   finalize → validate challenges, finalize CSR, download + store the cert

interface PendingChallenge {
  authz_url: string;
  challenge_url: string;
  identifier: string;
  txt_name: string;
  txt_value: string;
  triggered?: boolean;
}
interface StoredPendingOrder {
  order_url: string;
  finalize_url: string;
  csr_der: string;
  key_pem: string;
  domains: string[];
  challenges: PendingChallenge[];
  status: string;
  created_at: number;
}

interface ACMEConfig { dnsToken: string; zoneID: string; directoryURL: string; email: string | undefined; }

async function acmePreflight(env: Env): Promise<{ config: ACMEConfig } | { skip: { status: string; reason: string } }> {
  if (!env.DB) return { skip: { status: "skipped", reason: "d1_required" } };
  if (!(await getBooleanProjectSetting(env.DB, "ACME_ENABLED"))) return { skip: { status: "skipped", reason: "acme_disabled" } };
  if (!(await getDNSSettings(env.DB))) return { skip: { status: "skipped", reason: "dns_settings_required" } };
  const dnsToken = await getRuntimeSecret(env.DB, "CLOUDFLARE_DNSUPDATE_API_KEY");
  const zoneID = await getStringProjectSetting(env.DB, "CLOUDFLARE_ZONE_ID");
  if (!dnsToken || !zoneID) return { skip: { status: "skipped", reason: "dns_config_required" } };
  return {
    config: {
      dnsToken,
      zoneID,
      directoryURL: await getStringProjectSetting(env.DB, "ACME_DIRECTORY_URL") || DEFAULT_DIRECTORY_URL,
      email: await getStringProjectSetting(env.DB, "ACME_ACCOUNT_EMAIL"),
    },
  };
}

async function loadPendingOrder(db: SqlDatabase): Promise<StoredPendingOrder | null> {
  const row = await db.prepare("SELECT * FROM acme_pending_orders WHERE id = 'current'").first<Record<string, string>>();
  if (!row) return null;
  return {
    order_url: row.order_url,
    finalize_url: row.finalize_url,
    csr_der: row.csr_der,
    key_pem: row.key_pem,
    domains: JSON.parse(row.domains_json) as string[],
    challenges: JSON.parse(row.challenges_json) as PendingChallenge[],
    status: row.status,
    created_at: Number(row.created_at),
  };
}

async function savePendingOrder(db: SqlDatabase, order: StoredPendingOrder): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db.prepare(
    `INSERT INTO acme_pending_orders (id, order_url, finalize_url, csr_der, key_pem, domains_json, challenges_json, status, created_at, updated_at)
     VALUES ('current', ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET order_url=excluded.order_url, finalize_url=excluded.finalize_url, csr_der=excluded.csr_der,
       key_pem=excluded.key_pem, domains_json=excluded.domains_json, challenges_json=excluded.challenges_json,
       status=excluded.status, created_at=excluded.created_at, updated_at=excluded.updated_at`,
  ).bind(order.order_url, order.finalize_url, order.csr_der, order.key_pem, JSON.stringify(order.domains),
    JSON.stringify(order.challenges), order.status, order.created_at, now).run();
}

async function deletePendingOrder(db: SqlDatabase): Promise<void> {
  await db.prepare("DELETE FROM acme_pending_orders WHERE id = 'current'").bind().run();
}

async function cleanupOrderDNS(config: ACMEConfig, challenges: PendingChallenge[]): Promise<void> {
  for (const ch of challenges) {
    try { await deleteDNSRecord(config.dnsToken, config.zoneID, { type: "TXT", name: ch.txt_name }); } catch { /* best-effort */ }
  }
}

export interface PendingOrderInfo {
  pending: boolean;
  status?: string;
  domains?: string[];
  created_at?: number;
  dns_records?: Array<{ name: string }>;
  wait_seconds?: number;
}

export async function pendingCertificateOrder(env: Env): Promise<PendingOrderInfo> {
  if (!env.DB) return { pending: false };
  const order = await loadPendingOrder(env.DB);
  if (!order) return { pending: false };
  return {
    pending: true,
    status: order.status,
    domains: order.domains,
    created_at: order.created_at,
    dns_records: order.challenges.map((c) => ({ name: c.txt_name })),
  };
}

export async function beginManagedCertificateOrder(
  env: Env,
  fetcher: typeof fetch = fetch,
): Promise<{ status: string; reason?: string; domains?: string[]; dns_records?: Array<{ name: string; value: string }>; wait_seconds?: number }> {
  const pre = await acmePreflight(env);
  if ("skip" in pre) return pre.skip;
  const config = pre.config;
  const db = env.DB!;

  // Never replace an in-progress order implicitly: its CSR and TXT records
  // must remain paired until it is finalized or explicitly cancelled.
  const prior = await loadPendingOrder(db);
  if (prior) return {
    status: "dns_added",
    reason: "order_pending",
    domains: prior.domains,
    dns_records: prior.challenges.map((challenge) => ({ name: challenge.txt_name, value: challenge.txt_value })),
    wait_seconds: 0,
  };

  const dnsSettings = (await getDNSSettings(db))!;
  const domains = managedCertificateDomains(dnsSettings);
  const client = await newACMEClient(env, config.directoryURL, fetcher);
  await ensureACMEAccount(client, config.email);
  const orderResponse = await acmeRequest(client, client.directory.newOrder, {
    identifiers: domains.map((domain) => ({ type: "dns", value: domain })),
  }, false);
  const orderURL = orderResponse.headers.get("location");
  if (!orderURL) throw new Error("acme_order_url_missing");
  const order = (await orderResponse.json()) as ACMEOrder;

  const challenges: PendingChallenge[] = [];
  for (const authorizationURL of order.authorizations) {
    const authorization = await acmePost<ACMEAuthorization>(client, authorizationURL, null);
    if (authorization.status === "valid") continue;
    const challenge = authorization.challenges.find((item) => item.type === "dns-01");
    if (!challenge) throw new Error("acme_dns01_challenge_missing");
    const txt = await dns01TXTValue(challenge.token, client.account.publicJWK);
    const name = acmeChallengeName(authorization.identifier.value);
    challenges.push({ authz_url: authorizationURL, challenge_url: challenge.url, identifier: authorization.identifier.value, txt_name: name, txt_value: txt });
  }

  const csr = await createCSR(domains);
  await savePendingOrder(db, {
    order_url: orderURL,
    finalize_url: order.finalize,
    csr_der: csr.csrDERBase64URL,
    key_pem: csr.privateKeyPEM,
    domains,
    challenges,
    status: "dns_adding",
    created_at: Math.floor(Date.now() / 1000),
  });
  // Persist the order before DNS writes. If a provider call fails partway
  // through, cron or an admin retry can safely upsert the same TXT values.
  for (const challenge of challenges) {
    await upsertDNSRecord(config.dnsToken, config.zoneID, {
      type: "TXT",
      name: challenge.txt_name,
      content: challenge.txt_value,
    });
  }
  await savePendingOrder(db, {
    order_url: orderURL,
    finalize_url: order.finalize,
    csr_der: csr.csrDERBase64URL,
    key_pem: csr.privateKeyPEM,
    domains,
    challenges,
    status: "dns_added",
    created_at: Math.floor(Date.now() / 1000),
  });

  return {
    status: "dns_added",
    domains,
    dns_records: challenges.map((c) => ({ name: c.txt_name, value: c.txt_value })),
    wait_seconds: challenges.length > 0 ? 180 : 0,
  };
}

export async function finalizeManagedCertificateOrder(
  env: Env,
  fetcher: typeof fetch = fetch,
): Promise<{ status: string; reason?: string; domains?: string[]; nodes?: number }> {
  const pre = await acmePreflight(env);
  if ("skip" in pre) return pre.skip;
  const config = pre.config;
  const db = env.DB!;
  const pending = await loadPendingOrder(db);
  if (!pending) return { status: "skipped", reason: "no_pending_order" };

  const client = await newACMEClient(env, config.directoryURL, fetcher);
  await ensureACMEAccount(client, config.email);
  if (pending.status === "dns_adding") {
    for (const challenge of pending.challenges) {
      await upsertDNSRecord(config.dnsToken, config.zoneID, {
        type: "TXT",
        name: challenge.txt_name,
        content: challenge.txt_value,
      });
    }
    await savePendingOrder(db, { ...pending, status: "dns_added" });
    return { status: "waiting", reason: "dns_records_added", domains: pending.domains };
  }
  for (const [challengeIndex, ch] of pending.challenges.entries()) {
    const authorization = await acmePost<ACMEAuthorization>(client, ch.authz_url, null);
    if (authorization.status === "valid") continue;
    if (authorization.status === "invalid") throw new Error("acme_authorization_invalid");
    if (!ch.triggered) {
      await acmePost(client, ch.challenge_url, {});
      const challenges = pending.challenges.map((item, index) => index === challengeIndex ? { ...item, triggered: true } : item);
      await savePendingOrder(db, { ...pending, challenges });
    }
    return { status: "waiting", reason: "authorization_pending", domains: pending.domains };
  }
  const order = await acmePost<ACMEOrder>(client, pending.order_url, null);
  if (order.status === "invalid") throw new Error("acme_order_invalid");
  if (order.status === "ready") {
    await acmePost<ACMEOrder>(client, pending.finalize_url, { csr: pending.csr_der });
    await savePendingOrder(db, { ...pending, status: "finalizing" });
    return { status: "waiting", reason: "order_finalizing", domains: pending.domains };
  }
  if (order.status !== "valid" || !order.certificate) {
    return { status: "waiting", reason: order.status, domains: pending.domains };
  }
  const certPEM = await acmePost<string>(client, order.certificate, null, "text");
  const certExpiresAt = certificateExpiryOrFallback(certPEM);
  let stored = 0;
  for (const node of await listAdminNodes(db)) {
    try {
      await storeNodeCertificateBundle(env, node, { certPEM, keyPEM: pending.key_pem, caPEM: "", certExpiresAt, domains: pending.domains });
      stored += 1;
    } catch (error) {
      if (!(error instanceof Error && error.message === "node_encryption_key_required")) throw error;
    }
  }
  await cleanupOrderDNS(config, pending.challenges);
  await deletePendingOrder(db);
  return { status: "issued", domains: pending.domains, nodes: stored };
}

export async function cancelManagedCertificateOrder(env: Env): Promise<{ status: string }> {
  if (!env.DB) return { status: "skipped" };
  const locked = await withCertificateIssuanceLock(env, async () => {
    const pending = await loadPendingOrder(env.DB!);
    if (pending) {
      const pre = await acmePreflight(env);
      if ("config" in pre) await cleanupOrderDNS(pre.config, pending.challenges);
      await deletePendingOrder(env.DB!);
    }
    return { status: "cancelled" };
  });
  return locked.ran ? locked.value : { status: "locked" };
}

const AUTO_ISSUE_LOCK = "acme_auto_issue";
// Long enough that a slow begin/finalize is not re-entered by concurrent pulls,
// short enough that a crashed attempt is retried within a few minutes.
const AUTO_ISSUE_LOCK_TTL_SECONDS = 300;
// A begin() is followed by a DNS-01 propagation wait; the next pull (or the
// cron) finalizes only after this. Until then an order is "waiting".
const AUTO_FINALIZE_AFTER_SECONDS = 60;

/**
 * Run an ACME issuance step while holding the shared issuance lock, so a
 * manual admin action and the pull/cron-driven flow cannot open competing
 * orders for the same certificate. Returns null (rather than running) when the
 * lock is already held by someone else.
 */
export async function withCertificateIssuanceLock<T>(
  env: Env,
  task: () => Promise<T>,
): Promise<{ ran: true; value: T } | { ran: false }> {
  if (!env.DB) throw new Error("d1_required");
  const fence = await acquireTaskLock(env.DB, AUTO_ISSUE_LOCK, AUTO_ISSUE_LOCK_TTL_SECONDS);
  if (fence === null) return { ran: false };
  try {
    return { ran: true, value: await task() };
  } finally {
    await releaseTaskLock(env.DB, AUTO_ISSUE_LOCK, fence);
  }
}

/**
 * Advance staged certificate issuance from a node pull, so a node with no valid
 * certificate does not have to wait for the next cron pass (or an admin click)
 * to get one.
 *
 * Runs one step per invocation, guarded by a short lock because every node
 * pulls around the same time:
 *   - pending order -> advance exactly one bounded ACME step
 *   - no order and certificates missing/due -> begin an order
 *
 * Best-effort: callers must never let this fail the pull. Returns a status for
 * logging only.
 */
export async function autoAdvanceCertificateIssuance(
  env: Env,
  fetcher: typeof fetch = fetch,
  options: { force?: boolean } = {},
): Promise<{ status: string; reason?: string; domains?: string[]; nodes?: number }> {
  if (!env.DB) return { status: "skipped", reason: "d1_required" };
  const pre = await acmePreflight(env);
  if ("skip" in pre) return { status: "skipped", reason: pre.skip.reason };

  const fence = await acquireTaskLock(env.DB, AUTO_ISSUE_LOCK, AUTO_ISSUE_LOCK_TTL_SECONDS);
  if (fence === null) {
    return { status: "skipped", reason: "locked" };
  }
  try {
    // Re-read state only after taking the shared lock: a manual begin/cancel or
    // another cron/pull may have changed the order while we waited for it.
    const pending = await loadPendingOrder(env.DB);
    if (pending) {
      if (Math.floor(Date.now() / 1000) - pending.created_at < AUTO_FINALIZE_AFTER_SECONDS) {
        return { status: "waiting", reason: "dns_propagation", domains: pending.domains };
      }
      return await finalizeManagedCertificateOrder(env, fetcher);
    }

    const nodes = (await listAdminNodes(env.DB)).filter((node) => node.enabled && !node.hidden);
    if (nodes.length === 0) return { status: "skipped", reason: "no_nodes" };
    const needsCertificate = await someNodeLacksCertificate(env.DB, nodes);
    const renewalNeeded = options.force || needsCertificate || await certificateRenewalNeeded(
      env.DB,
      renewalWindowSeconds(await renewBeforeDays(env)),
    );
    if (!renewalNeeded) return { status: "skipped", reason: "certificate_fresh" };

    const result = await beginManagedCertificateOrder(env, fetcher);
    return { status: result.status === "dns_added" ? "begun" : result.status, reason: result.reason };
  } finally {
    await releaseTaskLock(env.DB, AUTO_ISSUE_LOCK, fence);
  }
}

/** True when any of the given nodes has no active managed bundle covering it. */
async function someNodeLacksCertificate(db: SqlDatabase, nodes: Array<{ domain: string }>): Promise<boolean> {
  if (nodes.length === 0) return false;
  const bundles = await activeManagedCertificateBundles(db);
  if (bundles.length === 0) return true;
  return nodes.some((node) => !findCertificateBundleForDomain(bundles, node.domain));
}


export function managedCertificateDomains(settings: DNSSettings): string[] {
  const bases = new Set<string>();
  const add = (value: string) => {
    const normalized = value.trim().replace(/^\.+|\.+$/g, "");
    if (normalized) bases.add(normalized);
  };
  add(settings.base);
  if (!settings.single_base) {
    add(settings.v4_base || settings.base);
    add(settings.v6_base || settings.base);
  }
  return Array.from(bases).sort().map((domain) => `*.${domain}`);
}

async function newACMEClient(env: Env, directoryURL: string, fetcher: typeof fetch): Promise<ACMEClient> {
  let accountJWK = await getRuntimeSecret(env.DB, "ACME_ACCOUNT_JWK");
  if (!accountJWK) {
    if (!env.DB) throw new ServiceConfigError("DB");
    accountJWK = await generateRuntimeSecretValue("ACME_ACCOUNT_JWK");
    await setRuntimeSecret(env.DB, "ACME_ACCOUNT_JWK", accountJWK);
  }
  const jwk = JSON.parse(accountJWK) as JsonWebKey;
  const publicJWK = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const directoryResponse = await fetchACMEDirectory(fetcher, directoryURL);
  if (!directoryResponse.ok) throw await acmeHTTPError("acme_directory_failed", directoryResponse, directoryURL, "GET");
  const directory = (await directoryResponse.json()) as ACMEDirectory;
  return { directory, account: { jwk, publicJWK }, eab: await loadExternalAccountBinding(env), fetcher };
}

async function fetchACMEDirectory(fetcher: typeof fetch, directoryURL: string): Promise<Response> {
  let response: Response | null = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    response = await callFetch(fetcher, directoryURL, {
      headers: { accept: "application/json" },
    });
    if (response.status < 500) return response;
    if (attempt < 2) await sleep(1 + attempt);
  }
  return response ?? callFetch(fetcher, directoryURL);
}

async function ensureACMEAccount(client: ACMEClient, email: string | undefined): Promise<void> {
  const payload: Record<string, unknown> = { termsOfServiceAgreed: true };
  if (email) payload.contact = [`mailto:${email}`];
  if (client.eab) {
    payload.externalAccountBinding = await externalAccountBinding(client, client.directory.newAccount);
  } else if (client.directory.meta?.externalAccountRequired === true) {
    throw new ServiceConfigError("ACME_EAB_HMAC_KEY");
  }
  const response = await acmeRequest(client, client.directory.newAccount, payload, true);
  const kid = response.headers.get("location");
  if (!kid) throw new Error("acme_account_kid_missing");
  client.account.kid = kid;
}

async function loadExternalAccountBinding(env: Env): Promise<ACMEExternalAccountBinding | undefined> {
  const provider = await getStringProjectSetting(env.DB, "ACME_PROVIDER");
  if (!providerUsesExternalAccountBinding(provider)) return undefined;
  const keyID = await getStringProjectSetting(env.DB, "ACME_EAB_KEY_ID");
  const hmacKey = await getRuntimeSecret(env.DB, "ACME_EAB_HMAC_KEY");
  if (!keyID && !hmacKey) return undefined;
  if (!keyID) throw new ServiceConfigError("ACME_EAB_KEY_ID");
  if (!hmacKey) throw new ServiceConfigError("ACME_EAB_HMAC_KEY");
  return {
    keyID,
    hmacKey,
    alg: normalizeEABAlgorithm(await getStringProjectSetting(env.DB, "ACME_EAB_ALG")),
  };
}

function providerUsesExternalAccountBinding(value: string | undefined): boolean {
  return value === "zerossl" || value === "google" || value === "google-staging" || value === "custom-eab";
}

async function externalAccountBinding(client: ACMEClient, url: string): Promise<Record<string, string>> {
  if (!client.eab) throw new ServiceConfigError("ACME_EAB_HMAC_KEY");
  const key = await importJWK({ kty: "oct", k: normalizeBase64URLSecret(client.eab.hmacKey) }, client.eab.alg);
  return await new FlattenedSign(new TextEncoder().encode(JSON.stringify(client.account.publicJWK)))
    .setProtectedHeader({
      alg: client.eab.alg,
      kid: client.eab.keyID,
      url,
    })
    .sign(key) as unknown as Record<string, string>;
}

function normalizeEABAlgorithm(value: string | undefined): ACMEExternalAccountBinding["alg"] {
  const alg = (value || "HS256").trim().toUpperCase();
  if (alg === "HS256" || alg === "HS384" || alg === "HS512") return alg;
  throw new ServiceConfigError("ACME_EAB_ALG");
}

function normalizeBase64URLSecret(value: string): string {
  return value.trim().replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function acmePost<T>(client: ACMEClient, url: string, payload: unknown, responseType: "json" | "text" = "json"): Promise<T> {
  const response = await acmeRequest(client, url, payload, false);
  if (responseType === "text") return (await response.text()) as T;
  return (await response.json()) as T;
}

async function acmeRequest(client: ACMEClient, url: string, payload: unknown, useJWK: boolean): Promise<Response> {
  const nonce = client.nonce || await newNonce(client);
  const protectedHeader: Record<string, unknown> = {
    alg: "ES256",
    nonce,
    url,
    ...(useJWK ? { jwk: client.account.publicJWK } : { kid: client.account.kid }),
  };
  const protectedPart = base64URLString(JSON.stringify(protectedHeader));
  const payloadPart = payload === null ? "" : base64URLString(JSON.stringify(payload));
  const signature = await signES256(client.account.jwk, `${protectedPart}.${payloadPart}`);
  const response = await callFetch(client.fetcher, url, {
    method: "POST",
    headers: { "content-type": "application/jose+json" },
    body: JSON.stringify({ protected: protectedPart, payload: payloadPart, signature }),
  });
  client.nonce = response.headers.get("replay-nonce") || undefined;
  if (!response.ok) throw await acmeHTTPError("acme_request_failed", response, url, "POST");
  return response;
}

async function acmeHTTPError(prefix: string, response: Response, url: string, method: string): Promise<ACMERequestError> {
  const responseBody = await response.text();
  return new ACMERequestError(`${prefix}:${response.status}`, {
    status: response.status,
    url,
    method,
    responseBody: responseBody.slice(0, 8192),
    problem: parseACMEProblem(responseBody),
  });
}

function parseACMEProblem(responseBody: string): unknown | undefined {
  if (!responseBody.trim()) return undefined;
  try {
    return JSON.parse(responseBody) as unknown;
  } catch {
    return undefined;
  }
}

async function newNonce(client: ACMEClient): Promise<string> {
  const response = await callFetch(client.fetcher, client.directory.newNonce, { method: "HEAD" });
  const nonce = response.headers.get("replay-nonce");
  if (!response.ok || !nonce) throw new Error("acme_nonce_failed");
  return nonce;
}

function callFetch(fetcher: typeof fetch, input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const signal = init?.signal ?? AbortSignal.timeout(8_000);
  return fetcher.call(globalThis, input, { ...init, signal });
}

async function dns01TXTValue(token: string, jwk: JsonWebKey): Promise<string> {
  const keyAuthorization = `${token}.${await jwkThumbprint(jwk)}`;
  return base64URLBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(keyAuthorization))));
}

function acmeChallengeName(identifier: string): string {
  return `_acme-challenge.${identifier.replace(/^\*\./, "")}`;
}

async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  return base64URLBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })))));
}

async function signES256(jwk: JsonWebKey, signingInput: string): Promise<string> {
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(signingInput)));
  return base64URLBytes(signature);
}

async function createCSR(domains: string[]): Promise<{ csrDERBase64URL: string; privateKeyPEM: string }> {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const privateKey = "privateKey" in keyPair ? keyPair.privateKey : keyPair;
  const publicKey = "publicKey" in keyPair ? keyPair.publicKey : keyPair;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
  const cri = derSeq(
    derInt(new Uint8Array([0])),
    // Empty subject (RDNSequence with no RDNs). A Subject CN would be treated by the ACME
    // CA (Boulder) as an extra DNS identifier; since the order identifiers are wildcards
    // only, including a de-wildcarded CN makes the CSR identifier set differ from the order
    // (RFC 8555 §7.4). Authorize via subjectAltName exclusively.
    derSeq(),
    spki,
    derContext0(derSeq(derOID("1.2.840.113549.1.9.14"), derSet(derSeq(derExtensionSAN(domains))))),
  );
  const criBuffer = cri.buffer.slice(cri.byteOffset, cri.byteOffset + cri.byteLength) as ArrayBuffer;
  const rawSig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, criBuffer));
  const csr = derSeq(cri, derSeq(derOID("1.2.840.10045.4.3.2")), derBitString(ecdsaRawToDER(rawSig)));
  return {
    csrDERBase64URL: base64URLBytes(csr),
    privateKeyPEM: pem("PRIVATE KEY", pkcs8),
  };
}

function derExtensionSAN(domains: string[]): Uint8Array {
  const names = derSeq(...domains.map((domain) => derTLV(0x82, ascii(domain))));
  return derSeq(derOID("2.5.29.17"), derOctetString(names));
}

function ecdsaRawToDER(signature: Uint8Array): Uint8Array {
  const half = signature.length / 2;
  return derSeq(derInt(signature.slice(0, half)), derInt(signature.slice(half)));
}

function derSeq(...parts: Uint8Array[]): Uint8Array {
  return derTLV(0x30, concat(...parts));
}

function derSet(...parts: Uint8Array[]): Uint8Array {
  return derTLV(0x31, concat(...parts));
}

function derContext0(...parts: Uint8Array[]): Uint8Array {
  return derTLV(0xa0, concat(...parts));
}

function derInt(value: Uint8Array): Uint8Array {
  let bytes = trimLeadingZeros(value);
  if (bytes.length === 0) bytes = new Uint8Array([0]);
  if (bytes[0] & 0x80) bytes = concat(new Uint8Array([0]), bytes);
  return derTLV(0x02, bytes);
}

function derBitString(value: Uint8Array): Uint8Array {
  return derTLV(0x03, concat(new Uint8Array([0]), value));
}

function derOctetString(value: Uint8Array): Uint8Array {
  return derTLV(0x04, value);
}

function derOID(oid: string): Uint8Array {
  const parts = oid.split(".").map((part) => Number(part));
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let value = part >> 7;
    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }
    bytes.push(...stack);
  }
  return derTLV(0x06, new Uint8Array(bytes));
}

function derTLV(tag: number, value: Uint8Array): Uint8Array {
  return concat(new Uint8Array([tag]), derLength(value.length), value);
}

function derLength(length: number): Uint8Array {
  if (length < 128) return new Uint8Array([length]);
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function trimLeadingZeros(value: Uint8Array): Uint8Array {
  let index = 0;
  while (index < value.length - 1 && value[index] === 0) index += 1;
  return value.slice(index);
}

function pem(label: string, der: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...der));
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * Real certificate expiry from the issued PEM, falling back to a conservative
 * default only if the DER cannot be parsed. Never invent a longer validity than
 * the CA granted: that would keep the renewal gate quiet past actual expiry.
 */
function certificateExpiryOrFallback(certPEM: string): number {
  return certificateNotAfter(certPEM) ?? Math.floor(Date.now() / 1000) + DEFAULT_CERT_VALIDITY_SECONDS;
}

function ascii(value: string): Uint8Array {
  return Uint8Array.from(value, (char) => char.charCodeAt(0));
}

/**
 * Parse NotAfter (Unix seconds) from the first CERTIFICATE PEM block.
 *
 * The CA decides the real validity (Lets Encrypt 90d, ZeroSSL 90d, some CAs
 * much less), so the expiry must come from the certificate itself: writing a
 * hardcoded 89 days would mark a short-lived certificate "fresh" long after it
 * actually expired, and the renewal gate would never fire. Workers have no
 * X.509 parser, so this walks the DER minimally: Certificate -> tbsCertificate
 * -> [validity] -> notAfter (UTCTime or GeneralizedTime).
 *
 * Returns null when the input cannot be parsed; callers fall back to a
 * conservative default rather than trusting a wrong value.
 */
export function certificateNotAfter(pemText: string): number | null {
  const der = pemToDER(pemText);
  if (!der) return null;
  try {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    const certificate = derChildren(readDERElement(der, 0).value);
    const tbs = certificate[0];
    if (!tbs) return null;
    // tbsCertificate ::= SEQUENCE { version [0] OPTIONAL, serialNumber,
    //   signature, issuer, validity, ... }
    // The version tag (0xA0) is absent for v1 certificates, which shifts every
    // later field by one; locate validity by that.
    const fields = derChildren(tbs.value);
    const validityIndex = fields[0]?.tag === 0xa0 ? 4 : 3;
    const validity = fields[validityIndex];
    if (!validity) return null;
    const validityFields = derChildren(validity.value);
    const notAfter = validityFields[1];
    if (!notAfter) return null;
    return parseASN1Time(notAfter.tag, notAfter.value);
  } catch {
    return null;
  }
}

/** Read one DER element starting at `offset`, returning tag, value and next offset. */
function readDERElement(content: Uint8Array, offset: number): { tag: number; value: Uint8Array; next: number } {
  let index = offset;
  const tag = content[index];
  index += 1;
  let length = content[index];
  index += 1;
  if (length & 0x80) {
    const byteCount = length & 0x7f;
    length = 0;
    for (let i = 0; i < byteCount; i += 1) length = (length << 8) | content[index + i];
    index += byteCount;
  }
  return { tag, value: content.slice(index, index + length), next: index + length };
}

interface DERElement {
  tag: number;
  value: Uint8Array;
}

/** Split one level of DER SEQUENCE contents into child elements. */
function derChildren(content: Uint8Array): DERElement[] {
  const out: DERElement[] = [];
  let index = 0;
  while (index < content.length) {
    const tag = content[index];
    index += 1;
    let length = content[index];
    index += 1;
    if (length === undefined) break;
    if (length & 0x80) {
      const byteCount = length & 0x7f;
      length = 0;
      for (let i = 0; i < byteCount; i += 1) length = (length << 8) | content[index + i];
      index += byteCount;
    }
    out.push({ tag, value: content.slice(index, index + length) });
    index += length;
  }
  return out;
}

/** Decode a PEM block's base64 body to DER bytes. */
function pemToDER(pemText: string): Uint8Array | null {
  const match = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(pemText);
  if (!match) return null;
  const base64 = match[1].replace(/\s+/g, "");
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/** ASN.1 UTCTime (0x17) or GeneralizedTime (0x18) to Unix seconds. */
function parseASN1Time(tag: number, value: Uint8Array): number | null {
  const text = String.fromCharCode(...value);
  let year: number;
  let rest: string;
  if (tag === 0x17) {
    // YYMMDDHHMMSSZ; RFC 5280: YY >= 50 -> 19YY, else 20YY.
    const yy = Number(text.slice(0, 2));
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    rest = text.slice(2);
  } else if (tag === 0x18) {
    year = Number(text.slice(0, 4));
    rest = text.slice(4);
  } else {
    return null;
  }
  const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z?$/.exec(rest);
  if (!match) return null;
  const [, month, day, hour, minute, second] = match;
  const ms = Date.UTC(year, Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second));
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / 1000);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base64URLString(value: string): string {
  return base64URLBytes(new TextEncoder().encode(value));
}

function base64URLBytes(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function certificateRenewalNeeded(db: SqlDatabase, renewBeforeSeconds: number): Promise<boolean> {
  const row = await db.prepare("SELECT cert_expires_at FROM certificate_bundles WHERE active = 1 ORDER BY cert_expires_at ASC LIMIT 1").first<{ cert_expires_at: number }>();
  if (!row?.cert_expires_at) return true;
  return row.cert_expires_at <= Math.floor(Date.now() / 1000) + renewBeforeSeconds;
}

async function renewBeforeDays(env: Env): Promise<number> {
  const raw = await getStringProjectSetting(env.DB, "ACME_RENEW_BEFORE_DAYS");
  const parsed = Number(raw || DEFAULT_RENEW_BEFORE_DAYS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_RENEW_BEFORE_DAYS;
}

function renewalWindowSeconds(days: number): number {
  return Math.floor(days * 24 * 60 * 60);
}

function sleep(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}
