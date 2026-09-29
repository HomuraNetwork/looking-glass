import { describe, expect, it } from "vitest";
import { vi } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import type { Env } from "../src/config";
import worker from "../src/index";
import { buildSignedConfig } from "../src/enroll";
import { base64URLToBytes, bytesToBase64URL, sha256Hex, signCompact } from "../src/signing";

// Ed25519 signing keys are generated per test run instead of being committed:
// private JWK material must never live in the repository.
async function generateEd25519PrivateJWK(): Promise<JsonWebKey> {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"]);
  const privateKey = "privateKey" in keyPair ? keyPair.privateKey : keyPair;
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return { crv: "Ed25519", d: jwk.d, x: jwk.x, kty: "OKP" };
}

const TEST_TOKEN_SIGN_JWK = await generateEd25519PrivateJWK();
const TEST_CONFIG_SIGN_JWK = await generateEd25519PrivateJWK();
const TEST_ADMIN_SIGN_JWK = await generateEd25519PrivateJWK();
const TEST_AGENT_PUBLIC_KEY = TEST_ADMIN_SIGN_JWK.x;
const TEST_AGENT_ENCRYPTION_PUBLIC_KEY = "BESaVZlSBvPTn8DH7a2HuC4T9mNsSzANH7bM6okjdYfkOX9YZR461tJ91e0iKbH6wy6SwVGZ0AbExqRbsjTmFV4";

const signingEnv = {
};
const env = signingEnv as Env;
const turnstileEnv = signingEnv as Env;
const adminPassword = "local-admin-pass";
const defaultProfileConfig = {
  features: ["generate204", "download", "ping", "mtr", "traceroute", "nexttrace", "iperf3"],
  limits: {
    download_concurrency: 2,
    iperf_active_sessions: 10,
    job_concurrency_per_ip: 1,
    job_timeout_sec: 45,
    job_max_output_bytes: 65536,
    allowed_download_sizes: ["10M", "100M", "1G"],
    iperf_port_min: 30000,
    iperf_port_max: 39999,
    iperf_ttl_seconds: 180,
    iperf_max_duration: 40,
    iperf_max_parallel: 10,
    iperf_max_runs: 4,
    iperf_run_budget: 200,
    token_ipv4_prefix: 24,
    token_ipv6_prefix: 48,
    allowed_control_ttl: 300,
  },
};

async function json<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

async function setupAdmin(db: D1Database, username = "admin", password = adminPassword): Promise<{ cookie: string; headers: { cookie: string } }> {
  const response = await worker.fetch(
    new Request("http://worker.test/api/admin/setup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password }),
    }),
    { ...env, DB: db },
  );
  expect(response.status).toBe(200);
  const cookie = response.headers.get("set-cookie")?.split(";")[0] ?? "";
  expect(cookie).toMatch(/^hlg_admin=/);
  return { cookie, headers: { cookie } };
}

async function adminLogin(db: D1Database, username = "admin", password = adminPassword, totp_code?: string): Promise<{ cookie: string; headers: { cookie: string } }> {
  const response = await worker.fetch(
    new Request("http://worker.test/api/admin/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password, totp_code }),
    }),
    { ...env, DB: db },
  );
  expect(response.status).toBe(200);
  const cookie = response.headers.get("set-cookie")?.split(";")[0] ?? "";
  expect(cookie).toMatch(/^hlg_admin=/);
  return { cookie, headers: { cookie } };
}

async function verifyCompactWithJWK(token: string, jwk: JsonWebKey): Promise<boolean> {
  const [payloadPart, signaturePart] = token.split(".");
  const payload = base64URLToBytes(payloadPart);
  const signature = base64URLToBytes(signaturePart);
  const verifyKey = await crypto.subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, { name: "Ed25519" } as AlgorithmIdentifier, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" } as AlgorithmIdentifier, verifyKey, signature as unknown as BufferSource, payload as unknown as BufferSource);
}

async function verifySignedConfigBundle(config: Record<string, unknown>, jwk: JsonWebKey): Promise<boolean> {
  const signature = base64URLToBytes(String(config.signature));
  const payload = new TextEncoder().encode(
    JSON.stringify({
      version: config.version,
      node_id: config.node_id,
      domain: config.domain,
      public_ipv4: config.public_ipv4,
      public_ipv6: config.public_ipv6,
      dynamic_ip: config.dynamic_ip || undefined,
      issued_at: config.issued_at,
      expires_at: config.expires_at,
      features: goCanonicalFeatureMap(config.features),
      limits: goCanonicalLimits(config.limits),
      config_kid: config.config_kid,
      keyset: config.keyset,
      signature: "",
    }),
  );
  const verifyKey = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    { name: "Ed25519" } as AlgorithmIdentifier,
    false,
    ["verify"],
  );
  return crypto.subtle.verify({ name: "Ed25519" } as AlgorithmIdentifier, verifyKey, signature as unknown as BufferSource, payload as unknown as BufferSource);
}

function goCanonicalFeatureMap(value: unknown): Record<string, boolean> {
  const source = isRecord(value) ? value : {};
  const out: Record<string, boolean> = {};
  for (const key of Object.keys(source).sort()) out[key] = source[key] === true;
  return out;
}

function goCanonicalLimits(value: unknown): Record<string, unknown> {
  const source = isRecord(value) ? value : {};
  const number = (key: string) => (typeof source[key] === "number" ? source[key] : 0);
  const out: Record<string, unknown> = {
    download_concurrency: number("download_concurrency"),
    download_max_requests_per_token: number("download_max_requests_per_token"),
    download_max_bytes_multiplier: number("download_max_bytes_multiplier"),
    iperf_active_sessions: number("iperf_active_sessions"),
    job_concurrency_per_ip: number("job_concurrency_per_ip"),
    job_timeout_sec: number("job_timeout_sec"),
    job_max_output_bytes: number("job_max_output_bytes"),
    allowed_download_sizes: Array.isArray(source.allowed_download_sizes) ? source.allowed_download_sizes : null,
    iperf_port_min: number("iperf_port_min"),
    iperf_port_max: number("iperf_port_max"),
    iperf_ttl_seconds: number("iperf_ttl_seconds"),
    iperf_max_duration: number("iperf_max_duration"),
    iperf_max_parallel: number("iperf_max_parallel"),
    iperf_max_runs: number("iperf_max_runs"),
    iperf_run_budget: number("iperf_run_budget"),
    token_ipv4_prefix: number("token_ipv4_prefix"),
    token_ipv6_prefix: number("token_ipv6_prefix"),
    allowed_control_ttl: number("allowed_control_ttl"),
  };
  if (typeof source.guard_private_ip === "boolean") out.guard_private_ip = source.guard_private_ip;
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function compactPayload(token: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64URLToBytes(token.split(".")[0]))) as Record<string, unknown>;
}

function jwsPayload(body: BodyInit | null | undefined): Record<string, unknown> {
  const source = typeof body === "string" ? body : "";
  const envelope = JSON.parse(source) as { payload: string };
  return jwsPayloadPart(envelope.payload);
}

function jwsPayloadPart(value: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64URLToBytes(value))) as Record<string, unknown>;
}

function jwsProtected(value: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64URLToBytes(value))) as Record<string, unknown>;
}

async function expectedKidForJWK(jwk: JsonWebKey): Promise<string> {
  if (typeof jwk.x !== "string") throw new Error("missing_public_key");
  const raw = base64URLToBytes(jwk.x);
  const buffer = new ArrayBuffer(raw.byteLength);
  new Uint8Array(buffer).set(raw);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
  return bytesToBase64URL(digest.slice(0, 8));
}

async function insertNodeProfile(db: D1Database, id: string, config: Record<string, unknown> = defaultProfileConfig): Promise<void> {
  await db
    .prepare("INSERT INTO node_profiles (id, name, config_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, id, JSON.stringify(config), 1780000000, 1780000000)
    .run();
}

async function insertEnrollToken(db: D1Database, id: string, token: string, nodeID: string, profileID = "default", autoApprove = 1, maxUses = 1): Promise<void> {
  await db
    .prepare(
      `INSERT INTO enroll_tokens (id, token_hash, node_id, profile_id, auto_approve, max_uses, used_count, expires_at, created_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(id, await sha256Hex(token), nodeID, profileID, autoApprove, maxUses, 0, null, 1780000000, null)
    .run();
}

async function insertDNSSettings(
  db: D1Database,
  settings = { base: "lgtest-node.example", v4_base: "lgtest-node-v4.example", v6_base: "lgtest-node-v6.example", single_base: false },
): Promise<void> {
  await db.prepare("INSERT INTO project_settings (key, value_json, updated_at) VALUES (?, ?, ?)")
    .bind("dns", JSON.stringify(settings), 1780000000)
    .run();
}

async function insertProjectSetting(db: D1Database, key: string, value: unknown): Promise<void> {
  await db.prepare("INSERT INTO project_settings (key, value_json, updated_at) VALUES (?, ?, ?)")
    .bind(key, JSON.stringify(value), 1780000000)
    .run();
}

async function insertRuntimeSecret(db: D1Database, key: string, value: string): Promise<void> {
  await db.prepare("INSERT INTO runtime_secrets (key, value, updated_at) VALUES (?, ?, ?)")
    .bind(key, value, 1780000000)
    .run();
}

async function seedControlPlaneSecrets(db: D1Database, options: { turnstile?: boolean; dns?: boolean } = {}): Promise<void> {
  await insertRuntimeSecret(db, "LG_TOKEN_SIGN_JWK", JSON.stringify(TEST_TOKEN_SIGN_JWK));
  await insertRuntimeSecret(db, "LG_CONFIG_SIGN_JWK", JSON.stringify(TEST_CONFIG_SIGN_JWK));
  await insertRuntimeSecret(db, "LG_ADMIN_SIGN_JWK", JSON.stringify(TEST_ADMIN_SIGN_JWK));
  if (options.turnstile === true) await insertRuntimeSecret(db, "TURNSTILE_SECRET_KEY", "turnstile-secret");
  if (options.dns === true) await insertRuntimeSecret(db, "CLOUDFLARE_DNSUPDATE_API_KEY", "dns-token");
}

async function seedDnsControlSettings(db: D1Database, options: { zoneID?: string; acme?: boolean; provider?: string; email?: string; directoryURL?: string; renewBeforeDays?: string; eabKeyID?: string; eabAlg?: string; eabHmacKey?: string } = {}): Promise<void> {
  await insertProjectSetting(db, "CLOUDFLARE_ZONE_ID", options.zoneID || "zone-id");
  if (options.acme !== undefined) await insertProjectSetting(db, "ACME_ENABLED", options.acme);
  if (options.provider !== undefined) await insertProjectSetting(db, "ACME_PROVIDER", options.provider);
  if (options.email !== undefined) await insertProjectSetting(db, "ACME_ACCOUNT_EMAIL", options.email);
  if (options.directoryURL !== undefined) await insertProjectSetting(db, "ACME_DIRECTORY_URL", options.directoryURL);
  if (options.renewBeforeDays !== undefined) await insertProjectSetting(db, "ACME_RENEW_BEFORE_DAYS", options.renewBeforeDays);
  if (options.eabKeyID !== undefined) await insertProjectSetting(db, "ACME_EAB_KEY_ID", options.eabKeyID);
  if (options.eabAlg !== undefined) await insertProjectSetting(db, "ACME_EAB_ALG", options.eabAlg);
  if (options.eabHmacKey !== undefined) await insertRuntimeSecret(db, "ACME_EAB_HMAC_KEY", options.eabHmacKey);
}

async function getProjectSetting(db: D1Database, key: string): Promise<unknown> {
  const row = await db.prepare("SELECT value_json FROM project_settings WHERE key = ?").bind(key).first<{ value_json: string }>();
  return row ? JSON.parse(row.value_json) : undefined;
}

async function getRuntimeSecretValue(db: D1Database, key: string): Promise<string | undefined> {
  const row = await db.prepare("SELECT value FROM runtime_secrets WHERE key = ?").bind(key).first<{ value: string }>();
  return row?.value;
}

describe("minimal control plane", () => {
  it("requires D1 for public nodes instead of using a hardcoded fallback", async () => {
    const response = await worker.fetch(new Request("http://worker.test/api/nodes"), env);
    expect(response.status).toBe(503);
    expect(await json<{ error: string }>(response)).toEqual({ error: "d1_required" });
  });

  it("returns generic internal errors without leaking thrown messages", async () => {
    const db = {
      prepare() {
        throw new Error("sqlite schema leak: admin_users.password_hash");
      },
    } as unknown as D1Database;

    const response = await worker.fetch(new Request("http://worker.test/api/nodes"), { ...env, DB: db });

    expect(response.status).toBe(500);
    expect(await json<{ error: string }>(response)).toEqual({ error: "internal_error" });
  });

  it("issues compact signed download and job tokens", async () => {
    const db = memoryD1();
    const expectedTokenKid = await expectedKidForJWK(TEST_TOKEN_SIGN_JWK);
    const download = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", size: "10M", turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(download.status).toBe(200);
    const downloadBody = await json<{ token: string; expires_at: number; sizes: string[]; extensions_remaining: number }>(download);
    expect(downloadBody.token.split(".")).toHaveLength(2);
    expect(compactPayload(downloadBody.token)).toMatchObject({ typ: "download", kid: expectedTokenKid, size: "*" });
    const downloadSecondsLeft = downloadBody.expires_at - Math.floor(Date.now() / 1000);
    expect(downloadSecondsLeft).toBeGreaterThanOrEqual(895);
    expect(downloadSecondsLeft).toBeLessThanOrEqual(900);
    expect(downloadBody.sizes).toEqual(["10M", "100M", "1G"]);
    expect(downloadBody.extensions_remaining).toBe(2);

    const job = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 4, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(job.status).toBe(200);
    const jobBody = await json<{ token: string }>(job);
    expect(jobBody.token.split(".")).toHaveLength(2);
    expect(compactPayload(jobBody.token)).toMatchObject({ typ: "job", kid: expectedTokenKid });
  });

  it("blocks signed token creation when signing keys are not configured", async () => {
    const db = memoryD1({ seedRuntimeSecrets: false });
    const response = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 5, turnstile_token: "dev-turnstile" }),
      }),
      { DB: db },
    );
    expect(response.status).toBe(503);
    const body = await json<Record<string, unknown>>(response.clone());
    expect(body).toMatchObject({ error: "service_unconfigured" });
    // The missing setting name must not leak to the client.
    expect(body.missing).toBeUndefined();
  });

  it("enrolls a pre-created node from a node-scoped enroll token and applies profile limits", async () => {
    const db = memoryD1();
    await db
      .prepare(
        `INSERT INTO nodes (
          id, domain, domain_v4, domain_v6, display_name, display_label, public_ipv4, public_ipv6, profile_id, enabled, hidden,
          maintenance, config_version, agent_public_key, agent_encryption_public_key, version, capabilities, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)`,
      )
      .bind(
        "edge01",
        "edge01.lg.example.net",
        "edge01.lg-v4.example.net",
        "edge01.lg-v6.example.net",
        "Edge 01",
        "US",
        "192.0.2.9",
        "2001:db8::9",
        "fast",
        1,
        0,
        0,
        7,
        "0.3.0",
        JSON.stringify(["generate204", "download", "ping", "iperf3"]),
        1780000000,
        1780000000,
      )
      .run();
    await insertNodeProfile(db, "fast", {
      limits: {
        download_concurrency: 3,
        iperf_active_sessions: 4,
        job_timeout_sec: 25,
        allowed_download_sizes: ["10M"],
        iperf_max_parallel: 8,
        guard_private_ip: false,
      },
    });
    await insertEnrollToken(db, "enroll_edge01", "edge-enroll-token", "edge01", "fast");
    const guarded = {
      prepare(sql: string) {
        if (sql.includes("LEFT JOIN node_profiles") && sql.includes("capabilities, created_at,")) {
          throw new Error("unqualified_node_created_at");
        }
        return db.prepare(sql);
      },
    } as unknown as D1Database;

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enroll_token: "edge-enroll-token",
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          detected_ipv4: "198.51.100.20",
          detected_ipv6: "2001:db8::20",
          version: "0.4.0",
          capabilities: ["generate204", "download", "ping"],
        }),
      }),
      { ...env, DB: guarded },
    );

    expect(response.status).toBe(200);
    const expectedAdminKid = await expectedKidForJWK(TEST_ADMIN_SIGN_JWK);
    const expectedConfigKid = await expectedKidForJWK(TEST_CONFIG_SIGN_JWK);
    const expectedTokenKid = await expectedKidForJWK(TEST_TOKEN_SIGN_JWK);
    const body = await json<{
      node_id: string;
      config: { domain: string; limits: Record<string, unknown>; keyset: Array<{ kid: string; use: string }>; config_kid: string };
    }>(response);
    expect(body.node_id).toBe("edge01");
    expect(body.config.domain).toBe("edge01.lg.example.net");
    expect(body.config.config_kid).toBe(expectedConfigKid);
    expect(body.config.keyset).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kid: expectedAdminKid, use: "admin_verify" }),
        expect.objectContaining({ kid: expectedTokenKid, use: "token_verify" }),
        expect.objectContaining({ kid: expectedConfigKid, use: "config_verify" }),
      ]),
    );
    expect(await verifySignedConfigBundle(body.config as Record<string, unknown>, TEST_CONFIG_SIGN_JWK)).toBe(true);
    expect(body.config.limits).toMatchObject({
      download_concurrency: 3,
      iperf_active_sessions: 4,
      job_timeout_sec: 25,
      allowed_download_sizes: ["10M"],
      iperf_max_parallel: 8,
      guard_private_ip: false,
    });
    const row = await db.prepare("SELECT id, agent_public_key, version, capabilities FROM nodes WHERE id = ?").bind("edge01").first<Record<string, unknown>>();
    expect(row).toMatchObject({ id: "edge01", agent_public_key: TEST_AGENT_PUBLIC_KEY, version: "0.4.0" });
    expect(JSON.parse(String(row?.capabilities))).toEqual(["generate204", "download", "ping"]);

    await insertEnrollToken(db, "enroll_edge01_retry", "edge-enroll-retry", "edge01", "fast", 1, 2);
    const retryEnroll = (agentPublicKey: string) => worker.fetch(
      new Request("http://worker.test/_lg/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enroll_token: "edge-enroll-retry",
          agent_public_key: agentPublicKey,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    expect((await retryEnroll(TEST_AGENT_PUBLIC_KEY!)).status).toBe(200);
    const changedIdentity = await retryEnroll(TEST_CONFIG_SIGN_JWK.x!);
    expect(changedIdentity.status).toBe(409);
    expect(await json<{ error: string }>(changedIdentity)).toEqual({ error: "node_identity_change_requires_rekey" });
  });

  it("signs config bundles without empty optional ip fields", async () => {
    const db = memoryD1();
    await db
      .prepare(
        `INSERT INTO nodes (
          id, domain, display_name, display_label, profile_id, enabled, hidden,
          maintenance, config_version, agent_public_key, agent_encryption_public_key, version, capabilities, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        "edge-empty",
        "edge-empty.example.net",
        "Edge Empty",
        "TEST",
        "default",
        1,
        0,
        0,
        1,
        TEST_AGENT_PUBLIC_KEY,
        TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
        "0.4.0",
        JSON.stringify(["generate204", "download"]),
        1780000000,
        1780000000,
      )
      .run();
    await insertNodeProfile(db, "default");
    await insertEnrollToken(db, "enroll_empty", "empty-enroll-token", "edge-empty");

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enroll_token: "empty-enroll-token",
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ config: Record<string, unknown> }>(response);
    expect(body.config).not.toHaveProperty("public_ipv4");
    expect(body.config).not.toHaveProperty("public_ipv6");
    expect(body.config).not.toHaveProperty("dynamic_ip");
    expect(await verifySignedConfigBundle(body.config, TEST_CONFIG_SIGN_JWK)).toBe(true);
  });

  it("verifies the actual Worker bundle with the real Go verifier", async () => {
    const db = memoryD1();
    await db.prepare(`INSERT INTO nodes (id, domain, display_name, display_label, profile_id, enabled, hidden, maintenance, config_version, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind("cross-lang", "cross-lang.example", "Cross", "TEST", "default", 1, 0, 0, 7, 1780000000, 1780000000).run();
    await insertNodeProfile(db, "default", { ...defaultProfileConfig, limits: { ...defaultProfileConfig.limits, download_max_requests_per_token: 17, download_max_bytes_multiplier: 9, guard_private_ip: false } });
    await seedControlPlaneSecrets(db);
    const bundles = [];
    for (const guard of [undefined, true, false]) {
      const limits = { ...defaultProfileConfig.limits, download_max_requests_per_token: 17, download_max_bytes_multiplier: 9 } as Record<string, unknown>;
      if (guard !== undefined) limits.guard_private_ip = guard;
      await db.prepare("UPDATE node_profiles SET config_json = ? WHERE id = ?").bind(JSON.stringify({ ...defaultProfileConfig, limits }), "default").run();
      const bundle = await buildSignedConfig({ ...env, DB: db }, "cross-lang");
      expect(bundle.limits).toMatchObject({ download_max_requests_per_token: 17, download_max_bytes_multiplier: 9 });
      if (guard === undefined) expect(bundle.limits).not.toHaveProperty("guard_private_ip");
      else expect(bundle.limits).toHaveProperty("guard_private_ip", guard);
      bundles.push(bundle);
    }
    const dir = mkdtempSync(join(tmpdir(), "lg-cross-lang-"));
    const fixture = join(dir, "bundle.json");
    writeFileSync(fixture, JSON.stringify(bundles));
    try {
      execFileSync("go", ["test", "./internal/config", "-run", "TestVerifyWorkerGeneratedBundleFixture", "-count=1", "-timeout=120s"], {
        cwd: join(process.cwd(), "..", "agent"),
        env: { ...process.env, LG_WORKER_BUNDLE_FIXTURE: fixture },
        stdio: "pipe",
        timeout: 120_000,
      });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 120_000);

  it("does not return a runnable signed config for pending enrollments", async () => {
    const db = memoryD1();
    await insertEnrollToken(db, "enroll_pending", "pending-enroll-token", "testnode01", "default", 0);

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enroll_token: "pending-enroll-token",
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download", "ping"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    expect(await json<{ status: string; node_id: string; config?: unknown }>(response)).toEqual({
      status: "pending",
      node_id: "testnode01",
    });
  });

  it("bootstraps a node even when the default profile seed is missing", async () => {
    const db = memoryD1();
    const { issueNodeInitToken, issueNodeToken, validateNodeToken } = await import("../src/node-tokens");
    await db
      .prepare(
        `INSERT INTO nodes (
          id, domain, display_name, display_label, public_ipv4, profile_id, enabled, hidden,
          maintenance, config_version, agent_public_key, agent_encryption_public_key, version, capabilities, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)`,
      )
      .bind(
        "edge-bootstrap",
        "edge-bootstrap.example.net",
        "Edge Bootstrap",
        "TEST",
        "192.0.2.44",
        "default",
        1,
        0,
        0,
        1,
        "0.4.0",
        JSON.stringify(["generate204", "download"]),
        1780000000,
        1780000000,
      )
      .run();
    const previousToken = await issueNodeToken(db, "edge-bootstrap");
    const init = await issueNodeInitToken(db, "edge-bootstrap");

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${init.token}` },
        body: JSON.stringify({
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ status: string; node_id: string; node_token: string; config: { node_id: string; limits: Record<string, unknown> } }>(response);
    expect(body.status).toBe("active");
    expect(body.node_id).toBe("edge-bootstrap");
    expect(body.node_token).toMatch(/^lgnode_/);
    expect(body.config.node_id).toBe("edge-bootstrap");
    expect(await validateNodeToken(db, previousToken)).toBeNull();
    expect(body.config.limits).toBeDefined();
    // guard_private_ip is tri-state: an unset profile omits it so the agent
    // keeps its fail-safe default (guard on).
    expect(body.config.limits).not.toHaveProperty("guard_private_ip");
  });

  it("rejects enroll agent public keys that are not raw Ed25519 base64url keys", async () => {
    const db = memoryD1();
    await insertEnrollToken(db, "enroll_bad_agent_key", "bad-agent-key-token", "testnode01");

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enroll_token: "bad-agent-key-token",
          agent_public_key: "agent-pub",
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download", "ping"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(400);
    expect(await json<{ error: string }>(response)).toEqual({ error: "invalid_agent_public_key" });
    const row = await db.prepare("SELECT id, agent_public_key FROM nodes WHERE id = ?").bind("testnode01").first<Record<string, unknown>>();
    expect(row?.agent_public_key).toBe(TEST_AGENT_PUBLIC_KEY);
  });

  it("consumes enroll tokens with one conditional D1 update instead of a separate token SELECT", async () => {
    const inner = memoryD1();
    await insertEnrollToken(inner, "enroll_atomic", "atomic-enroll-token", "testnode01");
    const updateStatements: string[] = [];
    const guarded = {
      prepare(sql: string) {
        if (/SELECT[\s\S]+FROM enroll_tokens/i.test(sql)) throw new Error("separate_enroll_token_select");
        if (/UPDATE\s+enroll_tokens/i.test(sql)) updateStatements.push(sql);
        return inner.prepare(sql);
      },
    } as unknown as D1Database;

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enroll_token: "atomic-enroll-token",
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download", "ping"],
        }),
      }),
      { ...env, DB: guarded },
    );

    expect(response.status).toBe(200);
    expect(updateStatements).toHaveLength(1);
    expect(updateStatements[0]).toMatch(/used_count\s*<\s*max_uses/i);
    expect(updateStatements[0]).toMatch(/revoked_at\s+IS\s+NULL/i);
    expect(updateStatements[0]).toMatch(/expires_at\s+IS\s+NULL/i);
    expect(updateStatements[0]).toMatch(/node_id\s+IS\s+NOT\s+NULL/i);
    expect(updateStatements[0]).toMatch(/RETURNING/i);
  });

  it("requires Turnstile before creating download links, job tokens, and iperf sessions", async () => {
    const db = memoryD1();
    await insertRuntimeSecret(db, "TURNSTILE_SECRET_KEY", "turnstile-secret");
    const download = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", size: "10M" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(download.status).toBe(403);
    expect(await json<{ error: string }>(download)).toMatchObject({ error: "turnstile_required" });

    const job = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 4 }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(job.status).toBe(403);
    expect(await json<{ error: string }>(job)).toMatchObject({ error: "turnstile_required" });

    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (request: Request) => {
        calls.push(request);
        return new Response("unexpected", { status: 500 });
      }),
    );
    const iperf = await worker.fetch(
      new Request("http://worker.test/api/iperf/session", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", mode: "tcp", reverse: false, duration: 10, parallel: 1 }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(iperf.status).toBe(403);
    expect(calls).toHaveLength(0);
    vi.unstubAllGlobals();
  });

  it("does not consume iPerf session creation quota when challenge verification fails", async () => {
    const db = memoryD1();
    await insertRuntimeSecret(db, "TURNSTILE_SECRET_KEY", "turnstile-secret");
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (request.url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
          return Response.json({ success: true, hostname: "worker.test", challenge_ts: new Date().toISOString() });
        }
        calls.push(request);
        return new Response(
          JSON.stringify({
            ok: true,
            session_id: "ipf_after_challenge",
            host: "testnode01.lgtest-node.example",
            port: 31742,
            expires_at: 1780300000,
            command: "iperf3 -c testnode01.lgtest-node.example -p 31742 -P 1 -t 10",
          }),
          { headers: { "content-type": "application/json" } },
        );
      }),
    );

    for (let index = 0; index < 3; index++) {
      const rejected = await worker.fetch(
        new Request("http://worker.test/api/iperf/session", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
          body: JSON.stringify({ node: "testnode01", mode: "tcp", reverse: false, duration: 10, parallel: 1 }),
        }),
        { ...turnstileEnv, DB: db },
      );
      expect(rejected.status).toBe(403);
    }

    const accepted = await worker.fetch(
      new Request("http://worker.test/api/iperf/session", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", mode: "tcp", reverse: false, duration: 10, parallel: 1, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(accepted.status).toBe(200);
    expect(calls).toHaveLength(1);
    vi.unstubAllGlobals();
  });

  it("rate limits expensive creation endpoints by client and node", async () => {
    const db = memoryD1();
    for (let index = 0; index < 6; index++) {
      const response = await worker.fetch(
        new Request("http://worker.test/api/token/download", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
          body: JSON.stringify({ node: "testnode01", size: "10M", turnstile_token: "dev-turnstile" }),
        }),
        { ...turnstileEnv, DB: db },
      );
      expect(response.status).toBe(200);
    }

    const limited = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", size: "10M", turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(limited.status).toBe(429);
    expect(await json<{ error: string }>(limited)).toMatchObject({ error: "rate_limited" });
  });

  it("rate limits job token issuance after the per-window limit", async () => {
    const db = memoryD1();
    const issue = async () =>
      worker.fetch(
        new Request("http://worker.test/api/token/job", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.66" },
          body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 4, turnstile_token: "dev-turnstile" }),
        }),
        { ...turnstileEnv, DB: db },
      );

    for (let index = 0; index < 6; index++) {
      const response = await issue();
      expect(response.status).toBe(200);
    }

    const limited = await issue();
    expect(limited.status).toBe(429);
    expect(await json<{ error: string; reset_at: number }>(limited)).toMatchObject({ error: "rate_limited" });
  });

  it("does not consume job token rate limit budget when the challenge fails", async () => {
    const db = memoryD1();
    await insertRuntimeSecret(db, "TURNSTILE_SECRET_KEY", "turnstile-secret");
    const issue = (withToken: boolean) =>
      worker.fetch(
        new Request("http://worker.test/api/token/job", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.77" },
          body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 4, ...(withToken ? { turnstile_token: "dev-turnstile" } : {}) }),
        }),
        { ...turnstileEnv, DB: db },
      );

    for (let index = 0; index < 9; index++) {
      const rejected = await issue(false);
      expect(rejected.status).toBe(403);
      expect(await json<{ error: string }>(rejected)).toMatchObject({ error: "turnstile_required" });
    }

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (request.url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") {
          return Response.json({ success: true, hostname: "worker.test", challenge_ts: new Date().toISOString() });
        }
        return new Response("unexpected", { status: 500 });
      }),
    );
    const accepted = await issue(true);
    expect(accepted.status).toBe(200);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({
        success: true,
        hostname: "attacker.example",
        challenge_ts: new Date().toISOString(),
      })),
    );
    const wrongHostname = await issue(true);
    expect(wrongHostname.status).toBe(403);
    expect(await json<{ error: string }>(wrongHostname)).toMatchObject({ error: "turnstile_invalid" });
    vi.unstubAllGlobals();
  });

  it("fails the Turnstile challenge closed when the runtime secret cannot be read", async () => {
    const inner = memoryD1();
    const broken = {
      prepare(sql: string) {
        if (sql.includes("FROM runtime_secrets")) throw new Error("d1_infra_failure");
        return inner.prepare(sql);
      },
    } as unknown as D1Database;

    const response = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 4, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: broken },
    );

    expect(response.status).toBe(502);
    expect(await json<{ error: string; provider: string }>(response)).toMatchObject({ error: "turnstile_error", provider: "turnstile" });
  });

  it("returns 503 instead of silently passing when TURNSTILE_ENFORCED is set without a secret", async () => {
    const db = memoryD1();
    await insertProjectSetting(db, "TURNSTILE_ENFORCED", true);

    const response = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 4, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(503);
    expect(await json<{ error: string; provider: string }>(response)).toMatchObject({ error: "turnstile_unavailable", provider: "turnstile" });
  });

  it("records reusable download link audit rows without replacing previous links", async () => {
    const db = memoryD1();
    const bodies: Array<{ token: string; link_id: string }> = [];
    for (let index = 0; index < 3; index++) {
      const response = await worker.fetch(
        new Request("http://worker.test/api/token/download", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
          body: JSON.stringify({ node: "testnode01", turnstile_token: "dev-turnstile" }),
        }),
        { ...turnstileEnv, DB: db },
      );
      expect(response.status).toBe(200);
      const body = await json<{ token: string; link_id: string }>(response);
      bodies.push(body);
      expect(compactPayload(body.token).link_id).toBe(body.link_id);
    }

    const links = await db.prepare("SELECT size, status FROM download_links ORDER BY created_at").all<{ size: string; status: string }>();
    expect(links.results).toEqual([
      { size: "any", status: "active" },
      { size: "any", status: "active" },
      { size: "any", status: "active" },
    ]);

    const audit = await db.prepare("SELECT operation_type FROM operation_audit").all<{ operation_type: string }>();
    expect(audit.results.map((row) => row.operation_type)).toEqual(["download_link", "download_link", "download_link"]);
  });

  it("records download usage from node sync reports", async () => {
    const db = memoryD1();
    const issued = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    const issuedBody = await json<{ link_id: string }>(issued);
    const { issueNodeToken } = await import("../src/node-tokens");
    const nodeToken = await issueNodeToken(db, "testnode01");

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/control/sync?node=testnode01", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${nodeToken}` },
        body: JSON.stringify({ type: "download_used", link_id: issuedBody.link_id, size: "1G" }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    expect(await json<{ ok: boolean; usage_count: number }>(response)).toMatchObject({ ok: true, usage_count: 1 });
    const link = await db
      .prepare("SELECT usage_count, last_used_at FROM download_links WHERE id = ?")
      .bind(issuedBody.link_id)
      .first<{ usage_count: number; last_used_at: number }>();
    expect(link?.usage_count).toBe(1);
    expect(link?.last_used_at).toBeGreaterThan(0);
  });

  it("dedupes identical managed certificate bundles instead of storing copies", async () => {
    const db = memoryD1();
    const { storeManagedCertificateBundle } = await import("../src/certificates");
    const envWithDB = { ...env, DB: db } as Env;
    const input = {
      certPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
      keyPEM: "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
      caPEM: "",
      certExpiresAt: Math.floor(Date.now() / 1000) + 86400,
      domains: ["*.lgtest-node.example"],
    };

    const firstID = await storeManagedCertificateBundle(envWithDB, input);
    const secondID = await storeManagedCertificateBundle(envWithDB, { ...input });
    expect(secondID).toBe(firstID);
    const bundles = await db.prepare("SELECT id, active FROM certificate_bundles").all<{ id: string; active: number }>();
    expect(bundles.results.filter((row) => row.id === firstID)).toHaveLength(1);
    expect(bundles.results.filter((row) => Number(row.active) === 1)).toHaveLength(1);

    // A different certificate must replace, not duplicate: exactly one active.
    const changedID = await storeManagedCertificateBundle(envWithDB, {
      ...input,
      certPEM: "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
    });
    expect(changedID).not.toBe(firstID);
    const after = await db.prepare("SELECT id, active FROM certificate_bundles ORDER BY created_at ASC").all<{ id: string; active: number }>();
    expect(after.results.filter((row) => Number(row.active) === 1)).toHaveLength(1);
    expect(after.results.find((row) => row.id === firstID)?.active).toBe(0);
    expect(after.results.find((row) => row.id === changedID)?.active).toBe(1);
  });

  it("stores an admin-uploaded certificate bundle and lets the node pull it", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
    const keyPEM = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----";
    const certExpiresAt = Math.floor(Date.now() / 1000) + 86400;

    const unauthenticated = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/cert", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ node_id: "testnode01", cert_pem: certPEM, key_pem: keyPEM, cert_expires_at: certExpiresAt }),
      }),
      { ...env, DB: db },
    );
    expect(unauthenticated.status).toBe(401);

    const uploaded = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/cert", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ node_id: "testnode01", cert_pem: certPEM, key_pem: keyPEM, cert_expires_at: certExpiresAt }),
      }),
      { ...env, DB: db },
    );
    expect(uploaded.status).toBe(200);
    expect(await json<{ bundle: { node_id: string; cert_expires_at: number } }>(uploaded)).toMatchObject({
      bundle: { node_id: "testnode01", cert_expires_at: certExpiresAt },
    });

    const rejected = await worker.fetch(new Request("http://worker.test/_lg/control/cert-bundle?node=testnode01"), { ...env, DB: db });
    expect(rejected.status).toBe(401);

    const { issueNodeToken } = await import("../src/node-tokens");
    const nodeToken = await issueNodeToken(db, "testnode01");
    const pulled = await worker.fetch(
      new Request("http://worker.test/_lg/control/cert-bundle?node=testnode01", {
        headers: { authorization: `Bearer ${nodeToken}` },
      }),
      { ...env, DB: db },
    );
    expect(pulled.status).toBe(200);
    const envelope = await json<Record<string, unknown>>(pulled);
    expect(envelope).toMatchObject({ alg: "ECDH-P256+A256GCM", epk: expect.any(String), iv: expect.any(String), ciphertext: expect.any(String) });
    expect(JSON.stringify(envelope)).not.toContain("PRIVATE KEY");
    expect(JSON.stringify(envelope)).not.toContain("cert_pem");
  });

  it("imports a managed certificate bundle and publishes it to eligible nodes", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await insertProjectSetting(db, "ACME_ENABLED", true);
    const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
    const keyPEM = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----";
    const caPEM = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";
    const certExpiresAt = Math.floor(Date.now() / 1000) + 86400;
    const payload = {
      action: "import",
      cert_pem: certPEM,
      key_pem: keyPEM,
      ca_pem: caPEM,
      cert_expires_at: certExpiresAt,
      domains: ["*.lgtest-node.example"],
    };

    const unauthenticated = await worker.fetch(
      new Request("http://worker.test/api/admin/certificates", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      }),
      { ...env, DB: db },
    );
    expect(unauthenticated.status).toBe(401);

    const imported = await worker.fetch(
      new Request("http://worker.test/api/admin/certificates", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify(payload),
      }),
      { ...env, DB: db },
    );
    expect(imported.status).toBe(200);
    expect(await json<{ status: string; nodes: number; skipped: number; domains: string[]; acme_enabled: boolean }>(imported)).toMatchObject({
      status: "imported",
      nodes: 1,
      skipped: 0,
      domains: ["*.lgtest-node.example"],
      acme_enabled: false,
    });
    const acmeSetting = await db.prepare("SELECT value_json FROM project_settings WHERE key = ?").bind("ACME_ENABLED").first<{ value_json: string }>();
    expect(acmeSetting ? JSON.parse(acmeSetting.value_json) : null).toBe(false);

    const { issueNodeToken } = await import("../src/node-tokens");
    const nodeToken = await issueNodeToken(db, "testnode01");
    const pulled = await worker.fetch(
      new Request("http://worker.test/_lg/control/cert-bundle?node=testnode01", {
        headers: { authorization: `Bearer ${nodeToken}` },
      }),
      { ...env, DB: db },
    );
    expect(pulled.status).toBe(200);
    const envelope = await json<Record<string, unknown>>(pulled);
    expect(envelope).toMatchObject({ alg: "ECDH-P256+A256GCM", ciphertext: expect.any(String) });
    expect(JSON.stringify(envelope)).not.toContain("PRIVATE KEY");

    // The row must stay pending until the agent acknowledges the apply.
    const nodeBundleID = pulled.headers.get("x-lg-node-bundle-id") || "";
    expect(nodeBundleID).toMatch(/^ncb_/);
    const beforeAck = await db.prepare("SELECT status FROM node_certificate_bundles WHERE id = ?").bind(nodeBundleID).first<{ status: string }>();
    expect(beforeAck?.status).toBe("pending");

    const acked = await worker.fetch(
      new Request("http://worker.test/_lg/control/cert/ack", {
        method: "POST",
        headers: { authorization: `Bearer ${nodeToken}`, "content-type": "application/json" },
        body: JSON.stringify({ node_bundle_id: nodeBundleID, status: "applied" }),
      }),
      { ...env, DB: db },
    );
    expect(acked.status).toBe(200);
    const afterAck = await db.prepare("SELECT status FROM node_certificate_bundles WHERE id = ?").bind(nodeBundleID).first<{ status: string }>();
    expect(afterAck?.status).toBe("synced");

    // A failed report leaves the row retryable rather than marking it synced.
    const failed = await worker.fetch(
      new Request("http://worker.test/_lg/control/cert/ack", {
        method: "POST",
        headers: { authorization: `Bearer ${nodeToken}`, "content-type": "application/json" },
        body: JSON.stringify({ node_bundle_id: nodeBundleID, status: "failed", error: "decrypt_failed" }),
      }),
      { ...env, DB: db },
    );
    expect(failed.status).toBe(200);
    expect(await json<{ status: string }>(failed)).toMatchObject({ status: "pending" });
  });

  it("syncs wildcard managed certificate bundles to matching nodes", async () => {
    const db = memoryD1();
    await insertNodeProfile(db, "default");
    await insertDNSSettings(db, {
      base: "lg-nodes.example",
      v4_base: "lg-nodes-v4.example",
      v6_base: "lg-nodes-v6.example",
      single_base: false,
    });
    await insertProjectSetting(db, "ACME_ENABLED", true);
    await insertRuntimeSecret(db, "LG_CONFIG_SIGN_JWK", JSON.stringify(TEST_CONFIG_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_TOKEN_SIGN_JWK", JSON.stringify(TEST_TOKEN_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_ADMIN_SIGN_JWK", JSON.stringify(TEST_ADMIN_SIGN_JWK));
    await db
      .prepare(
        `INSERT INTO nodes (id, slug, domain, profile_id, enabled, hidden, config_version, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, 0, 1, ?, ?)`,
      )
      .bind("wild-node", "wild-node", "node1.lg-nodes.example", "default", 1780000000, 1780000000)
      .run();
    await db
      .prepare(
        `INSERT INTO certificate_bundles (
          id, domain, version, domains_json, fingerprint_sha256, cert_pem, key_pem, ca_pem,
          cert_expires_at, created_at, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      )
      .bind(
        "cb_wild",
        "sg-1-test.lg-nodes.example",
        1,
        JSON.stringify(["*.lg-nodes.example"]),
        "aa:bb",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        "",
        Math.floor(Date.now() / 1000) + 86400,
        1780000000,
      )
      .run();
    const { issueNodeInitToken } = await import("../src/node-tokens");
    const init = await issueNodeInitToken(db, "wild-node");

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { authorization: `Bearer ${init.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["ping"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ cert_sync?: { synced: number; skipped: number; reason?: string } }>(response);
    expect(body.cert_sync).toMatchObject({ synced: 1, skipped: 0 });
  });

  it("does not match a wildcard certificate across multiple labels", async () => {
    const db = memoryD1();
    await insertNodeProfile(db, "default");
    await insertDNSSettings(db, {
      base: "lg-nodes.example",
      v4_base: "lg-nodes-v4.example",
      v6_base: "lg-nodes-v6.example",
      single_base: false,
    });
    await insertProjectSetting(db, "ACME_ENABLED", true);
    await insertRuntimeSecret(db, "LG_CONFIG_SIGN_JWK", JSON.stringify(TEST_CONFIG_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_TOKEN_SIGN_JWK", JSON.stringify(TEST_TOKEN_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_ADMIN_SIGN_JWK", JSON.stringify(TEST_ADMIN_SIGN_JWK));
    // A deeper name that *.lg-nodes.example does NOT cover.
    await db
      .prepare(
        `INSERT INTO nodes (id, slug, domain, profile_id, enabled, hidden, config_version, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, 0, 1, ?, ?)`,
      )
      .bind("deep-node", "deep-node", "a.b.lg-nodes.example", "default", 1780000000, 1780000000)
      .run();
    await db
      .prepare(
        `INSERT INTO certificate_bundles (
          id, domain, version, domains_json, fingerprint_sha256, cert_pem, key_pem, ca_pem,
          cert_expires_at, created_at, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      )
      .bind(
        "cb_wild2",
        "sg-1-test.lg-nodes.example",
        1,
        JSON.stringify(["*.lg-nodes.example"]),
        "cc:dd",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        "",
        Math.floor(Date.now() / 1000) + 86400,
        1780000000,
      )
      .run();
    const { issueNodeInitToken } = await import("../src/node-tokens");
    const init = await issueNodeInitToken(db, "deep-node");

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { authorization: `Bearer ${init.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["ping"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ cert_sync?: { synced: number; skipped: number; reason?: string } }>(response);
    // Must not be published to a node whose name the wildcard does not cover.
    expect(body.cert_sync).toMatchObject({ synced: 0, skipped: 1, reason: "certificate_not_found" });
  });

  it("stages managed ACME issuance through DNS-01 and publishes only a valid certificate", async () => {
    const db = memoryD1();
    await seedControlPlaneSecrets(db, { dns: true });
    await insertDNSSettings(db, {
      base: "lgtest-node.example",
      v4_base: "lgtest-node-v4.example",
      v6_base: "lgtest-node-v6.example",
      single_base: false,
    });
    await insertProjectSetting(db, "CLOUDFLARE_ZONE_ID", "zone-id");
    await insertProjectSetting(db, "ACME_ENABLED", true);
    await insertProjectSetting(db, "ACME_PROVIDER", "zerossl");
    await insertProjectSetting(db, "ACME_ACCOUNT_EMAIL", "admin@example.net");
    await insertProjectSetting(db, "ACME_DIRECTORY_URL", "https://acme.test/directory");
    await insertProjectSetting(db, "ACME_RENEW_BEFORE_DAYS", "30");
    await insertProjectSetting(db, "ACME_EAB_KEY_ID", "kid-test");
    await insertProjectSetting(db, "ACME_EAB_ALG", "HS256");
    await insertRuntimeSecret(db, "ACME_EAB_HMAC_KEY", "c2VjcmV0LWtleQ");
    const calls: string[] = [];
    let accountPayload: Record<string, unknown> | null = null;
    let authPolls = 0;
    let finalizations = 0;
    let orderReads = 0;
    vi.stubGlobal("ACME_DNS_PROPAGATION_SECONDS", "0");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push(`${init?.method || "GET"} ${url}`);
        if (url === "https://acme.test/directory") {
          return Response.json({ newNonce: "https://acme.test/new-nonce", newAccount: "https://acme.test/new-account", newOrder: "https://acme.test/new-order" });
        }
        if (url === "https://acme.test/new-nonce") {
          return new Response(null, { headers: { "replay-nonce": `nonce-${calls.length}` } });
        }
        if (url === "https://acme.test/new-account") {
          accountPayload = jwsPayload(init?.body);
          return Response.json({}, { headers: { "replay-nonce": "nonce-account", location: "https://acme.test/account/1" } });
        }
        if (url === "https://acme.test/new-order") {
          return Response.json(
            { status: "pending", authorizations: ["https://acme.test/authz/1"], finalize: "https://acme.test/finalize/1" },
            { status: 201, headers: { "replay-nonce": "nonce-order", location: "https://acme.test/order/1" } },
          );
        }
        if (url === "https://acme.test/authz/1") {
          authPolls += 1;
          return Response.json(
            authPolls < 4
              ? { status: "pending", identifier: { type: "dns", value: "*.lgtest-node.example" }, challenges: [{ type: "dns-01", url: "https://acme.test/challenge/1", token: "tok" }] }
              : { status: "valid", identifier: { type: "dns", value: "*.lgtest-node.example" }, challenges: [] },
            { headers: { "replay-nonce": `nonce-auth-${authPolls}` } },
          );
        }
        if (url === "https://acme.test/challenge/1") {
          return Response.json({}, { headers: { "replay-nonce": "nonce-challenge" } });
        }
        if (url === "https://acme.test/order/1") {
          orderReads += 1;
          return Response.json(
            finalizations === 0
              ? { status: "ready", finalize: "https://acme.test/finalize/1" }
              : orderReads === 2
                ? { status: "processing" }
                : { status: "valid", certificate: "https://acme.test/cert/1" },
            { headers: { "replay-nonce": "nonce-order-status" } },
          );
        }
        if (url === "https://acme.test/finalize/1") {
          finalizations += 1;
          return Response.json({ status: "processing" }, { headers: { "replay-nonce": "nonce-finalize" } });
        }
        if (url === "https://acme.test/cert/1") {
          return new Response("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", { headers: { "replay-nonce": "nonce-cert" } });
        }
        if (url.includes("api.cloudflare.com/client/v4/zones/zone-id/dns_records")) {
          return Response.json({ success: true, result: [] });
        }
        throw new Error(`unexpected fetch: ${url}`);
      }),
    );

    const { renewManagedCertificates } = await import("../src/acme");
    const renewed = await renewManagedCertificates({ ...env, DB: db });
    expect(renewed).toMatchObject({ status: "begun" });
    expect(calls.some((call) => call.includes("/dns_records"))).toBe(true);
    expect(accountPayload).not.toBeNull();
    const payload = accountPayload as unknown as Record<string, unknown>;
    expect(payload.externalAccountBinding).toBeTruthy();
    const eab = payload.externalAccountBinding as { protected: string; payload: string; signature: string };
    expect(jwsProtected(eab.protected)).toMatchObject({ alg: "HS256", kid: "kid-test", url: "https://acme.test/new-account" });
    expect(jwsPayloadPart(eab.payload)).toMatchObject({ kty: "EC", crv: "P-256", x: expect.any(String), y: expect.any(String) });
    expect(eab.signature).toEqual(expect.any(String));

    const { finalizeManagedCertificateOrder, pendingCertificateOrder } = await import("../src/acme");
    expect(await finalizeManagedCertificateOrder({ ...env, DB: db })).toMatchObject({ status: "waiting", reason: "authorization_pending" });
    expect(await finalizeManagedCertificateOrder({ ...env, DB: db })).toMatchObject({ status: "waiting", reason: "authorization_pending" });
    expect(calls.filter((call) => call.includes("/challenge/1")).length).toBe(1);
    expect(await finalizeManagedCertificateOrder({ ...env, DB: db })).toMatchObject({ status: "waiting", reason: "order_finalizing" });
    expect(await finalizeManagedCertificateOrder({ ...env, DB: db })).toMatchObject({ status: "waiting", reason: "processing" });
    expect(await finalizeManagedCertificateOrder({ ...env, DB: db })).toMatchObject({ status: "issued", nodes: 1 });
    expect(finalizations).toBe(1);
    expect(await pendingCertificateOrder({ ...env, DB: db })).toMatchObject({ pending: false });

    const { issueNodeToken } = await import("../src/node-tokens");
    const nodeToken = await issueNodeToken(db, "testnode01");
    const pulled = await worker.fetch(
      new Request("http://worker.test/_lg/control/cert-bundle?node=testnode01", {
        headers: { authorization: `Bearer ${nodeToken}` },
      }),
      { ...env, DB: db },
    );
    expect(pulled.status).toBe(200);
    const envelope = await json<Record<string, unknown>>(pulled);
    expect(envelope).toMatchObject({ alg: "ECDH-P256+A256GCM", ciphertext: expect.any(String) });
    expect(JSON.stringify(envelope)).not.toContain("BEGIN CERTIFICATE");
    vi.unstubAllGlobals();
  });

  it("auto-advances certificate issuance only when a node lacks a valid certificate", async () => {
    const db = memoryD1();
    await seedControlPlaneSecrets(db, { dns: true });
    await insertDNSSettings(db, {
      base: "lgtest-node.example",
      v4_base: "lgtest-node-v4.example",
      v6_base: "lgtest-node-v6.example",
      single_base: false,
    });
    await insertProjectSetting(db, "CLOUDFLARE_ZONE_ID", "zone-id");
    await insertProjectSetting(db, "ACME_ENABLED", true);
    await insertProjectSetting(db, "ACME_DIRECTORY_URL", "https://acme.test/directory");

    const calls: string[] = [];
    vi.stubGlobal("ACME_DNS_PROPAGATION_SECONDS", "0");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push(`${init?.method || "GET"} ${url}`);
        if (url === "https://acme.test/directory") {
          return Response.json({ newNonce: "https://acme.test/new-nonce", newAccount: "https://acme.test/new-account", newOrder: "https://acme.test/new-order" });
        }
        if (url === "https://acme.test/new-nonce") {
          return new Response(null, { headers: { "replay-nonce": `nonce-${calls.length}` } });
        }
        if (url === "https://acme.test/new-account") {
          return Response.json({}, { headers: { "replay-nonce": "n", location: "https://acme.test/account/1" } });
        }
        if (url === "https://acme.test/new-order") {
          return Response.json(
            { status: "pending", authorizations: ["https://acme.test/authz/1"], finalize: "https://acme.test/finalize/1" },
            { status: 201, headers: { "replay-nonce": "n", location: "https://acme.test/order/1" } },
          );
        }
        if (url === "https://acme.test/authz/1") {
          return Response.json({ status: "pending", identifier: { type: "dns", value: "lgtest-node.example" }, challenges: [{ type: "dns-01", url: "https://acme.test/challenge/1", token: "tok" }] });
        }
        if (url.startsWith("https://api.cloudflare.com/")) {
          return Response.json({ success: true, result: [] });
        }
        throw new Error(`unexpected fetch: ${url}`);
      }),
    );

    const { autoAdvanceCertificateIssuance } = await import("../src/acme");
    // The seeded node's domain is not covered by any active bundle, so this
    // must begin an order on its own (no admin click, no cron pass).
    const begun = await autoAdvanceCertificateIssuance({ ...env, DB: db });
    expect(begun).toMatchObject({ status: "begun" });
    expect(calls.some((call) => call.includes("new-order"))).toBe(true);

    // A pending order now exists; a second call must NOT open another order —
    // it either waits for propagation or finalizes, never begins again.
    const again = await autoAdvanceCertificateIssuance({ ...env, DB: db });
    expect(again.status).not.toBe("begun");
    vi.unstubAllGlobals();
  });

  it("returns ACME problem details in certificate debug responses", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await seedControlPlaneSecrets(db, { dns: true });
    await insertDNSSettings(db, {
      base: "lgtest-node.example",
      v4_base: "lgtest-node-v4.example",
      v6_base: "lgtest-node-v6.example",
      single_base: false,
    });
    await insertProjectSetting(db, "CLOUDFLARE_ZONE_ID", "zone-id");
    await insertProjectSetting(db, "ACME_ENABLED", true);
    await insertProjectSetting(db, "ACME_PROVIDER", "letsencrypt");
    await insertProjectSetting(db, "ACME_DIRECTORY_URL", "https://acme.test/directory");
    await insertProjectSetting(db, "LG_WORKER_DEBUG_LOGS", true);
    vi.stubGlobal("ACME_DNS_PROPAGATION_SECONDS", "0");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === "https://acme.test/directory") {
          return Response.json({ newNonce: "https://acme.test/new-nonce", newAccount: "https://acme.test/new-account", newOrder: "https://acme.test/new-order" });
        }
        if (url === "https://acme.test/new-nonce") {
          return new Response(null, { headers: { "replay-nonce": "nonce-1" } });
        }
        if (url === "https://acme.test/new-account") {
          return Response.json(
            { type: "urn:ietf:params:acme:error:malformed", detail: "bad account payload", status: 400 },
            { status: 400, headers: { "content-type": "application/problem+json", "replay-nonce": "nonce-account" } },
          );
        }
        throw new Error(`unexpected fetch: ${url} ${init?.method || "GET"}`);
      }),
    );

    try {
      const response = await worker.fetch(
        new Request("http://worker.test/api/admin/certificates", {
          method: "POST",
          headers: { "content-type": "application/json", ...adminHeaders },
          body: JSON.stringify({ action: "reissue" }),
        }),
        { ...env, DB: db },
      );

      expect(response.status).toBe(502);
      const body = await json<{ status: string; reason: string; error: string; debug: Record<string, unknown> }>(response);
      expect(body).toMatchObject({ status: "failed", reason: "acme_request_failed:400", error: "acme_request_failed:400" });
      expect(body.debug.error).toMatchObject({
        name: "ACMERequestError",
        message: "acme_request_failed:400",
        status: 400,
        method: "POST",
        url: "https://acme.test/new-account",
        response_body: expect.stringContaining("bad account payload"),
      });
      const debugError = body.debug.error as Record<string, unknown>;
      expect(debugError.problem).toMatchObject({ detail: "bad account payload" });
      expect(JSON.stringify(body.debug)).not.toContain("dns-token");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("registers ZeroSSL email and stores generated EAB credentials", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await insertProjectSetting(db, "ACME_ENABLED", true);
    await insertProjectSetting(db, "ACME_PROVIDER", "zerossl");

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "https://api.zerossl.com/acme/eab-credentials-email") {
          return Response.json({
            success: true,
            eab_kid: "kid-zero",
            eab_hmac_key: "hmac-zero",
          });
        }
        throw new Error(`unexpected fetch: ${url}`);
      }),
    );

    try {
      const response = await worker.fetch(
        new Request("http://worker.test/api/admin/certificates", {
          method: "POST",
          headers: { "content-type": "application/json", ...adminHeaders },
          body: JSON.stringify({ action: "zerossl_eab_register", email: "Admin@Example.NET " }),
        }),
        { ...env, DB: db },
      );

      expect(response.status).toBe(200);
      const body = await json<{
        status: string;
        provider: string;
        email: string;
        eab_key_id: string;
        eab_alg: string;
        account_email_setting: { value: string; configured: boolean };
        eab_key_id_setting: { value: string; configured: boolean };
        eab_alg_setting: { value: string; configured: boolean };
        eab_hmac_secret: { configured: boolean; source: string };
      }>(response);
      expect(body).toMatchObject({
        status: "registered",
        provider: "zerossl",
        email: "admin@example.net",
        eab_key_id: "kid-zero",
        eab_alg: "HS256",
        account_email_setting: { value: "admin@example.net", configured: true },
        eab_key_id_setting: { value: "kid-zero", configured: true },
        eab_alg_setting: { value: "HS256", configured: true },
        eab_hmac_secret: { configured: true },
      });

      expect(await getProjectSetting(db, "ACME_ACCOUNT_EMAIL")).toBe("admin@example.net");
      expect(await getProjectSetting(db, "ACME_EAB_KEY_ID")).toBe("kid-zero");
      expect(await getProjectSetting(db, "ACME_EAB_ALG")).toBe("HS256");
      expect(await getRuntimeSecretValue(db, "ACME_EAB_HMAC_KEY")).toBe("hmac-zero");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("extends active download links at most twice", async () => {
    const db = memoryD1();
    const issued = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    const firstBody = await json<{ token: string; link_id: string; expires_at: number; extensions_remaining: number }>(issued);

    const extend = async (token: string) => {
      const response = await worker.fetch(
        new Request("http://worker.test/api/token/download/extend", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
          body: JSON.stringify({ node: "testnode01", link_id: firstBody.link_id, token }),
        }),
        { ...env, DB: db },
      );
      return response;
    };

    const second = await extend(firstBody.token);
    expect(second.status).toBe(200);
    const secondBody = await json<{ token: string; expires_at: number; extensions_remaining: number }>(second);
    expect(secondBody.expires_at - firstBody.expires_at).toBe(600);
    expect(secondBody.extensions_remaining).toBe(1);

    const third = await extend(secondBody.token);
    expect(third.status).toBe(200);
    const thirdBody = await json<{ token: string; extensions_remaining: number }>(third);
    expect(thirdBody.extensions_remaining).toBe(0);

    const limited = await extend(thirdBody.token);
    expect(limited.status).toBe(409);
    expect(await json<{ error: string }>(limited)).toMatchObject({ error: "download_link_extension_limit" });
  });

  it("requires D1-backed enroll tokens instead of localtest fallback enrollment", async () => {
    const response = await worker.fetch(
      new Request("http://worker.test/_lg/enroll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          enroll_token: "localtest",
          agent_public_key: "agent-pub",
          version: "0.3.0",
          capabilities: ["generate204", "download", "ping", "iperf3"],
        }),
      }),
      env,
    );
    expect(response.status).toBe(503);
    expect(await json<{ error: string }>(response)).toEqual({ error: "d1_required" });
  });

  it("opens iperf sessions through an admin-signed agent request", async () => {
    const db = memoryD1({ nodePort: 8443 });
    const expectedAdminKid = await expectedKidForJWK(TEST_ADMIN_SIGN_JWK);
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (request: Request) => {
        calls.push(request);
        return new Response(
          JSON.stringify({
            ok: true,
            session_id: "ipf_test",
            host: "testnode01.lgtest-node.example",
            port: 31742,
            expires_at: 1780300000,
            command: "iperf3 -u -b 0 -c testnode01.lgtest-node.example -p 31742 -P 1 -t 10 -R",
          }),
          { headers: { "content-type": "application/json" } },
        );
      }),
    );

    const response = await worker.fetch(
      new Request("http://worker.test/api/iperf/session", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", mode: "udp", reverse: true, duration: 10, parallel: 100, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(200);
    expect(calls[0].url).toBe("https://testnode01.lgtest-node.example:8443/_lg/control/iperf/open");
    expect(calls[0].headers.get("x-lg-key-id")).toBe(expectedAdminKid);
    expect(calls[0].headers.get("x-lg-signature")).toBeTruthy();
    expect(await calls[0].json()).toMatchObject({ mode: "udp", reverse: true, parallel: 10, ttl: 180, max_runs: 4, run_budget: 200 });
    const body = await json<{ command: string; port: number }>(response);
    expect(body.command).toContain("iperf3 -u -b 0 -c testnode01.lgtest-node.example");
    expect(body.command).toContain("-R");
    expect(body.command).toContain("-p 31742");
    expect(body.port).toBe(31742);
    vi.unstubAllGlobals();
  });

  it("expires stale open iperf sessions before opening a new one", async () => {
    const db = memoryD1();
    await db
      .prepare(
        `INSERT INTO iperf_sessions (id, node_id, client_ip_hash, port, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, 'open', ?, ?)`,
      )
      .bind("ipf_stale", "testnode01", "oldhash", 31742, 1780000000, 1780000001)
      .run();
    const { recordOperation } = await import("../src/audit");
    await recordOperation(db, {
      id: "ipf_stale",
      operationType: "iperf_session",
      node: "testnode01",
      clientIP: "203.0.113.10",
      status: "open",
      metadata: { port: 31742 },
      createdAt: 1780000000,
      expiresAt: 1780000001,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            ok: true,
            session_id: "ipf_new",
            host: "testnode01.lgtest-node.example",
            port: 31743,
            expires_at: Math.floor(Date.now() / 1000) + 180,
            command: "iperf3 -c testnode01.lgtest-node.example -p 31743 -P 1 -t 10",
          }),
          { headers: { "content-type": "application/json" } },
        ),
      ),
    );

    const response = await worker.fetch(
      new Request("http://worker.test/api/iperf/session", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", mode: "tcp", reverse: false, duration: 10, parallel: 1, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(200);
    const row = await db.prepare("SELECT status, closed_at FROM iperf_sessions WHERE id = ?").bind("ipf_stale").first<{ status: string; closed_at: number }>();
    expect(row).toMatchObject({ status: "expired", closed_at: 1780000001 });
    vi.unstubAllGlobals();
  });

  it("records closed iperf sessions back to D1", async () => {
    const db = memoryD1();
    await db
      .prepare(
        `INSERT INTO iperf_sessions (id, node_id, client_ip_hash, port, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, 'open', ?, ?)`,
      )
      .bind("ipf_closed", "testnode01", "clienthash", 31742, 1780000000, 1780000180)
      .run();
    const { recordOperation, closeIperfSessionAudit } = await import("../src/audit");
    await recordOperation(db, {
      id: "ipf_closed",
      operationType: "iperf_session",
      node: "testnode01",
      clientIP: "203.0.113.44",
      status: "open",
      metadata: { port: 31742 },
      createdAt: 1780000000,
      expiresAt: 1780000180,
    });

    await closeIperfSessionAudit(db, { id: "ipf_closed", status: "closed", reason: "ttl_expired", closedAt: 1780000181 });

    const sessions = await db.prepare("SELECT id, status, closed_at FROM iperf_sessions").all<{ id: string; status: string; closed_at: number }>();
    expect(sessions.results).toEqual([{ id: "ipf_closed", status: "closed", closed_at: 1780000181 }]);
    const audit = await db.prepare("SELECT id, status, metadata_json FROM operation_audit").all<{ id: string; status: string; metadata_json: string }>();
    expect(audit.results[0]).toMatchObject({ id: "ipf_closed", status: "closed" });
    expect(JSON.parse(audit.results[0].metadata_json)).toMatchObject({ close_reason: "ttl_expired" });
  });

  it("closes iperf sessions through an admin-signed agent request and records D1", async () => {
    const db = memoryD1();
    const sessionID = "ipf_close_api";
    const clientIP = "203.0.113.44";
    const clientHash = (await sha256Hex(clientIP)).slice(0, 16);
    const expiresAt = Math.floor(Date.now() / 1000) + 180;
    const expectedAdminKid = await expectedKidForJWK(TEST_ADMIN_SIGN_JWK);
    await db
      .prepare(
        `INSERT INTO iperf_sessions (id, node_id, client_ip_hash, port, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, 'open', ?, ?)`,
      )
      .bind(sessionID, "testnode01", clientHash, 31742, 1780000000, expiresAt)
      .run();
    const { recordOperation } = await import("../src/audit");
    await recordOperation(db, {
      id: sessionID,
      operationType: "iperf_session",
      node: "testnode01",
      clientIP,
      status: "open",
      metadata: { port: 31742 },
      createdAt: 1780000000,
      expiresAt,
    });
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (request: Request) => {
        calls.push(request);
        return new Response(JSON.stringify({ ok: true, closed_at: 1780000181 }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );

    const response = await worker.fetch(
      new Request("http://worker.test/api/iperf/session/close", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": clientIP },
        body: JSON.stringify({ node: "testnode01", session_id: sessionID }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(200);
    expect(calls[0].url).toBe("https://testnode01.lgtest-node.example/_lg/control/iperf/close");
    expect(calls[0].headers.get("x-lg-key-id")).toBe(expectedAdminKid);
    expect(await calls[0].json()).toEqual({ session_id: sessionID });
    expect(await json<{ status: string; session_id: string }>(response)).toMatchObject({
      session_id: sessionID,
      status: "closed_by_request",
    });
    const row = await db.prepare("SELECT status, closed_at FROM iperf_sessions WHERE id = ?").bind(sessionID).first<{ status: string; closed_at: number }>();
    expect(row).toMatchObject({ status: "closed_by_request" });
    vi.unstubAllGlobals();
  });

  it("requires first admin setup before admin APIs and rejects Basic credentials", async () => {
    const db = memoryD1();
    const session = await worker.fetch(new Request("http://worker.test/api/admin/session"), { ...env, DB: db });
    expect(session.status).toBe(200);
    expect(await json<{ authenticated: boolean; onboarding_required: boolean }>(session)).toMatchObject({
      authenticated: false,
      onboarding_required: true,
    });

    const blocked = await worker.fetch(new Request("http://worker.test/api/admin/nodes"), { ...env, DB: db });
    expect(blocked.status).toBe(403);
    expect(await json<{ error: string; onboarding_required: boolean }>(blocked)).toMatchObject({
      error: "onboarding_required",
      onboarding_required: true,
    });

    const { headers } = await setupAdmin(db);
    const accepted = await worker.fetch(new Request("http://worker.test/api/admin/nodes", { headers }), { ...env, DB: db });
    expect(accepted.status).toBe(200);

    const basic = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        headers: { authorization: `Basic ${btoa(`admin:${adminPassword}`)}` },
      }),
      { ...env, DB: db },
    );
    expect(basic.status).toBe(401);
    expect(basic.headers.get("www-authenticate")).toBeNull();
  });

  it("lists admin users without selecting password hashes or TOTP secrets", async () => {
    const inner = memoryD1();
    const { headers } = await setupAdmin(inner);
    const seenSQL: string[] = [];
    const guarded = {
      prepare(sql: string) {
        seenSQL.push(sql);
        if (/SELECT\s+id,\s+username,\s+password_hash,\s+totp_secret/i.test(sql)) {
          throw new Error("sensitive_admin_columns_selected");
        }
        return inner.prepare(sql);
      },
    } as unknown as D1Database;

    const response = await worker.fetch(new Request("http://worker.test/api/admin/users", { headers }), { ...env, DB: guarded });

    expect(response.status).toBe(200);
    expect(await json<{ users: Array<{ username: string; has_totp: boolean }> }>(response)).toMatchObject({
      users: [{ username: "admin", has_totp: false }],
    });
    expect(seenSQL.some((sql) => sql.includes("password_hash"))).toBe(false);
    expect(seenSQL.some((sql) => /SELECT\s+id,\s+username,\s+totp_secret/i.test(sql))).toBe(false);
  });

  it("cleans expired admin sessions when a new login succeeds", async () => {
    const db = memoryD1();
    await setupAdmin(db);
    const users = await db.prepare("SELECT id, username, password_hash, totp_secret, role, created_at, updated_at FROM admin_users ORDER BY created_at ASC, username ASC").all<{ id: string }>();
    await db
      .prepare("INSERT INTO admin_sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind("sess_expired", users.results[0].id, "expired_hash", 1, 1)
      .run();

    await adminLogin(db);

    const sessions = await db.prepare("SELECT id, expires_at FROM admin_sessions").all<{ id: string }>();
    expect(sessions.results.some((session) => session.id === "sess_expired")).toBe(false);
  });

  it("filters expired admin sessions in the session lookup query", async () => {
    const inner = memoryD1();
    const { headers } = await setupAdmin(inner);
    const seenSQL: string[] = [];
    const guarded = {
      prepare(sql: string) {
        if (/FROM admin_sessions/i.test(sql)) {
          seenSQL.push(sql);
          if (!/expires_at\s*>/i.test(sql)) throw new Error("admin_session_query_missing_expiry_filter");
        }
        return inner.prepare(sql);
      },
    } as unknown as D1Database;

    const response = await worker.fetch(new Request("http://worker.test/api/admin/nodes", { headers }), { ...env, DB: guarded });

    expect(response.status).toBe(200);
    expect(seenSQL.length).toBeGreaterThan(0);
  });

  it("rate limits repeated admin login failures by client and username", async () => {
    const db = memoryD1();
    await setupAdmin(db);

    for (let index = 0; index < 8; index++) {
      const rejected = await worker.fetch(
        new Request("http://worker.test/api/admin/login", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.55" },
          body: JSON.stringify({ username: "admin", password: "wrong-password" }),
        }),
        { ...env, DB: db },
      );
      expect(rejected.status).toBe(401);
    }

    const limited = await worker.fetch(
      new Request("http://worker.test/api/admin/login", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.55" },
        body: JSON.stringify({ username: "admin", password: "wrong-password" }),
      }),
      { ...env, DB: db },
    );
    expect(limited.status).toBe(429);
    expect(await json<{ error: string }>(limited)).toMatchObject({ error: "rate_limited" });
  });

  it("rate limits admin logins globally per client IP across usernames", async () => {
    const db = memoryD1();
    await setupAdmin(db);

    // A single IP rotating usernames must hit the global per-IP bucket even
    // though each username stays below its own per-username limit.
    let limited: Response | null = null;
    for (let index = 0; index < 35; index++) {
      const response = await worker.fetch(
        new Request("http://worker.test/api/admin/login", {
          method: "POST",
          headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.66" },
          body: JSON.stringify({ username: `rotating${index}`, password: "wrong-password" }),
        }),
        { ...env, DB: db },
      );
      if (response.status === 429) {
        limited = response;
        break;
      }
      expect(response.status).toBe(401);
    }
    expect(limited).not.toBeNull();
    expect(await json<{ error: string }>(limited!)).toMatchObject({ error: "rate_limited" });

    // The same IP stays blocked even with the correct credentials: the global
    // bucket is exhausted and returns 429 before authentication runs.
    const blocked = await worker.fetch(
      new Request("http://worker.test/api/admin/login", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.66" },
        body: JSON.stringify({ username: "admin", password: adminPassword }),
      }),
      { ...env, DB: db },
    );
    expect(blocked.status).toBe(429);
  });

  it("supports admin login, users, password reset, delete, and TOTP", async () => {
    const db = memoryD1();
    const { headers } = await setupAdmin(db);

    const created = await worker.fetch(
      new Request("http://worker.test/api/admin/users", {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "ops", password: "ops-local-pass" }),
      }),
      { ...env, DB: db },
    );
    expect(created.status).toBe(200);
    const createdBody = await json<{ user: { id: string; username: string; has_totp: boolean } }>(created);
    expect(createdBody.user).toMatchObject({ username: "ops", has_totp: false });

    const listed = await worker.fetch(new Request("http://worker.test/api/admin/users", { headers }), { ...env, DB: db });
    expect(listed.status).toBe(200);
    expect(await json<{ users: Array<{ username: string; has_totp: boolean; password_hash?: string; totp_secret?: string }> }>(listed)).toMatchObject({
      users: [
        { username: "admin", has_totp: false },
        { username: "ops", has_totp: false },
      ],
    });

    const reset = await worker.fetch(
      new Request("http://worker.test/api/admin/users/password", {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "ops", password: "ops-reset-pass" }),
      }),
      { ...env, DB: db },
    );
    expect(reset.status).toBe(200);
    await adminLogin(db, "ops", "ops-reset-pass");

    const totpSetup = await worker.fetch(
      new Request("http://worker.test/api/admin/users/totp/setup", {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "ops", current_password: adminPassword }),
      }),
      { ...env, DB: db },
    );
    expect(totpSetup.status).toBe(200);
    const totpBody = await json<{ secret: string; otpauth_url: string; user: { username: string; has_totp: boolean } }>(totpSetup);
    expect(totpBody.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(totpBody.otpauth_url).toContain("otpauth://totp/");
    expect(totpBody.user).toMatchObject({ username: "ops", has_totp: true });

    const setupWithoutReauth = await worker.fetch(
      new Request("http://worker.test/api/admin/users/totp/setup", {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "ops" }),
      }),
      { ...env, DB: db },
    );
    expect(setupWithoutReauth.status).toBe(401);
    expect(await json<{ error: string }>(setupWithoutReauth)).toEqual({ error: "admin_reauthentication_required" });

    const noCode = await worker.fetch(
      new Request("http://worker.test/api/admin/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "ops", password: "ops-reset-pass" }),
      }),
      { ...env, DB: db },
    );
    expect(noCode.status).toBe(401);
    expect(await json<{ error: string }>(noCode)).toMatchObject({ error: "totp_required" });

    const { totpCode } = await import("../src/admin-auth");
    const code = await totpCode(totpBody.secret);
    await adminLogin(db, "ops", "ops-reset-pass", code);

    const replayedCode = await worker.fetch(
      new Request("http://worker.test/api/admin/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "ops", password: "ops-reset-pass", totp_code: code }),
      }),
      { ...env, DB: db },
    );
    expect(replayedCode.status).toBe(401);
    expect(await json<{ error: string }>(replayedCode)).toMatchObject({ error: "totp_replay" });

    const totpReset = await worker.fetch(
      new Request("http://worker.test/api/admin/users/totp/reset", {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "ops", current_password: adminPassword }),
      }),
      { ...env, DB: db },
    );
    expect(totpReset.status).toBe(200);

    const deleted = await worker.fetch(
      new Request("http://worker.test/api/admin/users", {
        method: "DELETE",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "ops" }),
      }),
      { ...env, DB: db },
    );
    expect(deleted.status).toBe(200);
    const deletedLogin = await worker.fetch(
      new Request("http://worker.test/api/admin/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "ops", password: "ops-reset-pass" }),
      }),
      { ...env, DB: db },
    );
    expect(deletedLogin.status).toBe(401);

    const lastAdmin = await worker.fetch(
      new Request("http://worker.test/api/admin/users", {
        method: "DELETE",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "admin" }),
      }),
      { ...env, DB: db },
    );
    expect(lastAdmin.status).toBe(400);
    expect(await json<{ error: string }>(lastAdmin)).toMatchObject({ error: "last_admin_required" });
  });

  it("rejects cross-origin admin state changes", async () => {
    const db = memoryD1();
    const { headers } = await setupAdmin(db);
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/users", {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://attacker.example", ...headers },
        body: JSON.stringify({ username: "ops", password: "ops-local-pass" }),
      }),
      { ...env, DB: db },
    );
    expect(response.status).toBe(403);
    expect(await json<{ error: string }>(response)).toEqual({ error: "cross_origin_admin_request" });
  });

  it("enforces the last-admin guard inside the conditional delete statement", async () => {
    const inner = memoryD1();
    const { headers } = await setupAdmin(inner);
    const users = await inner.prepare("SELECT id FROM admin_users").all<{ id: string }>();
    expect(users.results).toHaveLength(1);
    const onlyAdminID = users.results[0].id;
    const seenDeletes: string[] = [];
    const guarded = {
      prepare(sql: string) {
        if (/DELETE\s+FROM\s+admin_users/i.test(sql)) seenDeletes.push(sql);
        return inner.prepare(sql);
      },
      async batch(statements: Array<{ run(): Promise<unknown> }>) {
        for (const statement of statements) await statement.run();
        return statements.map(() => ({ success: true, meta: { changes: 1 } } as D1Result));
      },
    } as unknown as D1Database;

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/users", {
        method: "DELETE",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ user_id: onlyAdminID }),
      }),
      { ...env, DB: guarded },
    );

    expect(response.status).toBe(400);
    expect(await json<{ error: string }>(response)).toEqual({ error: "last_admin_required" });
    expect(seenDeletes).toHaveLength(1);
    expect(seenDeletes[0]).toMatch(/\(SELECT COUNT\(\*\) FROM admin_users\) > 1/);
    // The surviving admin still exists and sessions were not nuked.
    expect(await inner.prepare("SELECT id FROM admin_users WHERE id = ?").bind(onlyAdminID).first()).not.toBeNull();
  });

  it("rotates an admin password and revokes sessions in one atomic batch", async () => {
    const inner = memoryD1();
    const { headers } = await setupAdmin(inner);
    const statements: string[] = [];
    let batched = 0;
    const guarded = {
      prepare(sql: string) {
        const statement = inner.prepare(sql);
        return {
          ...statement,
          bind(...values: unknown[]) {
            const bound = statement.bind(...values);
            return {
              ...bound,
              async run() {
                statements.push(sql);
                return bound.run();
              },
            };
          },
        };
      },
      async batch(stmts: Array<{ run(): Promise<unknown> }>) {
        batched += 1;
        for (const stmt of stmts) await stmt.run();
        return stmts.map(() => ({ success: true, meta: { changes: 1 } } as D1Result));
      },
    } as unknown as D1Database;

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/users/password", {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ username: "admin", password: "rotated-pass-1" }),
      }),
      { ...env, DB: guarded },
    );

    expect(response.status).toBe(200);
    expect(batched).toBe(1);
    const batchSQL = statements.filter((sql) => /UPDATE admin_users|DELETE FROM admin_sessions/.test(sql));
    expect(batchSQL.some((sql) => sql.includes("UPDATE admin_users SET password_hash"))).toBe(true);
    expect(batchSQL.some((sql) => sql.includes("DELETE FROM admin_sessions WHERE user_id"))).toBe(true);
  });

  it("rejects setup via the conditional insert when an admin already exists", async () => {
    const db = memoryD1();
    const first = await worker.fetch(
      new Request("http://worker.test/api/admin/setup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "admin", password: adminPassword }),
      }),
      { ...env, DB: db },
    );
    expect(first.status).toBe(200);

    // Force the onboarding pre-check to pass even though an admin exists
    // (simulates the race window between the check and the insert).
    await insertProjectSetting(db, "on-boarding", { required: true });

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/setup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "second", password: "second-admin-pass" }),
      }),
      { ...env, DB: db },
    );
    expect(response.status).toBe(409);
    expect(await json<{ error: string }>(response)).toEqual({ error: "already_initialized" });
    const users = await db.prepare("SELECT username FROM admin_users").all<{ username: string }>();
    expect(users.results.map((row) => row.username)).toEqual(["admin"]);
  });

  it("requires admin session and upserts nodes", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const payload = {
      id: "testnode01",
      domain: "testnode01.lgtest-node.example",
      port: 8443,
      display_name: "Test Node 01",
      region: "TEST",
      public_ipv4: "203.0.113.9",
      public_ipv6: "",
      features: ["generate204", "download", "ping", "mtr", "traceroute", "nexttrace", "iperf3"],
    };

    const rejected = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      }),
      { ...env, DB: db },
    );
    expect(rejected.status).toBe(401);

    const accepted = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify(payload),
      }),
      { ...env, DB: db },
    );
    expect(accepted.status).toBe(200);
    const body = await json<{ node: { id: string; public_ipv4: string; port: number } }>(accepted);
    expect(body.node).toMatchObject({ id: "testnode01", public_ipv4: "203.0.113.9", port: 8443 });
    expect(body.node).not.toHaveProperty("agent_port");

    const invalidPort = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ ...payload, id: "bad-port", port: 65536 }),
      }),
      { ...env, DB: db },
    );
    expect(invalidPort.status).toBe(400);

    const listed = await worker.fetch(new Request("http://worker.test/api/nodes"), { DB: db });
    const nodes = await json<Array<{ id: string; public_ipv4: string; port: number }>>(listed);
    expect(nodes.find((node) => node.id === "testnode01")).toMatchObject({ id: "testnode01", public_ipv4: "203.0.113.9", port: 8443 });
  });

  it("renames a node slug without replacing its internal identity", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const initialResponse = await worker.fetch(new Request("http://worker.test/api/admin/nodes", { headers: adminHeaders }), { ...env, DB: db });
    const initialNode = (await json<{ nodes: Array<{ id: string; internal_id: string }> }>(initialResponse)).nodes.find((node) => node.id === "testnode01");
    expect(initialNode).toBeTruthy();

    const renamed = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          internal_id: initialNode?.internal_id,
          id: "sg-1",
          domain: "sg-1.example.net",
          display_name: "SG 1",
          region: "SG",
          public_ipv4: "203.0.113.9",
          public_ipv6: "2001:db8::a",
          features: ["generate204", "download", "ping"],
        }),
      }),
      { ...env, DB: db },
    );
    expect(renamed.status).toBe(200);
    expect(await json<{ node: { id: string; internal_id: string } }>(renamed)).toMatchObject({
      node: { id: "sg-1", internal_id: initialNode?.internal_id },
    });

    const adminListed = await worker.fetch(new Request("http://worker.test/api/admin/nodes", { headers: adminHeaders }), { ...env, DB: db });
    const adminNodes = (await json<{ nodes: Array<{ id: string; internal_id: string }> }>(adminListed)).nodes;
    expect(adminNodes.filter((node) => node.internal_id === initialNode?.internal_id)).toHaveLength(1);
    expect(adminNodes.find((node) => node.id === "testnode01")).toBeUndefined();
    expect(adminNodes.find((node) => node.id === "sg-1")).toMatchObject({ internal_id: initialNode?.internal_id });

    const publicListed = await worker.fetch(new Request("http://worker.test/api/nodes"), { DB: db });
    const publicNodes = await json<Array<{ id: string; internal_id: string }>>(publicListed);
    expect(publicNodes.find((node) => node.id === "testnode01")).toBeUndefined();
    expect(publicNodes.find((node) => node.id === "sg-1")).toMatchObject({ internal_id: initialNode?.internal_id });
  });

  it("preserves agent-detected IPs and agent version when admin edits omit IP fields", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const created = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "edge-dyn",
          domain: "edge-dyn.example.net",
          display_name: "Edge Dyn",
          region: "TEST",
          dynamic_ip: true,
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    expect(created.status).toBe(200);
    const createdBody = await json<{ node: { internal_id: string }; init: { token: string } }>(created);

    const bootstrapped = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${createdBody.init.token}` },
        body: JSON.stringify({
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download"],
          detected_ipv4: "198.51.100.20",
          detected_ipv6: "2001:db8::20",
        }),
      }),
      { ...env, DB: db },
    );
    expect(bootstrapped.status).toBe(200);

    const edited = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          internal_id: createdBody.node.internal_id,
          id: "edge-dyn",
          domain: "edge-dyn.example.net",
          display_name: "Edge Dyn Renamed",
          region: "TEST",
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    expect(edited.status).toBe(200);

    const row = await db
      .prepare("SELECT public_ipv4, public_ipv6, version, display_name FROM nodes WHERE id = ?")
      .bind("edge-dyn")
      .first<{ public_ipv4: string | null; public_ipv6: string | null; version: string | null; display_name: string }>();
    expect(row).toMatchObject({
      public_ipv4: "198.51.100.20",
      public_ipv6: "2001:db8::20",
      version: "0.4.0",
      display_name: "Edge Dyn Renamed",
    });
  });

  it("deletes a node with cascade cleanup of tokens and node-scoped rows", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const created = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "edge-del",
          domain: "edge-del.example.net",
          display_name: "Edge Del",
          region: "TEST",
          public_ipv4: "192.0.2.77",
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    expect(created.status).toBe(200);
    const internalID = (await json<{ node: { internal_id: string } }>(created)).node.internal_id;

    const { issueNodeInitToken, issueNodeToken } = await import("../src/node-tokens");
    const nodeToken = await issueNodeToken(db, internalID);
    await issueNodeInitToken(db, internalID);
    await db
      .prepare(
        `INSERT INTO enroll_tokens (id, token_hash, node_id, profile_id, auto_approve, max_uses, used_count, expires_at, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind("enroll_del", "hash-del", internalID, "default", 1, 1, 0, null, 1780000000, null)
      .run();
    await db
      .prepare(
        `INSERT INTO download_links (id, node_id, client_ip_hash, size, token_hash, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`,
      )
      .bind("dl_del", internalID, "iph", "10M", "tokhash", 1780000000, 1780000600)
      .run();
    await db
      .prepare(
        `INSERT INTO iperf_sessions (id, node_id, client_ip_hash, port, status, created_at, expires_at)
         VALUES (?, ?, ?, ?, 'open', ?, ?)`,
      )
      .bind("ipf_del", internalID, "iph", 31742, 1780000000, 1780000180)
      .run();
    await db
      .prepare(
        `INSERT INTO node_certificate_bundles (id, node_id, bundle_id, encrypted_payload, recipient_key_id, status, created_at, synced_at)
         VALUES (?, ?, ?, ?, ?, 'pending', ?, NULL)`,
      )
      .bind("ncb_del", internalID, "cb_x", "{}", "kid", 1780000000)
      .run();

    const unauthenticated = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: "edge-del" }),
      }),
      { ...env, DB: db },
    );
    expect(unauthenticated.status).toBe(401);

    const missing = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "DELETE",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ id: "no-such-node" }),
      }),
      { ...env, DB: db },
    );
    expect(missing.status).toBe(404);

    const deleted = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "DELETE",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ id: "edge-del" }),
      }),
      { ...env, DB: db },
    );
    expect(deleted.status).toBe(200);

    expect(await db.prepare("SELECT id FROM nodes WHERE id = ?").bind(internalID).first()).toBeNull();
    const tokenRow = await db
      .prepare("SELECT id, node_id, revoked_at FROM node_tokens WHERE token_hash = ?")
      .bind(await sha256Hex(nodeToken))
      .first<{ id: string; node_id: string; revoked_at: number | null }>();
    expect(tokenRow).toMatchObject({ node_id: internalID });
    expect(tokenRow?.revoked_at).not.toBeNull();
    // memoryD1's all() ignores WHERE clauses; filter client-side.
    const selectWhere = async (sql: string, nodeID: string): Promise<Array<{ id: string }>> => {
      const rows = (await db.prepare(sql).bind(nodeID).all<{ id: string }>()).results;
      return rows.filter((row) => String((row as unknown as { node_id?: string }).node_id ?? row.id) === nodeID);
    };
    expect((await selectWhere("SELECT id, node_id FROM node_init_tokens WHERE node_id = ?", internalID))).toEqual([]);
    expect((await selectWhere("SELECT id, node_id FROM enroll_tokens WHERE node_id = ?", internalID))).toEqual([]);
    expect((await selectWhere("SELECT id, node_id FROM download_links WHERE node_id = ?", internalID))).toEqual([]);
    expect((await selectWhere("SELECT id, node_id FROM iperf_sessions WHERE node_id = ?", internalID))).toEqual([]);
    expect((await selectWhere("SELECT id, node_id FROM node_certificate_bundles WHERE node_id = ?", internalID))).toEqual([]);
  });

  it("uses the default node profile features when admin creates a node without explicit features", async () => {
    const db = memoryD1();
    await insertNodeProfile(db, "default", {
      features: ["generate204", "ping"],
      limits: defaultProfileConfig.limits,
    });
    const { headers: adminHeaders } = await setupAdmin(db);

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "profile-default-node",
          domain: "profile-default-node.example.net",
          display_name: "Profile Default Node",
          region: "TEST",
          public_ipv4: "192.0.2.20",
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    expect(await json<{ node: { features: string[] } }>(response)).toMatchObject({
      node: { features: ["generate204", "ping"] },
    });
    const listed = await worker.fetch(new Request("http://worker.test/api/nodes"), { DB: db });
    const nodes = await json<Array<{ id: string; features: string[] }>>(listed);
    expect(nodes.find((node) => node.id === "profile-default-node")).toBeUndefined();
  });

  it("issues a one-time node init token when admin creates a node", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "edge01",
          domain: "edge01.example.net",
          display_name: "Edge 01",
          region: "TEST",
          public_ipv4: "192.0.2.10",
          public_ipv6: "2001:db8::10",
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ node: { id: string }; init: { token: string; expires_at: number; pull_command: string } }>(response);
    expect(body.node.id).toBe("edge01");
    expect(body.init.token).toMatch(/^lginit_/);
    const remainingSeconds = body.init.expires_at - Math.floor(Date.now() / 1000);
    expect(remainingSeconds).toBeLessThanOrEqual(900);
    expect(remainingSeconds).toBeGreaterThan(870);
    expect(body.init.pull_command).toContain("/_agent/download?init-key=");
    expect(body.init.pull_command).toContain("bash -s --");
    expect(body.init.pull_command).toContain(body.init.token);

    const update = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "edge01",
          domain: "edge01.example.net",
          display_name: "Edge 01",
          region: "TEST",
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    expect(update.status).toBe(200);
    expect(await json<{ init?: unknown }>(update)).not.toHaveProperty("init");
  });

  it("reissues a one-time init token for an existing node behind admin auth", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);

    const blocked = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/init", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ node_id: "testnode01" }),
      }),
      { ...env, DB: db },
    );
    expect(blocked.status).toBe(401);

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/init", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ node_id: "testnode01" }),
      }),
      { ...env, DB: db },
    );
    expect(response.status).toBe(200);
    const body = await json<{ node: { id: string }; init: { token: string; expires_at: number; pull_command: string } }>(response);
    expect(body.node.id).toBe("testnode01");
    expect(body.init.token).toMatch(/^lginit_/);
    expect(body.init.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(body.init.pull_command).toContain("/_agent/download?init-key=");
    expect(body.init.pull_command).toContain(body.init.token);

    const missing = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/init", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ node_id: "missing" }),
      }),
      { ...env, DB: db },
    );
    expect(missing.status).toBe(404);
  });

  it("reissuing an init key invalidates older keys for that node only", async () => {
    const db = memoryD1();
    const { issueNodeInitToken, validateNodeInitToken, consumeNodeInitToken } = await import("../src/node-tokens");
    const old = await issueNodeInitToken(db, "testnode01");
    const otherNode = await issueNodeInitToken(db, "testnode02");
    const latest = await issueNodeInitToken(db, "testnode01");

    expect(await validateNodeInitToken(db, old.token)).toBeNull();
    await expect(consumeNodeInitToken(db, old.token)).resolves.toBeNull();
    expect(await validateNodeInitToken(db, latest.token)).toMatchObject({ nodeID: "testnode01" });
    expect(await validateNodeInitToken(db, otherNode.token)).toMatchObject({ nodeID: "testnode02" });
    await expect(consumeNodeInitToken(db, latest.token)).resolves.toEqual({ nodeID: "testnode01" });
  });

  it("treats init-token consume as failed when the atomic update returns no row", async () => {
    const { consumeNodeInitToken } = await import("../src/node-tokens");
    const statements: string[] = [];
    const db = {
      prepare(sql: string) {
        statements.push(sql);
        return {
          bind() {
            return {
              async first<T>() {
                return null as T | null;
              },
            };
          },
        };
      },
    } as unknown as D1Database;

    await expect(consumeNodeInitToken(db, "lginit_race")).resolves.toBeNull();
    expect(statements[0]).toMatch(/UPDATE\s+node_init_tokens/i);
    expect(statements[0]).toMatch(/RETURNING\s+node_id/i);
  });

  it("serves the agent installer only for an unconsumed init key", async () => {
    const db = memoryD1();
    const { issueNodeInitToken, validateNodeInitToken } = await import("../src/node-tokens");
    const init = await issueNodeInitToken(db, "testnode01");

    const missing = await worker.fetch(new Request("http://worker.test/_agent/download"), { ...env, DB: db });
    expect(missing.status).toBe(401);

    const invalid = await worker.fetch(new Request("http://worker.test/_agent/download?init-key=bad"), { ...env, DB: db });
    expect(invalid.status).toBe(401);

    const valid = await worker.fetch(new Request(`http://worker.test/_agent/download?init-key=${encodeURIComponent(init.token)}`), {
      ...env,
      DB: db,
    });
    expect(valid.status).toBe(200);
    expect(valid.headers.get("content-type")).toContain("text/x-shellscript");
    const script = await valid.text();
    expect(script).toContain("DEFAULT_AGENT_BINARY_BASE='http://worker.test/_agent/binary'");
    expect(script).toContain('AGENT_BINARY_URL="$DEFAULT_AGENT_BINARY_BASE/hlg-agent-linux-$agent_arch?init-key=$DOWNLOAD_KEY"');
    expect(script).toContain('BINARY_NAME="hlg-agent"');
    expect(script).toContain('SERVICE_NAME="hlg-agent"');
    expect(script).toContain('"$INSTALL_DIR/$BINARY_NAME" init');
    expect(script).toContain('--key "$CONTROLLER_ORIGIN/$DOWNLOAD_KEY"');
    expect(script).toContain('--name "$BINARY_NAME"');
    expect(script).toContain('--service-name "$SERVICE_NAME"');
    expect(script).toContain('SERVICE_MODE="none"');
    expect(script).toContain('setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip');
    expect(script).toContain('BIND_ADDR=""');
    expect(script).toContain("Default: chosen during init (port 443)");
    expect(script).toContain('--service "$SERVICE_MODE"');
    expect(await validateNodeInitToken(db, init.token)).toMatchObject({ nodeID: "testnode01" });
  });

  it("uses D1 agent install settings in init commands and installer defaults", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await insertProjectSetting(db, "AGENT_INSTALL_DIR", "/opt/custom-lg");
    await insertProjectSetting(db, "AGENT_BINARY_NAME", "custom-agent");
    await insertProjectSetting(db, "AGENT_SERVICE_NAME", "custom-hlg-agent");
    await insertProjectSetting(db, "AGENT_RUN_USER", "custom-lg");

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/init", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ node_id: "testnode01" }),
      }),
      { ...env, DB: db },
    );
    expect(response.status).toBe(200);
    const body = await json<{ init: { token: string; pull_command: string; init_string: string; manual: unknown[]; installDir: string; binaryName: string; serviceName: string; runUser: string } }>(response);
    expect(body.init).toMatchObject({
      installDir: "/opt/custom-lg",
      binaryName: "custom-agent",
      serviceName: "custom-hlg-agent",
      runUser: "custom-lg",
    });
    // No ASSETS binding here, so no release manifest: the manual install has no
    // archs and the panel falls back to the one-line install.
    expect(body.init.manual).toEqual([]);
    // The pull command is minimal (the script's defaults come from the stored
    // project settings); the custom install options are baked into the script.
    expect(body.init.pull_command).toContain("/_agent/download?init-key=");
    expect(body.init.pull_command).toContain("bash -s --");
    expect(body.init.pull_command).toContain(`-k 'http://worker.test/${body.init.token}'`);

    // The one-line init string carries the controller origin + the same key.
    expect(body.init.init_string).toBe(`http://worker.test/${body.init.token}`);

    const scriptResponse = await worker.fetch(new Request(`http://worker.test/_agent/download?init-key=${encodeURIComponent(body.init.token)}`), {
      ...env,
      DB: db,
    });
    expect(scriptResponse.status).toBe(200);
    const script = await scriptResponse.text();
    expect(script).toContain('INSTALL_DIR="/opt/custom-lg"');
    expect(script).toContain('DATA_DIR="/opt/custom-lg/data"');
    expect(script).toContain('BINARY_NAME="custom-agent"');
    expect(script).toContain('SERVICE_NAME="custom-hlg-agent"');
    expect(script).toContain('RUN_USER="custom-lg"');
  });

  it("gates bundled agent artifacts behind an unconsumed init key", async () => {
    const db = memoryD1();
    const { issueNodeInitToken, validateNodeInitToken } = await import("../src/node-tokens");
    const init = await issueNodeInitToken(db, "testnode01");
    const assetPaths: string[] = [];
    const assets = {
      fetch: async (request: RequestInfo | URL) => {
        assetPaths.push(new URL(request instanceof Request ? request.url : String(request)).pathname);
        return new Response("artifact-body", {
          headers: {
            "content-type": "application/octet-stream",
            "cache-control": "public, max-age=31536000",
          },
        });
      },
    } as unknown as Fetcher;

    const direct = await worker.fetch(new Request("http://worker.test/_agent/hlg-agent-linux-amd64"), { ...env, DB: db, ASSETS: assets });
    expect(direct.status).toBe(401);
    expect(assetPaths).toEqual([]);

    const invalid = await worker.fetch(new Request("http://worker.test/_agent/binary/hlg-agent-linux-amd64?init-key=bad"), { ...env, DB: db, ASSETS: assets });
    expect(invalid.status).toBe(401);
    expect(assetPaths).toEqual([]);

    const valid = await worker.fetch(new Request(`http://worker.test/_agent/binary/hlg-agent-linux-amd64?init-key=${encodeURIComponent(init.token)}`), {
      ...env,
      DB: db,
      ASSETS: assets,
    });
    expect(valid.status).toBe(200);
    expect(valid.headers.get("cache-control")).toBe("no-store");
    expect(valid.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await valid.text()).toBe("artifact-body");
    expect(assetPaths).toEqual(["/_agent/hlg-agent-linux-amd64"]);
    expect(await validateNodeInitToken(db, init.token)).toMatchObject({ nodeID: "testnode01" });
  });

  it("includes per-arch manual install steps (download + checksum + init) when a release is served", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const nodeUpdate = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "testnode01",
          domain: "testnode01.lgtest-node.example",
          display_name: "Test Node 01",
          port: 8443,
        }),
      }),
      { ...env, DB: db },
    );
    expect(nodeUpdate.status).toBe(200);
    const manifest = {
      build_id: "abc1234",
      targets: [
        { name: "hlg-agent-linux-amd64", sha256: "a".repeat(64), size_bytes: 4096 },
        { name: "hlg-agent-linux-arm64", sha256: "b".repeat(64), size_bytes: 8192 },
      ],
    };
    const assets = {
      fetch: async (request: RequestInfo | URL) => {
        const pathname = new URL(request instanceof Request ? request.url : String(request)).pathname;
        if (pathname.endsWith("/manifest.json")) {
          return new Response(JSON.stringify(manifest), { headers: { "content-type": "application/json" } });
        }
        return new Response("artifact-body", { headers: { "content-type": "application/octet-stream" } });
      },
    } as unknown as Fetcher;

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/init", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ node_id: "testnode01" }),
      }),
      { ...env, DB: db, ASSETS: assets },
    );
    expect(response.status).toBe(200);
    const body = await json<{ node: { port: number }; init: { token: string; manual: Array<{ arch: string; sha256: string; steps: string[] }> } }>(response);
    expect(body.init.manual.map((m) => m.arch)).toEqual(["amd64", "arm64"]);
    expect(body.node.port).toBe(8443);
    expect(body.init).not.toHaveProperty("agentPort");
    const amd64 = body.init.manual[0];
    expect(amd64.sha256).toBe("a".repeat(64));
    expect(amd64.steps).toHaveLength(4);
    expect(amd64.steps[1]).toBe(`echo '${"a".repeat(64)}  /tmp/hlg-agent-linux-amd64' | sha256sum -c -`);
    expect(amd64.steps[3]).toContain(`init -k 'http://worker.test/${body.init.token}'`);
    expect(amd64.steps[3]).not.toContain("--port");
  });

  it("issues a signed release descriptor and serves the binary to an enrolled node token", async () => {
    const db = memoryD1();
    await seedControlPlaneSecrets(db);
    const { issueNodeToken } = await import("../src/node-tokens");
    const nodeToken = await issueNodeToken(db, "testnode01");

    const manifest = {
      build_id: "abc1234",
      targets: [
        { name: "hlg-agent-linux-amd64", sha256: "a".repeat(64), size_bytes: 4096 },
        { name: "hlg-agent-linux-arm64", sha256: "b".repeat(64), size_bytes: 8192 },
      ],
    };
    const assetPaths: string[] = [];
    const assets = {
      fetch: async (request: RequestInfo | URL) => {
        const pathname = new URL(request instanceof Request ? request.url : String(request)).pathname;
        assetPaths.push(pathname);
        if (pathname.endsWith("/manifest.json")) {
          return new Response(JSON.stringify(manifest), { headers: { "content-type": "application/json" } });
        }
        return new Response("artifact-body", { headers: { "content-type": "application/octet-stream" } });
      },
    } as unknown as Fetcher;

    // The descriptor endpoint requires a valid node credential.
    const unauthorized = await worker.fetch(new Request("http://worker.test/_agent/update?arch=amd64"), { ...env, DB: db, ASSETS: assets });
    expect(unauthorized.status).toBe(401);

    const badArch = await worker.fetch(new Request("http://worker.test/_agent/update?arch=riscv", { headers: { authorization: `Bearer ${nodeToken}` } }), { ...env, DB: db, ASSETS: assets });
    expect(badArch.status).toBe(400);

    const described = await worker.fetch(
      new Request("http://worker.test/_agent/update?arch=amd64", { headers: { authorization: `Bearer ${nodeToken}` } }),
      { ...env, DB: db, ASSETS: assets },
    );
    expect(described.status).toBe(200);
    const descriptor = await json<{
      build_id: string;
      target: string;
      sha256: string;
      size: number;
      path: string;
      node_id: string;
      expires_at: number;
      config_kid: string;
      signature: string;
      signing_input: string;
    }>(described);
    expect(descriptor).toMatchObject({
      build_id: "abc1234",
      target: "hlg-agent-linux-amd64",
      sha256: "a".repeat(64),
      size: 4096,
      path: "/_agent/binary/hlg-agent-linux-amd64",
      node_id: "testnode01",
    });
    expect(descriptor.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(descriptor.config_kid).toBeTruthy();
    expect(descriptor.signature).toMatch(/^[A-Za-z0-9_-]+$/);

    // The signature must verify over the exact announced canonical input.
    const { publicKeyFromJWK, base64URLToBytes } = await import("../src/signing");
    const { kidFromJWK } = await import("../src/signing");
    expect(descriptor.config_kid).toBe(await kidFromJWK(TEST_CONFIG_SIGN_JWK));
    const configPublicKey = await crypto.subtle.importKey(
      "raw",
      base64URLToBytes(publicKeyFromJWK(TEST_CONFIG_SIGN_JWK)) as unknown as BufferSource,
      { name: "Ed25519" } as AlgorithmIdentifier,
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      { name: "Ed25519" } as AlgorithmIdentifier,
      configPublicKey,
      base64URLToBytes(descriptor.signature) as unknown as BufferSource,
      new TextEncoder().encode(descriptor.signing_input) as unknown as BufferSource,
    );
    expect(valid).toBe(true);
    expect(descriptor.signing_input).toContain("hlg-agent-release\nabc1234\nhlg-agent-linux-amd64\n");

    // An enrolled node can fetch its own binary with the node token, without a
    // fresh init key.
    const binary = await worker.fetch(
      new Request("http://worker.test/_agent/binary/hlg-agent-linux-amd64", { headers: { authorization: `Bearer ${nodeToken}` } }),
      { ...env, DB: db, ASSETS: assets },
    );
    expect(binary.status).toBe(200);
    expect(await binary.text()).toBe("artifact-body");
  });

  it("exchanges an init token once, then pulls config with the node token", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const created = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "edge01",
          domain: "edge01.example.net",
          display_name: "Edge 01",
          region: "TEST",
          public_ipv4: "192.0.2.10",
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    const createdBody = await json<{ node: { id: string; internal_id: string }; init: { token: string } }>(created);
    const internalNodeID = createdBody.node.internal_id;
    const bootstrapPayload = {
      agent_public_key: TEST_AGENT_PUBLIC_KEY,
      agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
      version: "0.4.0",
      capabilities: ["generate204", "download"],
    };

    const bootstrapped = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${createdBody.init.token}` },
        body: JSON.stringify(bootstrapPayload),
      }),
      { ...env, DB: db },
    );
    expect(bootstrapped.status).toBe(200);
    const bootstrapBody = await json<{ node_id: string; node_token: string; config: { node_id: string; domain: string; keyset: unknown[] } }>(bootstrapped);
    expect(bootstrapBody.node_id).toBe(internalNodeID);
    expect(bootstrapBody.node_token).toMatch(/^lgnode_/);
    expect(bootstrapBody.config).toMatchObject({ node_id: internalNodeID, domain: "edge01.example.net" });
    expect(bootstrapBody.config.keyset.length).toBeGreaterThan(0);

    const replay = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${createdBody.init.token}` },
        body: JSON.stringify(bootstrapPayload),
      }),
      { ...env, DB: db },
    );
    expect(replay.status).toBe(401);

    const configPull = await worker.fetch(
      new Request("http://worker.test/_lg/control/config?node=edge01", {
        headers: { authorization: `Bearer ${bootstrapBody.node_token}` },
      }),
      { ...env, DB: db },
    );
    expect(configPull.status).toBe(200);
    expect(await json<{ node_id: string; domain: string }>(configPull)).toMatchObject({ node_id: internalNodeID, domain: "edge01.example.net" });

    const keysetPull = await worker.fetch(
      new Request("http://worker.test/_lg/control/keyset?node=edge01", {
        headers: { authorization: `Bearer ${bootstrapBody.node_token}` },
      }),
      { ...env, DB: db },
    );
    expect(keysetPull.status).toBe(200);
    expect(await json<{ keyset: unknown[] }>(keysetPull)).toMatchObject({ keyset: expect.any(Array) });
  });

  it("attaches an active managed certificate bundle to a node during bootstrap", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const created = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "edge-cert",
          domain: "edge-cert.example.net",
          display_name: "Edge Cert",
          region: "TEST",
          public_ipv4: "192.0.2.40",
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    const createdBody = await json<{ node: { internal_id: string }; init: { token: string } }>(created);
    const internalNodeID = createdBody.node.internal_id;

    await db.prepare(
      `INSERT INTO certificate_bundles (
        id, domain, version, domains_json, fingerprint_sha256, cert_pem, key_pem, ca_pem,
        cert_expires_at, created_at, active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
    ).bind(
      "cb_test",
      "edge-cert.example.net",
      1,
      JSON.stringify(["edge-cert.example.net"]),
      "aa:bb",
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
      "",
      Math.floor(Date.now() / 1000) + 86400,
      1780000000,
    ).run();

    const bootstrapped = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${createdBody.init.token}` },
        body: JSON.stringify({
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    expect(bootstrapped.status).toBe(200);
    const bootstrapBody = await json<{ node_id: string; cert_sync?: { synced: number; skipped: number; reason?: string } }>(bootstrapped);
    expect(bootstrapBody.node_id).toBe(internalNodeID);
    expect(bootstrapBody.cert_sync).toBeDefined();
  });

  it("atomically elects one winner when bootstrap requests race", async () => {
    const db = memoryD1();
    await insertNodeProfile(db, "default");
    await insertDNSSettings(db);
    await insertRuntimeSecret(db, "LG_CONFIG_SIGN_JWK", JSON.stringify(TEST_CONFIG_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_TOKEN_SIGN_JWK", JSON.stringify(TEST_TOKEN_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_ADMIN_SIGN_JWK", JSON.stringify(TEST_ADMIN_SIGN_JWK));
    await db
      .prepare(
        `INSERT INTO nodes (id, slug, domain, profile_id, enabled, hidden, config_version, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, 0, 1, ?, ?)`,
      )
      .bind("bootstrap-retry", "bootstrap-retry", "bootstrap-retry.example.net", "default", 1780000000, 1780000000)
      .run();
    const { issueNodeInitToken } = await import("../src/node-tokens");
    const init = await issueNodeInitToken(db, "bootstrap-retry");

    const payload = {
      agent_public_key: TEST_AGENT_PUBLIC_KEY,
      agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
      version: "0.4.0",
      capabilities: ["ping", "traceroute"],
    };

    const requests = [TEST_AGENT_PUBLIC_KEY, TEST_CONFIG_SIGN_JWK.x].map((agentKey) =>
      worker.fetch(
        new Request("http://worker.test/_lg/control/config", {
          method: "POST",
          headers: { authorization: `Bearer ${init.token}`, "content-type": "application/json" },
          body: JSON.stringify({ ...payload, agent_public_key: agentKey }),
        }),
        { ...env, DB: db },
      ),
    );
    const [first, second] = await Promise.all(requests);
    expect([first.status, second.status].sort()).toEqual([200, 409]);
    const loser = first.status === 409 ? first : second;
    expect(await json<{ error: string }>(loser)).toEqual({ error: "init_token_consumed" });
    const winner = first.status === 200 ? first : second;
    expect((await json<{ node_token: string }>(winner)).node_token).toMatch(/^lgnode_/);
  });

  it("does not issue a node token when config generation fails after claiming init", async () => {
    const inner = memoryD1();
    await insertNodeProfile(inner, "default");
    await insertRuntimeSecret(inner, "LG_CONFIG_SIGN_JWK", JSON.stringify(TEST_CONFIG_SIGN_JWK));
    await insertRuntimeSecret(inner, "LG_TOKEN_SIGN_JWK", JSON.stringify(TEST_TOKEN_SIGN_JWK));
    await insertRuntimeSecret(inner, "LG_ADMIN_SIGN_JWK", JSON.stringify(TEST_ADMIN_SIGN_JWK));
    await inner.prepare(`INSERT INTO nodes (id, slug, domain, profile_id, enabled, hidden, config_version, created_at, updated_at) VALUES (?, ?, ?, ?, 1, 0, 1, ?, ?)`).bind("bootstrap-failure", "bootstrap-failure", "bootstrap-failure.example.net", "default", 1780000000, 1780000000).run();
    const { issueNodeInitToken } = await import("../src/node-tokens");
    const init = await issueNodeInitToken(inner, "bootstrap-failure");
    let claimed = false;
    const db = {
      prepare(sql: string) {
        if (claimed && sql.includes("FROM runtime_secrets")) throw new Error("config_generation_failure");
        const statement = inner.prepare(sql);
        return {
          bind(...values: unknown[]) {
            const bound = statement.bind(...values);
            return {
              run: async () => {
                const result = await bound.run();
                if (sql.includes("UPDATE node_init_tokens")) claimed = true;
                return result;
              },
              first: bound.first.bind(bound),
              all: bound.all.bind(bound),
            };
          },
        };
      },
    } as unknown as D1Database;
    const response = await worker.fetch(new Request("http://worker.test/_lg/control/config", {
      method: "POST",
      headers: { authorization: `Bearer ${init.token}`, "content-type": "application/json" },
      body: JSON.stringify({ agent_public_key: TEST_AGENT_PUBLIC_KEY, agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY }),
    }), { ...env, DB: db });
    expect(response.status).toBe(503);
    expect(await json<{ error: string }>(response)).toEqual({ error: "bootstrap_failed_new_init_required" });
    const retry = await worker.fetch(new Request("http://worker.test/_lg/control/config", { method: "POST", headers: { authorization: `Bearer ${init.token}`, "content-type": "application/json" }, body: JSON.stringify({ agent_public_key: TEST_AGENT_PUBLIC_KEY, agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY }) }), { ...env, DB: inner });
    expect(retry.status).toBe(401);
  });

  it("does not trigger managed certificate renewal during bootstrap", async () => {
    const db = memoryD1();
    await insertNodeProfile(db, "default");
    await insertDNSSettings(db);
    await insertRuntimeSecret(db, "LG_CONFIG_SIGN_JWK", JSON.stringify(TEST_CONFIG_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_TOKEN_SIGN_JWK", JSON.stringify(TEST_TOKEN_SIGN_JWK));
    await insertRuntimeSecret(db, "LG_ADMIN_SIGN_JWK", JSON.stringify(TEST_ADMIN_SIGN_JWK));
    await insertProjectSetting(db, "ACME_ENABLED", true);
    await db
      .prepare(
        `INSERT INTO nodes (id, slug, domain, profile_id, enabled, hidden, config_version, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, 0, 1, ?, ?)`,
      )
      .bind("bootstrap-no-renew", "bootstrap-no-renew", "bootstrap-no-renew.example.net", "default", 1780000000, 1780000000)
      .run();
    const { issueNodeInitToken } = await import("../src/node-tokens");
    const init = await issueNodeInitToken(db, "bootstrap-no-renew");

    const response = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { authorization: `Bearer ${init.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["ping"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ cert_sync?: { synced: number; skipped: number; reason?: string } }>(response);
    expect(body.cert_sync).toEqual({ synced: 0, skipped: 1, reason: "certificate_not_found" });
  });

  it("backfills dynamic public IPs on bootstrap and updates DNS again when they change", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await seedControlPlaneSecrets(db, { dns: true });
    await seedDnsControlSettings(db);
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        calls.push(request);
        if (request.method === "GET") {
          return new Response(JSON.stringify({ success: true, result: [] }), {
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ success: true, result: { id: `dns-${calls.length}` } }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );

    const created = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "edge-dynamic",
          domain: "edge-dynamic.example.net",
          domain_v4: "edge-dynamic-v4.example.net",
          domain_v6: "edge-dynamic-v6.example.net",
          display_name: "Edge Dynamic",
          region: "TEST",
          dynamic_ip: true,
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );
    expect(created.status).toBe(200);
    const createdBody = await json<{ init: { token: string } }>(created);

    const bootstrapped = await worker.fetch(
      new Request("http://worker.test/_lg/control/config", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${createdBody.init.token}` },
        body: JSON.stringify({
          agent_public_key: TEST_AGENT_PUBLIC_KEY,
          agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
          version: "0.4.0",
          capabilities: ["generate204", "download"],
          detected_ipv4: "198.51.100.20",
          detected_ipv6: "2001:db8::20",
        }),
      }),
      { ...env, DB: db },
    );
    expect(bootstrapped.status).toBe(200);

    const afterBootstrap = await db
      .prepare("SELECT public_ipv4, public_ipv6, dynamic_ip, config_version FROM nodes WHERE id = ?")
      .bind("edge-dynamic")
      .first<{ public_ipv4: string | null; public_ipv6: string | null; dynamic_ip: number; config_version: number }>();
    expect(afterBootstrap).toMatchObject({
      public_ipv4: "198.51.100.20",
      public_ipv6: "2001:db8::20",
      dynamic_ip: 1,
    });
    const dnsCallsAfterBootstrap = calls.filter((call) => call.url.includes("/zones/zone-id/dns_records")).length;
    expect(dnsCallsAfterBootstrap).toBeGreaterThanOrEqual(8);

    const nodeToken = (await json<{ node_token: string }>(bootstrapped)).node_token;
    const updated = await worker.fetch(
      new Request("http://worker.test/_lg/control/config?node=edge-dynamic&detected_ipv4=198.51.100.21", {
        headers: { authorization: `Bearer ${nodeToken}` },
      }),
      { ...env, DB: db },
    );
    expect(updated.status).toBe(200);

    const afterPull = await db
      .prepare("SELECT public_ipv4, public_ipv6, config_version FROM nodes WHERE id = ?")
      .bind("edge-dynamic")
      .first<{ public_ipv4: string | null; public_ipv6: string | null; config_version: number }>();
    expect(afterPull).toMatchObject({
      public_ipv4: "198.51.100.21",
      public_ipv6: "2001:db8::20",
    });
    const dnsCallsAfterPull = calls.filter((call) => call.url.includes("/zones/zone-id/dns_records")).length;
    expect(dnsCallsAfterPull).toBeGreaterThan(dnsCallsAfterBootstrap);

    vi.unstubAllGlobals();
  });

  it("syncs DNS automatically when admin saves a generated-domain node", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await seedControlPlaneSecrets(db, { dns: true });
    await seedDnsControlSettings(db);
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        calls.push(request);
        const url = new URL(request.url);
        const name = url.searchParams.get("name") || "";
        if (request.method === "GET" && name.includes("lgtest-node")) {
          return new Response(JSON.stringify({ success: true, result: [{ id: `old-${name}` }] }), { headers: { "content-type": "application/json" } });
        }
        if (request.method === "GET") {
          return new Response(JSON.stringify({ success: true, result: [] }), { headers: { "content-type": "application/json" } });
        }
        return new Response(JSON.stringify({ success: true, result: { id: `dns-${calls.length}` } }), { headers: { "content-type": "application/json" } });
      }),
    );

    const settings = await worker.fetch(
      new Request("http://worker.test/api/admin/dns-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          base: "lg2.example.net",
          v4_base: "lg2-v4.example.net",
          v6_base: "lg2-v6.example.net",
          single_base: false,
        }),
      }),
      { ...env, DB: db },
    );
    expect(settings.status).toBe(200);

    const accepted = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "testnode01",
          domain: "ignored.example.net",
          display_name: "Test Node 01",
          region: "TEST",
          public_ipv4: "203.0.113.9",
          public_ipv6: "2001:db8::a",
          features: ["generate204", "download"],
          auto_dns: true,
          dns_mode: "id",
        }),
      }),
      { ...env, DB: db },
    );

    expect(accepted.status).toBe(200);
    const body = await json<{ node: { domain: string; domain_v4: string; domain_v6: string }; dns: { records: unknown[]; deleted: unknown[] } }>(accepted);
    expect(body.node).toMatchObject({
      domain: "testnode01.lg2.example.net",
      domain_v4: "testnode01.lg2-v4.example.net",
      domain_v6: "testnode01.lg2-v6.example.net",
    });
    expect(body.dns.records).toHaveLength(4);
    expect(body.dns.deleted).toHaveLength(4);
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(4);
    expect(calls.filter((call) => call.method === "DELETE")).toHaveLength(4);
    vi.unstubAllGlobals();
  });

  it("does not touch DNS when admin saves a custom node with auto DNS disabled", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (request: Request) => {
        calls.push(request);
        return new Response("unexpected", { status: 500 });
      }),
    );

    const accepted = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          id: "custom01",
          domain: "custom.example.net",
          domain_v4: "custom-v4.example.net",
          domain_v6: "custom-v6.example.net",
          display_name: "Custom 01",
          region: "TEST",
          public_ipv4: "192.0.2.44",
          public_ipv6: "2001:db8::44",
          auto_dns: false,
          features: ["generate204", "download"],
        }),
      }),
      { ...env, DB: db },
    );

    expect(accepted.status).toBe(200);
    expect(calls).toHaveLength(0);
    vi.unstubAllGlobals();
  });

  it("reads and writes project DNS settings behind admin auth", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const saved = await worker.fetch(
      new Request("http://worker.test/api/admin/dns-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          base: "lg.example.net",
          v4_base: "lg-v4.example.net",
          v6_base: "lg-v6.example.net",
          single_base: true,
        }),
      }),
      { ...env, DB: db },
    );
    expect(saved.status).toBe(200);

    const loaded = await worker.fetch(new Request("http://worker.test/api/admin/dns-settings", { headers: adminHeaders }), { ...env, DB: db });
    expect(loaded.status).toBe(200);
    // single_base ignores the v4/v6 bases: they are not persisted (the panel
    // disables those inputs, and stale values would only confuse a later switch
    // back to multi-base), so the stored value comes back empty.
    expect(await json<{ settings: { base: string; v4_base: string; v6_base: string; single_base: boolean } }>(loaded)).toMatchObject({
      settings: {
        base: "lg.example.net",
        v4_base: "",
        v6_base: "",
        single_base: true,
      },
    });
  });

  it("accepts single_base with empty IPv4/IPv6 bases (the panel disables those inputs)", async () => {
    // In single-base mode the panel disables v4_base/v6_base, so it submits
    // them empty. The save must not require them, or every single-base save
    // fails with dns_settings_required.
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const saved = await worker.fetch(
      new Request("http://worker.test/api/admin/dns-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ base: "lg.example.net", v4_base: "", v6_base: "", single_base: true }),
      }),
      { ...env, DB: db },
    );
    expect(saved.status).toBe(200);
    expect(await json<{ settings: { base: string; v4_base: string; v6_base: string; single_base: boolean } }>(saved)).toMatchObject({
      settings: { base: "lg.example.net", v4_base: "", v6_base: "", single_base: true },
    });

    // Non-single-base still requires both v4 and v6 bases.
    const invalid = await worker.fetch(
      new Request("http://worker.test/api/admin/dns-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ base: "lg.example.net", v4_base: "", v6_base: "", single_base: false }),
      }),
      { ...env, DB: db },
    );
    expect(invalid.status).toBe(400);
    expect(await json<{ error: string }>(invalid)).toEqual({ error: "dns_settings_required" });
  });

  it("reads and writes runtime project settings behind admin auth", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const customNav = [
      { label: "example.com", href: "https://example.com", external: true },
      { label: "Looking Glass", href: "/", active: true },
      { label: "Tools", href: "/tools", disabled: true, badge: "tba" },
    ];
    const saved = await worker.fetch(
      new Request("http://worker.test/api/admin/project-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "LG_BLOCK_PRIVATE_IPS", value: false }),
      }),
      { ...env, DB: db },
    );
    expect(saved.status).toBe(200);
    expect(await json<{ key: string; value: boolean; source: string }>(saved)).toMatchObject({
      key: "LG_BLOCK_PRIVATE_IPS",
      value: false,
      source: "d1",
    });

    const savedNav = await worker.fetch(
      new Request("http://worker.test/api/admin/project-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "PUBLIC_NAV_ITEMS", value: customNav }),
      }),
      { ...env, DB: db },
    );
    expect(savedNav.status).toBe(200);
    expect(await json<{ key: string; value: typeof customNav; source: string; type: string }>(savedNav)).toMatchObject({
      key: "PUBLIC_NAV_ITEMS",
      type: "json",
      value: customNav,
      source: "d1",
    });

    const listed = await worker.fetch(new Request("http://worker.test/api/admin/project-settings", { headers: adminHeaders }), { ...env, DB: db });
    expect(listed.status).toBe(200);
    expect(await json<{ settings: Array<{ key: string; value: unknown; source: string; type: string }> }>(listed)).toMatchObject({
      settings: expect.arrayContaining([
        expect.objectContaining({ key: "CLOUDFLARE_ZONE_ID", source: "none" }),
        expect.objectContaining({ key: "TURNSTILE_SITE_KEY", source: "none" }),
        expect.objectContaining({ key: "LG_BLOCK_PRIVATE_IPS", value: false, source: "d1" }),
        expect.objectContaining({ key: "PUBLIC_SITE_NAME", value: "Looking Glass", source: "default" }),
        expect.objectContaining({ key: "PUBLIC_NAV_ITEMS", type: "json", value: customNav, source: "d1" }),
      ]),
    });

    const reset = await worker.fetch(
      new Request("http://worker.test/api/admin/project-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "LG_BLOCK_PRIVATE_IPS", reset: true, confirm: "LG_BLOCK_PRIVATE_IPS" }),
      }),
      { ...env, DB: db },
    );
    expect(reset.status).toBe(200);
    expect(await json<{ key: string; source: string }>(reset)).toMatchObject({ key: "LG_BLOCK_PRIVATE_IPS", source: "default" });
  });

  it("uses node domains for agent control and D1 project settings for guards and debug flags", async () => {
    const db = memoryD1();
    await insertProjectSetting(db, "LG_BLOCK_PRIVATE_IPS", false);
    await insertProjectSetting(db, "LG_DEBUG_STREAMS", false);
    await insertProjectSetting(db, "LG_WORKER_DEBUG_LOGS", false);
    await insertProjectSetting(db, "TURNSTILE_SITE_KEY", "site-key-from-d1");
    await insertProjectSetting(db, "PUBLIC_SITE_NAME", "Network Lab");
    await insertProjectSetting(db, "PUBLIC_LOGO_TEXT", "HN");
    await insertProjectSetting(db, "PUBLIC_NAV_ITEMS", [
      { label: "Home", href: "https://example.com", external: true },
      { label: "Looking Glass", href: "/", active: true },
    ]);

    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (request: Request) => {
        calls.push(request);
        return new Response(
          JSON.stringify({
            ok: true,
            session_id: "ipf_project_settings",
            host: "testnode01.lgtest-node.example",
            port: 31742,
            expires_at: 1780300000,
            command: "iperf3 -c testnode01.lgtest-node.example -p 31742 -P 1 -t 10",
          }),
          { headers: { "content-type": "application/json" } },
        );
      }),
    );

    const iperf = await worker.fetch(
      new Request("http://worker.test/api/iperf/session", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", mode: "tcp", reverse: false, duration: 10, parallel: 1, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(iperf.status).toBe(200);
    expect(calls[0].url).toBe("https://testnode01.lgtest-node.example/_lg/control/iperf/open");

    const job = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "10.0.0.8", ipver: "ipv4", count: 4, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(job.status).toBe(200);

    const publicConfig = await worker.fetch(new Request("http://worker.test/api/public-config"), { ...turnstileEnv, DB: db,  });
    expect(publicConfig.status).toBe(200);
    expect(await json<{
      branding: { site_name: string; logo_text: string; logo_image_url: string | null; brand_name: string; show_brand_name: boolean; nav_items: Array<{ label: string; href: string; active?: boolean; external?: boolean }> };
      challenge: { site_key: string };
      debug: { streams: boolean };
    }>(publicConfig)).toMatchObject({
      branding: {
        site_name: "Network Lab",
        logo_text: "HN",
        logo_image_url: null,
        brand_name: "",
        show_brand_name: false,
        nav_items: [
          { label: "Home", href: "https://example.com", external: true },
          { label: "Looking Glass", href: "/", active: true },
        ],
      },
      challenge: { site_key: "site-key-from-d1" },
      debug: { streams: false },
    });

    const { workerDebugEnabled } = await import("../src/log");
    expect(await workerDebugEnabled(db)).toBe(false);
    vi.unstubAllGlobals();
  });

  it("logs out admin sessions", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);

    const logout = await worker.fetch(
      new Request("http://worker.test/api/admin/logout", {
        method: "POST",
        headers: adminHeaders,
      }),
      { ...env, DB: db },
    );
    expect(logout.status).toBe(200);
    expect(logout.headers.get("set-cookie")).toContain("Max-Age=0");

    const rejected = await worker.fetch(new Request("http://worker.test/api/admin/nodes", { headers: adminHeaders }), { ...env, DB: db });
    expect(rejected.status).toBe(401);
  });

  it("stores runtime secrets invisibly and requires explicit override before changing configured values", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const stored = await worker.fetch(
      new Request("http://worker.test/api/admin/runtime-secrets", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "TURNSTILE_SECRET_KEY", value: "secret-value" }),
      }),
      { ...env, DB: db },
    );
    expect(stored.status).toBe(200);
    expect(await json<{ key: string; configured: boolean; source: string; value?: string }>(stored)).toMatchObject({
      key: "TURNSTILE_SECRET_KEY",
      configured: true,
      source: "d1",
    });

    const listed = await worker.fetch(new Request("http://worker.test/api/admin/runtime-secrets", { headers: adminHeaders }), { ...env, DB: db });
    const listedBody = await json<{ secrets: Array<{ key: string; configured: boolean; source: string; value?: string }> }>(listed);
    expect(listedBody.secrets).toEqual(expect.arrayContaining([expect.objectContaining({ key: "TURNSTILE_SECRET_KEY", configured: true, source: "d1" })]));
    expect(listedBody.secrets.some((secret) => "value" in secret)).toBe(false);

    const rejectedOverwrite = await worker.fetch(
      new Request("http://worker.test/api/admin/runtime-secrets", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "TURNSTILE_SECRET_KEY", value: "next-secret-value" }),
      }),
      { ...env, DB: db },
    );
    expect(rejectedOverwrite.status).toBe(409);
    expect(await json<{ error: string }>(rejectedOverwrite)).toEqual({ error: "secret_override_required" });

    const reset = await worker.fetch(
      new Request("http://worker.test/api/admin/runtime-secrets", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "TURNSTILE_SECRET_KEY", reset: true, confirm: "TURNSTILE_SECRET_KEY" }),
      }),
      { ...env, DB: db },
    );
    expect(reset.status).toBe(400);
    expect(await json<{ error: string }>(reset)).toEqual({ error: "secret_reset_disabled" });

    const overwritten = await worker.fetch(
      new Request("http://worker.test/api/admin/runtime-secrets", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "TURNSTILE_SECRET_KEY", value: "next-secret-value", override: true }),
      }),
      { ...env, DB: db },
    );
    expect(overwritten.status).toBe(200);
    expect(await json<{ configured: boolean; source: string }>(overwritten)).toMatchObject({ configured: true, source: "d1" });
  });

  it("uses D1 runtime signing keys before env fallback", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const stored = await worker.fetch(
      new Request("http://worker.test/api/admin/runtime-secrets", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "LG_TOKEN_SIGN_JWK", value: JSON.stringify(TEST_CONFIG_SIGN_JWK), override: true }),
      }),
      { ...env, DB: db },
    );
    expect(stored.status).toBe(200);

    const response = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 5, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );
    expect(response.status).toBe(200);
    const body = await json<{ token: string }>(response);
    expect(await verifyCompactWithJWK(body.token, TEST_CONFIG_SIGN_JWK)).toBe(true);
    expect(await verifyCompactWithJWK(body.token, TEST_TOKEN_SIGN_JWK)).toBe(false);
  });

  it("generates signing runtime secrets without exposing generated values", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const generated = await worker.fetch(
      new Request("http://worker.test/api/admin/runtime-secrets", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "LG_ADMIN_SIGN_JWK", generate: true, confirm: "LG_ADMIN_SIGN_JWK", override: true }),
      }),
      { ...env, DB: db },
    );
    expect(generated.status).toBe(200);
    expect(await json<{ key: string; configured: boolean; source: string; can_generate: boolean; value?: string }>(generated)).toMatchObject({
      key: "LG_ADMIN_SIGN_JWK",
      configured: true,
      source: "d1",
      can_generate: true,
    });
    const generatedACME = await worker.fetch(
      new Request("http://worker.test/api/admin/runtime-secrets", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ key: "ACME_ACCOUNT_JWK", generate: true, confirm: "ACME_ACCOUNT_JWK", override: true }),
      }),
      { ...env, DB: db },
    );
    expect(generatedACME.status).toBe(200);
    expect(await json<{ key: string; configured: boolean; source: string; can_generate: boolean; value?: string }>(generatedACME)).toMatchObject({
      key: "ACME_ACCOUNT_JWK",
      configured: true,
      source: "d1",
      can_generate: true,
    });

    const listed = await worker.fetch(new Request("http://worker.test/api/admin/runtime-secrets", { headers: adminHeaders }), { ...env, DB: db });
    const listedBody = await json<{ secrets: Array<{ key: string; configured: boolean; source: string; can_generate: boolean; value?: string }> }>(listed);
    expect(listedBody.secrets).toEqual(expect.arrayContaining([expect.objectContaining({ key: "LG_ADMIN_SIGN_JWK", configured: true, source: "d1", can_generate: true })]));
    expect(listedBody.secrets).toEqual(expect.arrayContaining([expect.objectContaining({ key: "ACME_ACCOUNT_JWK", configured: true, source: "d1", can_generate: true })]));
    expect(listedBody.secrets.some((secret) => "value" in secret)).toBe(false);
  });

  it("lists nodes with admin-only fields behind admin auth", async () => {
    const db = memoryD1();
    const onboarding = await worker.fetch(new Request("http://worker.test/api/admin/nodes"), { ...env, DB: db });
    expect(onboarding.status).toBe(403);
    expect(await json<{ error: string }>(onboarding)).toMatchObject({ error: "onboarding_required" });

    const { headers: adminHeaders } = await setupAdmin(db);
    const rejected = await worker.fetch(new Request("http://worker.test/api/admin/nodes"), { ...env, DB: db });
    expect(rejected.status).toBe(401);

    const accepted = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes", {
        headers: adminHeaders,
      }),
      { ...env, DB: db },
    );
    expect(accepted.status).toBe(200);
    const body = await json<{ nodes: Array<{ id: string; enabled: boolean; hidden: boolean; config_version: number }> }>(accepted);
    expect(body.nodes[0]).toMatchObject({ id: "testnode01", enabled: true, hidden: false, config_version: 1 });
  });

  it("checks node public endpoints behind admin auth", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (request: RequestInfo | URL) => {
        const url = request instanceof Request ? request.url : String(request);
        calls.push(url);
        if (url.endsWith("/generate_204")) return new Response(null, { status: 204 });
        if (url.endsWith("/info")) {
          return new Response(JSON.stringify({ node: "testnode01", domain: "testnode01.lgtest-node.example" }), {
            headers: { "content-type": "application/json" },
          });
        }
        return new Response("not found", { status: 404 });
      }),
    );

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/check", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({ id: "testnode01" }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ healthy: boolean; domain: string; checks: { generate_204: { ok: boolean }; info: { ok: boolean } } }>(response);
    expect(body).toMatchObject({
      healthy: true,
      domain: "testnode01.lgtest-node.example",
      checks: { generate_204: { ok: true }, info: { ok: true } },
    });
    expect(calls).toEqual([
      "https://testnode01.lgtest-node.example/generate_204",
      "https://testnode01.lgtest-node.example/info",
    ]);
    vi.unstubAllGlobals();
  });

  it("creates node DNS records from configurable split or single bases", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await seedControlPlaneSecrets(db, { dns: true });
    await seedDnsControlSettings(db);
    await insertDNSSettings(db);
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        calls.push(request);
        if (request.method === "GET") {
          return new Response(JSON.stringify({ success: true, result: [] }), { headers: { "content-type": "application/json" } });
        }
        return new Response(JSON.stringify({ success: true, result: { id: `dns-${calls.length}` } }), { headers: { "content-type": "application/json" } });
      }),
    );

    const split = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/dns", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          node_id: "testnode01",
          ipv4: "203.0.113.9",
          ipv6: "2001:db8::a",
        }),
      }),
      { ...env, DB: db },
    );

    expect(split.status).toBe(200);
    const splitBody = await json<{ domains: { domain: string; domain_v4: string; domain_v6: string }; records: Array<{ name: string; type: string }> }>(split);
    expect(splitBody.domains).toEqual({
      domain: "testnode01.lgtest-node.example",
      domain_v4: "testnode01.lgtest-node-v4.example",
      domain_v6: "testnode01.lgtest-node-v6.example",
    });
    expect(splitBody.records.map((record) => `${record.type}:${record.name}`)).toEqual([
      "A:testnode01.lgtest-node.example",
      "AAAA:testnode01.lgtest-node.example",
      "A:testnode01.lgtest-node-v4.example",
      "AAAA:testnode01.lgtest-node-v6.example",
    ]);

    await insertDNSSettings(db, { base: "lg.example.net", v4_base: "lg.example.net", v6_base: "lg.example.net", single_base: true });
    const single = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/dns", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          node_id: "hk02",
          ipv4: "192.0.2.10",
          ipv6: "2001:db8::10",
        }),
      }),
      { ...env, DB: db },
    );

    expect(single.status).toBe(200);
    expect(await json<{ domains: { domain: string; domain_v4: string; domain_v6: string } }>(single)).toMatchObject({
      domains: {
        domain: "hk02.lg.example.net",
        domain_v4: "hk02-v4.lg.example.net",
        domain_v6: "hk02-v6.lg.example.net",
      },
    });

    await insertDNSSettings(db);
    const full = await worker.fetch(
      new Request("http://worker.test/api/admin/nodes/dns", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          node_id: "hk02",
          domain: "lg-hk.example.net",
          domain_v4: "lg-hk-ipv4.example.net",
          domain_v6: "lg-hk-ipv6.example.net",
          ipv4: "192.0.2.10",
          ipv6: "2001:db8::10",
        }),
      }),
      { ...env, DB: db },
    );

    expect(full.status).toBe(200);
    expect(await json<{ domains: { domain: string; domain_v4: string; domain_v6: string } }>(full)).toMatchObject({
      domains: {
        domain: "lg-hk.example.net",
        domain_v4: "lg-hk-ipv4.example.net",
        domain_v6: "lg-hk-ipv6.example.net",
      },
    });
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(12);
    vi.unstubAllGlobals();
  });

  it("requires websocket upgrades on both job websocket routes", async () => {
    for (const path of ["/api/jobs/ws?node=node-a&token=tok.sig", "/api/jobs/live?node=node-a"]) {
      const response = await worker.fetch(new Request(`http://worker.test${path}`), env);
      expect(response.status, path).toBe(400);
      expect(await json<{ error: string }>(response), path).toEqual({ error: "websocket_upgrade_required" });
    }
  });

  it("rewrites browser job tokens for agent websocket proxy", async () => {
    const { agentTokenForJobProxy } = await import("../src/job-proxy");
    const db = memoryD1();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const expectedTokenKid = await expectedKidForJWK(TEST_TOKEN_SIGN_JWK);
    const browserToken = await signCompact(
      {
        typ: "job",
        kid: expectedTokenKid,
        node: "testnode01",
        tool: "ping",
        target: "1.1.1.1",
        ipver: "ipv4",
        count: 1,
        ip: "203.0.113.44",
        ip_binding: "relaxed",
        exp,
        nonce: "browsernoncebrowsernonce",
      },
      TEST_TOKEN_SIGN_JWK,
    );

    const agentToken = await agentTokenForJobProxy(browserToken, { ...env, DB: db }, "testnode01", "203.0.113.44");
    const payload = JSON.parse(new TextDecoder().decode(base64URLToBytes(agentToken.split(".")[0])));
    expect(payload).toMatchObject({ typ: "job", node: "testnode01", ip_binding: "none", ip: "203.0.113.44" });
    expect(payload.nonce).toBe("browsernoncebrowsernonce");
    await expect(agentTokenForJobProxy(browserToken, { ...env, DB: db }, "testnode01", "198.51.100.44")).rejects.toThrow("ip_mismatch");
  });

  it("rejects browser job tokens for a different node before proxying to the agent", async () => {
    const { agentTokenForJobProxy } = await import("../src/job-proxy");
    const db = memoryD1();
    const expectedTokenKid = await expectedKidForJWK(TEST_TOKEN_SIGN_JWK);
    const browserToken = await signCompact(
      {
        typ: "job",
        kid: expectedTokenKid,
        node: "testnode01",
        tool: "ping",
        target: "1.1.1.1",
        ipver: "ipv4",
        count: 5,
        ip: "203.0.113.44",
        ip_binding: "relaxed",
        exp: Math.floor(Date.now() / 1000) + 300,
        nonce: "browsernoncebrowsernonce",
      },
      TEST_TOKEN_SIGN_JWK,
    );

    await expect(agentTokenForJobProxy(browserToken, { ...env, DB: db }, "edge02", "203.0.113.44")).rejects.toThrow("node_mismatch");
  });

  it("preserves remote dns intent in issued job tokens", async () => {
    const db = memoryD1();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ Answer: [{ type: 1, data: "203.0.113.9" }] }), { headers: { "content-type": "application/json" } })),
    );
    const response = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "example.com", ipver: "ipv4", count: 4, remote_dns: true, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(200);
    const body = await json<{ token: string }>(response);
    const payload = JSON.parse(new TextDecoder().decode(base64URLToBytes(body.token.split(".")[0])));
    expect(payload.remote_dns).toBe(true);
    expect(payload.target).toBe("example.com");
    vi.unstubAllGlobals();
  });

  it("rejects job tokens when remote dns resolves to a private address", async () => {
    const db = memoryD1();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ Answer: [{ type: 1, data: "10.0.0.8" }] }), { headers: { "content-type": "application/json" } })),
    );
    const response = await worker.fetch(
      new Request("http://worker.test/api/token/job", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", tool: "ping", target: "internal.example", ipver: "ipv4", count: 4, remote_dns: true, turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(403);
    expect(await json<{ error: string; checked_ips: string[] }>(response)).toEqual({
      error: "blocked_private_ip",
      checked_ips: ["10.0.0.8"],
    });
    vi.unstubAllGlobals();
  });


  it("serializes live job websocket frames with separate stdout and debug streams", async () => {
    const { guardStopMessage, liveJobDebugEnabled, liveJobFrame } = await import("../src/job-proxy");

    expect(JSON.parse(liveJobFrame("stdout", "[1] 1.1.1.1 0.80 ms"))).toEqual({
      stream: "stdout",
      line: "[1] 1.1.1.1 0.80 ms",
    });
    expect(JSON.parse(liveJobFrame("debug", "command closed"))).toEqual({
      stream: "debug",
      line: "command closed",
    });
    expect(await liveJobDebugEnabled(undefined)).toBe(false);
    expect(guardStopMessage("invalid_target")).toBe("stopped: target is not a valid domain or IP");
    expect(guardStopMessage("ip_family_mismatch")).toBe("stopped: target IP does not match the selected IP family");
    expect(guardStopMessage("blocked_private_ip")).toBe("stopped: target is blocked because it resolves to a private/local IP");
  });

  it("runs node init behind admin auth from stored DNS settings and node input", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    await seedControlPlaneSecrets(db, { dns: true });
    await seedDnsControlSettings(db);
    const settings = await worker.fetch(
      new Request("http://worker.test/api/admin/dns-settings", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          base: "lg.example.net",
          v4_base: "lg-v4.example.net",
          v6_base: "lg-v6.example.net",
          single_base: false,
        }),
      }),
      { ...env, DB: db },
    );
    expect(settings.status).toBe(200);
    const calls: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        calls.push(request);
        return new Response(JSON.stringify({ success: true, result: [] }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );

    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/init/node", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          node_id: "edge01",
          display_name: "Edge 01",
          region: "US",
          public_ipv4: "192.0.2.9",
          public_ipv6: "2001:db8::9",
        }),
      }),
      {
        ...env,
        DB: db,
      },
    );

    expect(response.status).toBe(200);
    expect(calls.some((call) => call.url.includes("/zones/zone-id/dns_records"))).toBe(true);
    const listed = await worker.fetch(new Request("http://worker.test/api/admin/nodes", { headers: adminHeaders }), { ...env, DB: db });
    const nodes = (await json<{ nodes: Array<{ id: string; public_ipv6: string }> }>(listed)).nodes;
    expect(nodes.find((node) => node.id === "edge01")).toMatchObject({
      id: "edge01",
      public_ipv6: "2001:db8::9",
    });
    vi.unstubAllGlobals();
  });

  it("rejects node init until DNS settings are stored in D1", async () => {
    const db = memoryD1();
    const { headers: adminHeaders } = await setupAdmin(db);
    const response = await worker.fetch(
      new Request("http://worker.test/api/admin/init/node", {
        method: "POST",
        headers: { "content-type": "application/json", ...adminHeaders },
        body: JSON.stringify({
          node_id: "edge01",
          display_name: "Edge 01",
          public_ipv4: "192.0.2.9",
          public_ipv6: "2001:db8::9",
        }),
      }),
      { ...env, DB: db },
    );

    expect(response.status).toBe(503);
    expect(await json<{ error: string }>(response)).toEqual({ error: "dns_settings_required" });
  });

  it("returns 400 with a structured error for malformed JSON token requests", async () => {
    const db = memoryD1();
    const response = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: '{"node": "testnode01", broken',
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(400);
    expect(await json<{ error: string }>(response)).toEqual({ error: "bad_json" });
  });

  it("returns 400 when a token request omits the JSON content type", async () => {
    const db = memoryD1();
    const response = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "text/plain", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", turnstile_token: "dev-turnstile" }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(400);
    expect(await json<{ error: string }>(response)).toEqual({ error: "json_content_type_required" });
  });

  it("returns 413 for oversized JSON bodies", async () => {
    const db = memoryD1();
    const response = await worker.fetch(
      new Request("http://worker.test/api/token/download", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
        body: JSON.stringify({ node: "testnode01", turnstile_token: "dev-turnstile", pad: "x".repeat(70_000) }),
      }),
      { ...turnstileEnv, DB: db },
    );

    expect(response.status).toBe(413);
    expect(await json<{ error: string }>(response)).toEqual({ error: "payload_too_large" });
  });
});

function memoryD1(options: { seedRuntimeSecrets?: boolean; nodePort?: number } = {}): D1Database {
  const rows = new Map<string, Record<string, unknown>>([
    [
      "testnode01",
      {
        id: "testnode01",
        slug: "testnode01",
        domain: "testnode01.lgtest-node.example",
        port: options.nodePort ?? 443,
        domain_v4: "testnode01.lgtest-node-v4.example",
        domain_v6: "testnode01.lgtest-node-v6.example",
        display_name: "Test Node 01",
        region: "TEST",
        public_ipv4: "203.0.113.9",
        public_ipv6: "2001:db8::a",
        profile_id: "default",
        enabled: 1,
        hidden: 0,
        buy_label: null,
        dynamic_ip: 0,
        capabilities: JSON.stringify(["generate204", "download", "ping", "mtr", "traceroute", "nexttrace", "iperf3"]),
	        maintenance: 0,
	        config_version: 1,
	        agent_public_key: TEST_AGENT_PUBLIC_KEY,
	        agent_encryption_public_key: TEST_AGENT_ENCRYPTION_PUBLIC_KEY,
	        version: "0.3.0",
        created_at: 1780000000,
        updated_at: 1780000000,
      },
    ],
  ]);
  const rateRows = new Map<string, { bucket: string; count: number; reset_at: number; updated_at: number }>();
  const nodeProfiles = new Map<string, { id: string; name: string; config_json: string; created_at: number; updated_at: number }>([
    ["default", { id: "default", name: "Default", config_json: JSON.stringify(defaultProfileConfig), created_at: 1780000000, updated_at: 1780000000 }],
  ]);
  const enrollTokens = new Map<
    string,
    {
      id: string;
      token_hash: string;
      node_id: string | null;
      profile_id: string | null;
      auto_approve: number;
      max_uses: number;
      used_count: number;
      expires_at: number | null;
      created_at: number;
      revoked_at: number | null;
    }
  >();
  const projectSettings = new Map<string, { key: string; value_json: string; updated_at: number }>();
  const taskLocks = new Map<string, number>();
  const acmeOrders = new Map<string, Record<string, unknown>>();
  const adminUsers = new Map<
    string,
    {
      id: string;
      username: string;
      password_hash: string;
      totp_secret: string | null;
      role: string;
      created_at: number;
      updated_at: number;
    }
  >();
  const adminSessions = new Map<string, { id: string; user_id: string; token_hash: string; expires_at: number; created_at: number }>();
  const usedTOTPCodes = new Map<string, { user_id: string; step: number; used_at: number; expires_at: number }>();
  const runtimeSecrets = new Map<string, { key: string; value: string; updated_at: number }>();
  if (options.seedRuntimeSecrets !== false) {
    runtimeSecrets.set("LG_TOKEN_SIGN_JWK", { key: "LG_TOKEN_SIGN_JWK", value: JSON.stringify(TEST_TOKEN_SIGN_JWK), updated_at: 1780000000 });
    runtimeSecrets.set("LG_CONFIG_SIGN_JWK", { key: "LG_CONFIG_SIGN_JWK", value: JSON.stringify(TEST_CONFIG_SIGN_JWK), updated_at: 1780000000 });
    runtimeSecrets.set("LG_ADMIN_SIGN_JWK", { key: "LG_ADMIN_SIGN_JWK", value: JSON.stringify(TEST_ADMIN_SIGN_JWK), updated_at: 1780000000 });
  }
  const nodeInitTokens = new Map<string, { id: string; node_id: string; token_hash: string; created_at: number; expires_at: number; consumed_at: number | null; token_value: string | null }>();
  const nodeTokens = new Map<string, { id: string; node_id: string; token_hash: string; created_at: number; last_used_at: number | null; revoked_at: number | null }>();
  const certificateBundles = new Map<string, Record<string, unknown>>();
  const nodeCertificateBundles = new Map<string, Record<string, unknown>>();
  const downloadLinks: Array<Record<string, unknown>> = [];
  const iperfSessions = new Map<string, Record<string, unknown>>();
  const operationAudit: Array<Record<string, unknown>> = [];
  const schemaTables = [
    "nodes",
    "node_profiles",
    "enroll_tokens",
    "certificate_bundles",
    "node_certificate_bundles",
    "iperf_sessions",
    "rate_limits",
    "download_links",
    "operation_audit",
    "audit_logs",
    "admin_users",
    "admin_sessions",
    "used_totp_codes",
    "project_settings",
    "runtime_secrets",
    "node_init_tokens",
    "node_tokens",
    "acme_pending_orders",
    "node_events",
  ];
  const findNode = (nodeID: unknown): Record<string, unknown> | undefined => {
    const id = String(nodeID);
    return rows.get(id) ?? Array.from(rows.values()).find((row) => row.slug === id);
  };
  return {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async run() {
              let changes = 0;
              if (sql.includes("INSERT INTO nodes")) {
                if (sql.includes("id, slug")) {
                  rows.set(String(values[0]), {
                    id: values[0],
                    slug: values[1],
                    domain: values[2],
                    port: values[3],
                    domain_v4: values[4],
                    domain_v6: values[5],
                    display_name: values[6],
                    display_label: values[7],
                    public_ipv4: values[8],
                    public_ipv6: values[9],
                    description: values[10],
                    buy_url: values[11],
                    buy_label: values[12],
                    bgp_url: values[13],
                    profile_id: values[14],
                    enabled: values[15],
                    hidden: values[16],
                    maintenance: values[17],
                    dynamic_ip: values[18],
                    display_order: values[19],
                    config_version: values[20],
                    agent_public_key: null,
                    agent_encryption_public_key: null,
                    version: values[21],
                    capabilities: values[22],
                    created_at: values[23],
                    updated_at: values[24],
                  });
                } else if (values.length >= 24) {
                  rows.set(String(values[0]), {
                    id: values[0],
                    slug: null,
                    domain: values[1],
                    domain_v4: values[2],
                    domain_v6: values[3],
                    display_name: values[4],
                    display_label: values[5],
                    region: values[6],
                    public_ipv4: values[7],
                    public_ipv6: values[8],
                    description: values[9],
                    buy_url: values[10],
                    buy_label: values[11],
                    bgp_url: values[12],
                    profile_id: values[13],
                    enabled: values[14],
                    hidden: values[15],
                    maintenance: values[16],
                    dynamic_ip: values[17],
                    config_version: values[18],
                    agent_public_key: null,
                    agent_encryption_public_key: null,
                    version: values[19],
                    capabilities: values[20],
                    created_at: values[21],
                    updated_at: values[22],
                  });
                } else {
                  rows.set(String(values[0]), {
                    id: values[0],
                    slug: null,
                    domain: values[1],
                    domain_v4: values[2],
                    domain_v6: values[3],
                    display_name: values[4],
                    display_label: null,
                    region: values[5],
                    public_ipv4: values[6],
                    public_ipv6: values[7],
                    description: null,
                    buy_url: null,
                    buy_label: null,
                    bgp_url: null,
                    profile_id: values[8],
                    enabled: values[9],
                    hidden: values[10],
                    maintenance: values[11],
                    dynamic_ip: 0,
                    config_version: values[12],
                    agent_public_key: null,
                    agent_encryption_public_key: null,
                    version: values[13],
                    capabilities: values[14],
                    created_at: values[15],
                    updated_at: values[16],
                  });
                }
                changes = 1;
              }
              if (sql.includes("UPDATE nodes")) {
                if (sql.includes("build_id = COALESCE(?, build_id)")) {
                  // Heartbeat build/version report: [build_time, version, id].
                  const row = findNode(values[2]);
                  if (row) {
                    if (values[0]) row.build_id = values[0];
                    if (values[1]) row.version = values[1];
                    changes = 1;
                  }
                } else if (sql.includes("AND (agent_public_key IS NULL")) {
                  const row = findNode(String(values[7]));
                  if (row && (!row.agent_public_key || row.agent_public_key === values[8])
                    && (!row.agent_encryption_public_key || row.agent_encryption_public_key === values[9])) {
                    row.agent_public_key = values[0];
                    row.agent_encryption_public_key = values[1];
                    row.version = values[2];
                    row.build_id = values[3] ?? null;
                    row.capabilities = values[4];
                    row.profile_id = values[5] ?? row.profile_id;
                    row.config_version = Number(row.config_version ?? 1) + 1;
                    row.updated_at = values[6];
                    changes = 1;
                  }
                } else if (sql.includes("build_id = ?") && sql.includes("agent_public_key = ?")) {
                  // Enroll (8 binds, has profile_id) / bootstrap (7 binds).
                  // [agent_pubkey, enc_pubkey, version, build_time, capabilities, (profile_id), updated_at, id]
                  const isEnroll = values.length === 8;
                  const row = findNode(String(values[values.length - 1]));
                  if (row) {
                    row.agent_public_key = values[0];
                    row.agent_encryption_public_key = values[1];
                    row.version = values[2];
                    row.build_id = values[3] ?? null;
                    row.capabilities = values[4];
                    row.config_version = Number(row.config_version ?? 1) + 1;
                    row.updated_at = values[isEnroll ? 6 : 5];
                    changes = 1;
                  }
                } else if (sql.includes("SET slug = ?")) {
                  const row = findNode(values[21]);
                  if (row) {
                    row.slug = values[0];
                    row.domain = values[1];
                    row.port = values[2];
                    row.domain_v4 = values[3];
                    row.domain_v6 = values[4];
                    row.display_name = values[5];
                    row.display_label = values[6];
                    row.public_ipv4 = values[7];
                    row.public_ipv6 = values[8];
                    row.description = values[9];
                    row.buy_url = values[10];
                    row.buy_label = values[11];
                    row.bgp_url = values[12];
                    row.profile_id = values[13];
                    row.enabled = values[14];
                    row.hidden = values[15];
                    row.maintenance = values[16];
                    row.dynamic_ip = values[17];
                    row.display_order = values[18];
                    row.config_version = Number(row.config_version ?? 1) + 1;
                    row.capabilities = values[19];
                    row.updated_at = values[20];
                    changes = 1;
                  }
                } else if (sql.includes("public_ipv4 IS ?")) {
                  // Conditional node-ip update: only apply when the stored IPs
                  // still match the previously-read state (values[4]/[5]).
                  const row = findNode(values[3]);
                  if (row && row.public_ipv4 === values[4] && row.public_ipv6 === values[5]) {
                    row.public_ipv4 = values[0];
                    row.public_ipv6 = values[1];
                    row.config_version = Number(row.config_version ?? 1) + 1;
                    row.updated_at = values[2];
                    changes = 1;
                  }
                } else if (values.length === 6 && sql.includes("SET public_ipv4")) {
                  // Unconditional variant of the node-ip update (no IS guard).
                  const row = findNode(values[3]);
                  if (row) {
                    row.public_ipv4 = values[0];
                    row.public_ipv6 = values[1];
                    row.config_version = Number(row.config_version ?? 1) + 1;
                    row.updated_at = values[2];
                    changes = 1;
                  }
                } else if (sql.includes("profile_id = COALESCE")) {
                  const row = findNode(values[6]);
                  if (row) {
                    row.agent_public_key = values[0];
                    row.agent_encryption_public_key = values[1];
                    row.version = values[2];
                    row.capabilities = values[3];
                    row.profile_id = values[4] ?? row.profile_id;
                    row.config_version = Number(row.config_version ?? 1) + 1;
                    row.updated_at = values[5];
                    changes = 1;
                  }
                } else {
                  const row = findNode(values[5]);
                  if (row) {
                    row.agent_public_key = values[0];
                    row.agent_encryption_public_key = values[1];
                    row.version = values[2];
                    row.capabilities = values[3];
                    row.config_version = Number(row.config_version ?? 1) + 1;
                    row.updated_at = values[4];
                    changes = 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM nodes")) {
                // The delete statement matches on id OR slug (two binds);
                // remove every matching row so a slug delete also clears it.
                const deletedID = findNode(values[0]);
                const deletedSlug = findNode(values[1]);
                changes = 0;
                if (deletedID) changes = rows.delete(String(deletedID.id)) ? 1 : 0;
                if (deletedSlug) {
                  if (rows.delete(String(deletedSlug.id))) changes = 1;
                }
              }
              if (sql.includes("INSERT INTO node_profiles")) {
                nodeProfiles.set(String(values[0]), {
                  id: String(values[0]),
                  name: String(values[1]),
                  config_json: String(values[2]),
                  created_at: Number(values[3]),
                  updated_at: Number(values[4]),
                });
                changes = 1;
              }
              if (sql.includes("UPDATE node_profiles")) {
                const row = nodeProfiles.get(String(values[1]));
                if (row) {
                  row.config_json = String(values[0]);
                  row.updated_at = Math.floor(Date.now() / 1000);
                  changes = 1;
                }
              }
              if (sql.includes("INSERT INTO enroll_tokens")) {
                enrollTokens.set(String(values[0]), {
                  id: String(values[0]),
                  token_hash: String(values[1]),
                  node_id: values[2] === null ? null : String(values[2]),
                  profile_id: values[3] === null ? null : String(values[3]),
                  auto_approve: Number(values[4]),
                  max_uses: Number(values[5]),
                  used_count: Number(values[6]),
                  expires_at: values[7] === null ? null : Number(values[7]),
                  created_at: Number(values[8]),
                  revoked_at: values[9] === null ? null : Number(values[9]),
                });
                changes = 1;
              }
              if (sql.includes("UPDATE enroll_tokens")) {
                const row = enrollTokens.get(String(values[0]));
                if (row) {
                  row.used_count += 1;
                  changes = 1;
                }
              }
              if (sql.includes("INSERT INTO rate_limits")) {
                rateRows.set(String(values[0]), {
                  bucket: String(values[1]),
                  count: Number(values[2]),
                  reset_at: Number(values[3]),
                  updated_at: Number(values[4]),
                });
                changes = 1;
              }
              if (sql.includes("UPDATE rate_limits")) {
                const key = String(values[2]);
                const row = rateRows.get(key);
                if (row) {
                  row.count = Number(values[0]);
                  row.updated_at = Number(values[1]);
                  changes = 1;
                }
              }
	              if (sql.includes("UPDATE download_links") && sql.includes("token_hash")) {
	                const row = downloadLinks.find((item) => item.id === values[3]);
	                if (row) {
	                  row.token_hash = values[0];
	                  row.expires_at = values[1];
	                  row.extension_count = Number(row.extension_count ?? 0) + 1;
	                  row.last_extended_at = values[2];
	                  changes = 1;
	                }
	              } else if (sql.includes("UPDATE download_links") && sql.includes("usage_count")) {
	                const row = downloadLinks.find((item) => item.id === values[1] && item.node_id === values[2] && item.status === "active");
	                if (row) {
	                  row.usage_count = Number(row.usage_count ?? 0) + 1;
	                  row.last_used_at = values[0];
	                  changes = 1;
	                }
	              } else if (sql.includes("UPDATE download_links") && sql.includes("status = 'expired'")) {
	                const row = downloadLinks.find((item) => item.id === values[0]);
	                if (row) {
	                  row.status = "expired";
	                  changes = 1;
	                }
	              }
              if (sql.includes("INSERT INTO download_links")) {
                downloadLinks.push({
                  id: values[0],
                  node_id: values[1],
                  client_ip_hash: values[2],
                  size: values[3],
                  token_hash: values[4],
	                  status: "active",
	                  created_at: values[5],
	                  expires_at: values[6],
	                  replaced_at: null,
	                  extension_count: 0,
	                  last_extended_at: null,
	                  usage_count: 0,
	                  last_used_at: null,
	                });
                changes = 1;
              }
              if (sql.includes("INSERT INTO operation_audit")) {
                operationAudit.push({
                  id: values[0],
                  operation_type: values[1],
                  node_id: values[2],
                  client_ip_hash: values[3],
                  status: values[4],
                  metadata_json: values[5],
                  created_at: values[6],
                  expires_at: values[7],
                });
                changes = 1;
              }
              if (sql.includes("UPDATE operation_audit")) {
                const row = operationAudit.find((item) => item.id === values[2]);
                if (row) {
                  row.status = values[0];
                  row.metadata_json = values[1];
                  changes = 1;
                }
              }
              if (sql.includes("INSERT INTO iperf_sessions")) {
                iperfSessions.set(String(values[0]), {
                  id: values[0],
                  node_id: values[1],
                  client_ip_hash: values[2],
                  port: values[3],
                  status: "open",
                  created_at: values[4],
                  expires_at: values[5],
                  closed_at: null,
                });
                changes = 1;
              }
              if (sql.includes("UPDATE iperf_sessions")) {
                const row = iperfSessions.get(String(values[2]));
                if (row) {
                  row.status = values[0];
                  row.closed_at = values[1];
                  changes = 1;
                }
              }
              if (sql.includes("INSERT INTO project_settings")) {
                projectSettings.set(String(values[0]), {
                  key: String(values[0]),
                  value_json: String(values[1]),
                  updated_at: Number(values[2]),
                });
                changes = 1;
              }
              if (sql.includes("INSERT INTO task_locks")) {
                // Guarded upsert: only take the lock when it is free/expired.
                const name = String(values[0]);
                const lockedUntil = Number(values[1]);
                const now = Number(values[3]);
                const current = taskLocks.get(name);
                if (current === undefined || current < now) {
                  taskLocks.set(name, lockedUntil);
                  changes = 1;
                }
              }
              if (sql.includes("INSERT INTO acme_pending_orders")) {
                acmeOrders.set("current", {
                  id: "current",
                  order_url: values[0],
                  finalize_url: values[1],
                  csr_der: values[2],
                  key_pem: values[3],
                  domains_json: values[4],
                  challenges_json: values[5],
                  status: values[6],
                  created_at: values[7],
                  updated_at: values[8],
                });
                changes = 1;
              }
              if (sql.includes("DELETE FROM acme_pending_orders")) {
                changes = acmeOrders.delete("current") ? 1 : 0;
              }
              if (sql.includes("UPDATE task_locks")) {
                const name = String(values[1]);
                taskLocks.set(name, 0);
                changes = 1;
              }
              if (sql.includes("DELETE FROM project_settings")) {
                changes = projectSettings.delete(String(values[0])) ? 1 : 0;
              }
              if (sql.includes("INSERT INTO admin_users")) {
                // Mirror the setup guard: INSERT ... SELECT ... WHERE
                // (SELECT COUNT(*) FROM admin_users) = 0 inserts nothing
                // when any admin already exists.
                if (sql.includes("WHERE (SELECT COUNT(*) FROM admin_users) = 0") && adminUsers.size > 0) {
                  changes = 0;
                } else {
                  adminUsers.set(String(values[0]), {
                    id: String(values[0]),
                    username: String(values[1]),
                    password_hash: String(values[2]),
                    totp_secret: values[3] === null ? null : String(values[3]),
                    role: String(values[4]),
                    created_at: Number(values[5]),
                    updated_at: Number(values[6]),
                  });
                  changes = 1;
                }
              }
              if (sql.includes("UPDATE admin_users SET password_hash")) {
                const row = adminUsers.get(String(values[2]));
                if (row) {
                  row.password_hash = String(values[0]);
                  row.updated_at = Number(values[1]);
                  changes = 1;
                }
              }
              if (sql.includes("UPDATE admin_users SET totp_secret = NULL")) {
                const row = adminUsers.get(String(values[1]));
                if (row) {
                  row.totp_secret = null;
                  row.updated_at = Number(values[0]);
                  changes = 1;
                }
              } else if (sql.includes("UPDATE admin_users SET totp_secret")) {
                const row = adminUsers.get(String(values[2]));
                if (row) {
                  row.totp_secret = String(values[0]);
                  row.updated_at = Number(values[1]);
                  changes = 1;
                }
              }
              if (sql.includes("DELETE FROM admin_users")) {
                // Mirrors the SQL-level last-admin guard: refuse when only one user remains.
                if (adminUsers.size <= 1) changes = 0;
                else changes = adminUsers.delete(String(values[0])) ? 1 : 0;
              }
              if (sql.includes("INSERT INTO admin_sessions")) {
                adminSessions.set(String(values[0]), {
                  id: String(values[0]),
                  user_id: String(values[1]),
                  token_hash: String(values[2]),
                  expires_at: Number(values[3]),
                  created_at: Number(values[4]),
                });
                changes = 1;
              }
              if (sql.includes("DELETE FROM admin_sessions WHERE token_hash")) {
                for (const [id, row] of adminSessions) {
                  if (row.token_hash === String(values[0])) {
                    adminSessions.delete(id);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM admin_sessions WHERE user_id")) {
                for (const [id, row] of adminSessions) {
                  if (row.user_id === String(values[0])) {
                    adminSessions.delete(id);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM admin_sessions WHERE id")) {
                changes = adminSessions.delete(String(values[0])) ? 1 : 0;
              }
              if (sql.includes("DELETE FROM admin_sessions WHERE expires_at")) {
                for (const [id, row] of adminSessions) {
                  if (row.expires_at <= Number(values[0])) {
                    adminSessions.delete(id);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM used_totp_codes")) {
                for (const [key, row] of usedTOTPCodes) {
                  if (row.expires_at <= Number(values[0])) {
                    usedTOTPCodes.delete(key);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("INSERT INTO used_totp_codes")) {
                const key = `${values[0]}:${values[1]}`;
                if (!usedTOTPCodes.has(key)) {
                  usedTOTPCodes.set(key, {
                    user_id: String(values[0]),
                    step: Number(values[1]),
                    used_at: Number(values[2]),
                    expires_at: Number(values[3]),
                  });
                  changes = 1;
                }
              }
              if (sql.includes("INSERT INTO runtime_secrets")) {
                runtimeSecrets.set(String(values[0]), {
                  key: String(values[0]),
                  value: String(values[1]),
                  updated_at: Number(values[2]),
                });
                changes = 1;
              }
              if (sql.includes("INSERT INTO node_init_tokens")) {
                nodeInitTokens.set(String(values[0]), {
                  id: String(values[0]),
                  node_id: String(values[1]),
                  token_hash: String(values[2]),
                  created_at: Number(values[3]),
                  expires_at: Number(values[4]),
                  consumed_at: null,
                  token_value: values[5] === null ? null : String(values[5]),
                });
                changes = 1;
              }
              if (sql.includes("UPDATE node_init_tokens") && !sql.includes("RETURNING")) {
                if (sql.includes("WHERE node_id = ?")) {
                  for (const row of nodeInitTokens.values()) {
                    if (row.node_id !== String(values[1]) || row.consumed_at !== null) continue;
                    row.consumed_at = Number(values[0]);
                    row.token_value = null;
                    changes++;
                  }
                } else {
                  const byKey = nodeInitTokens.get(String(values[1]));
                  const row = byKey ?? Array.from(nodeInitTokens.values()).find((item) => item.token_hash === String(values[1]));
                  if (row && row.consumed_at === null) {
                    row.consumed_at = Number(values[0]);
                    if (sql.includes("token_value = NULL")) row.token_value = null;
                    changes = 1;
                  }
                }
              }
              if (sql.includes("INSERT INTO node_tokens")) {
                nodeTokens.set(String(values[0]), {
                  id: String(values[0]),
                  node_id: String(values[1]),
                  token_hash: String(values[2]),
                  created_at: Number(values[3]),
                  last_used_at: null,
                  revoked_at: null,
                });
                changes = 1;
              }
              if (sql.includes("UPDATE node_tokens SET revoked_at")) {
                for (const row of nodeTokens.values()) {
                  if (row.node_id === values[1] && row.revoked_at === null) {
                    row.revoked_at = Number(values[0]);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM node_init_tokens WHERE node_id")) {
                for (const [id, row] of Array.from(nodeInitTokens)) {
                  if (row.node_id === values[0]) {
                    nodeInitTokens.delete(id);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM enroll_tokens WHERE node_id")) {
                for (const [id, row] of Array.from(enrollTokens)) {
                  if (row.node_id === values[0]) {
                    enrollTokens.delete(id);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM download_links WHERE node_id")) {
                const before = downloadLinks.length;
                for (let index = downloadLinks.length - 1; index >= 0; index--) {
                  if (downloadLinks[index].node_id === values[0]) downloadLinks.splice(index, 1);
                }
                changes = before - downloadLinks.length;
              }
              if (sql.includes("DELETE FROM iperf_sessions WHERE node_id")) {
                for (const [id, row] of Array.from(iperfSessions)) {
                  if (row.node_id === values[0]) {
                    iperfSessions.delete(id);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("DELETE FROM node_certificate_bundles WHERE node_id")) {
                for (const [id, row] of Array.from(nodeCertificateBundles)) {
                  if (row.node_id === values[0]) {
                    nodeCertificateBundles.delete(id);
                    changes += 1;
                  }
                }
              }
              if (sql.includes("UPDATE certificate_bundles")) {
                for (const row of certificateBundles.values()) {
                  if (row.domain === values[0]) {
                    row.active = 0;
                    changes += 1;
                  }
                }
              }
              if (sql.includes("INSERT INTO certificate_bundles")) {
                certificateBundles.set(String(values[0]), {
                  id: values[0],
                  domain: values[1],
                  version: values[2],
                  domains_json: values[3],
                  fingerprint_sha256: values[4],
                  cert_pem: values[5],
                  key_pem: values[6],
                  ca_pem: values[7],
                  cert_expires_at: values[8],
                  created_at: values[9],
                  active: 1,
                });
                changes = 1;
              }
              if (sql.includes("INSERT INTO node_certificate_bundles")) {
                nodeCertificateBundles.set(String(values[0]), {
                  id: values[0],
                  node_id: values[1],
                  bundle_id: values[2],
                  encrypted_payload: values[3],
                  recipient_key_id: values[4],
                  status: "pending",
                  created_at: values[5],
                  synced_at: null,
                });
                changes = 1;
              }
              if (sql.includes("UPDATE node_certificate_bundles")) {
                // SET status = 'synced', synced_at = ? WHERE id = ?
                const row = nodeCertificateBundles.get(String(values[1]));
                if (row) {
                  const target = sql.includes("SET status = 'synced'") ? "synced" : String(values[1]);
                  row.status = target;
                  row.synced_at = values[0];
                  changes = 1;
                }
              }
              if (sql.includes("UPDATE node_tokens") && !sql.includes("SET revoked_at")) {
                const row = nodeTokens.get(String(values[1]));
                if (row) {
                  row.last_used_at = Number(values[0]);
                  changes = 1;
                }
              }
              if (sql.includes("DELETE FROM runtime_secrets")) {
                changes = runtimeSecrets.delete(String(values[0])) ? 1 : 0;
              }
              return { success: true, meta: { changes } } as D1Result;
            },
            async all<T>() {
              if (sql.includes("FROM sqlite_master")) {
                return {
                  results: schemaTables.map((name) => ({ name })) as T[],
                  success: true,
                } as D1Result<T>;
              }
              if (sql.includes("FROM project_settings")) {
                return {
                  results: Array.from(projectSettings.values()) as T[],
                  success: true,
                } as D1Result<T>;
              }
              if (sql.includes("FROM runtime_secrets")) {
                return {
                  results: Array.from(runtimeSecrets.values()).map((row) => ({ key: row.key })) as T[],
                  success: true,
                } as D1Result<T>;
              }
              if (sql.includes("FROM download_links")) {
                return {
                  results: downloadLinks.map((row) => ({ size: row.size, status: row.status })) as T[],
                  success: true,
                } as D1Result<T>;
              }
              if (sql.includes("FROM operation_audit")) {
                if (sql.includes("status") || sql.includes("metadata_json")) {
                  return {
                    results: operationAudit as T[],
                    success: true,
                  } as D1Result<T>;
                }
                return {
                  results: operationAudit.map((row) => ({ operation_type: row.operation_type })) as T[],
                  success: true,
                } as D1Result<T>;
              }
              if (sql.includes("FROM iperf_sessions")) {
                if (sql.includes("expires_at <= ?")) {
                  return {
                    results: Array.from(iperfSessions.values()).filter(
                      (row) => row.status === "open" && typeof row.expires_at === "number" && row.expires_at <= Number(values[0]),
                    ) as T[],
                    success: true,
                  } as D1Result<T>;
                }
                if (sql.includes("id, status, closed_at")) {
                  return {
                    results: Array.from(iperfSessions.values()).map((row) => ({ id: row.id, status: row.status, closed_at: row.closed_at })) as T[],
                    success: true,
                  } as D1Result<T>;
                }
                return {
                  results: Array.from(iperfSessions.values()) as T[],
                  success: true,
                } as D1Result<T>;
              }
              if (sql.includes("FROM admin_users")) {
                if (sql.includes("has_totp")) {
                  return {
                    results: Array.from(adminUsers.values())
                      .sort((a, b) => a.created_at - b.created_at || a.username.localeCompare(b.username))
                      .map((row) => ({
                        id: row.id,
                        username: row.username,
                        role: row.role,
                        has_totp: row.totp_secret ? 1 : 0,
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                      })) as T[],
                    success: true,
                  } as D1Result<T>;
                }
                return {
                  results: Array.from(adminUsers.values()).sort((a, b) => a.created_at - b.created_at || a.username.localeCompare(b.username)) as T[],
                  success: true,
                } as D1Result<T>;
              }
              const nodeRows = sql.includes("agent_public_key IS NOT NULL")
                ? Array.from(rows.values()).filter((row) => row.agent_public_key)
                : Array.from(rows.values());
              const results = nodeRows.sort((a, b) => String(a.slug ?? a.id).localeCompare(String(b.slug ?? b.id))) as T[];
              return { results, success: true } as D1Result<T>;
            },
            async first<T>() {
              if (sql.includes("FROM acme_pending_orders")) {
                return (acmeOrders.get("current") ?? null) as T | null;
              }
              if (sql.includes("UPDATE download_links") && sql.includes("RETURNING extension_count")) {
                const row = downloadLinks.find(
                  (item) =>
                    item.id === values[3] &&
                    item.node_id === values[4] &&
                    item.client_ip_hash === values[5] &&
                    item.token_hash === values[6] &&
                    item.status === "active" &&
                    typeof item.expires_at === "number" &&
                    item.expires_at > Number(values[7]) &&
                    Number(item.extension_count ?? 0) < Number(values[8]),
                );
                if (!row) return null as T | null;
                row.token_hash = values[0];
                row.expires_at = values[1];
                row.extension_count = Number(row.extension_count ?? 0) + 1;
                row.last_extended_at = values[2];
                return { extension_count: row.extension_count } as T;
              }
              if (sql.includes("UPDATE download_links") && sql.includes("RETURNING usage_count")) {
                const row = downloadLinks.find(
                  (item) =>
                    item.id === values[1] &&
                    item.node_id === values[2] &&
                    item.status === "active" &&
                    typeof item.expires_at === "number" &&
                    item.expires_at > Number(values[3]),
                );
                if (!row) return null as T | null;
                row.usage_count = Number(row.usage_count ?? 0) + 1;
                row.last_used_at = values[0];
                return { usage_count: row.usage_count } as T;
              }
              if (sql.includes("INSERT INTO rate_limits")) {
                const key = String(values[0]);
                const bucket = String(values[1]);
                const resetAt = Number(values[2]);
                const updatedAt = Number(values[3]);
                const now = Number(values[4]);
                const limit = Number(values[7]);
                const row = rateRows.get(key);
                if (!row || row.reset_at <= now) {
                  rateRows.set(key, { bucket, count: 1, reset_at: resetAt, updated_at: updatedAt });
                  return { count: 1, reset_at: resetAt } as T;
                }
                if (row.count >= limit) return null as T | null;
                row.count += 1;
                row.updated_at = updatedAt;
                return { count: row.count, reset_at: row.reset_at } as T;
              }
              if (sql.includes("UPDATE enroll_tokens")) {
                const row = Array.from(enrollTokens.values()).find((item) => item.token_hash === String(values[0]));
                const now = Number(values[1]);
                if (!row || row.node_id === null || row.revoked_at !== null || (row.expires_at !== null && row.expires_at <= now) || row.used_count >= row.max_uses) {
                  return null as T | null;
                }
                row.used_count += 1;
                return row as T;
              }
              if (sql.includes("UPDATE node_init_tokens") && sql.includes("RETURNING node_id")) {
                const row = Array.from(nodeInitTokens.values()).find(
                  (item) => item.token_hash === String(values[1]) && item.consumed_at === null && item.expires_at > Number(values[2]),
                );
                if (!row) return null as T | null;
                row.consumed_at = Number(values[0]);
                if (sql.includes("token_value = NULL")) {
                  row.token_value = null;
                }
                return { node_id: row.node_id } as T;
              }
              if (sql.includes("FROM rate_limits")) {
                const row = rateRows.get(String(values[0]));
                return (row ? { count: row.count, reset_at: row.reset_at } : null) as T | null;
              }
              if (sql.includes("FROM project_settings")) {
                return (projectSettings.get(String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("FROM node_profiles")) {
                return (nodeProfiles.get(String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("FROM enroll_tokens")) {
                return (Array.from(enrollTokens.values()).find((row) => row.token_hash === String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("COUNT(*) AS count FROM admin_users")) {
                return { count: adminUsers.size } as T;
              }
              if (sql.includes("FROM admin_sessions")) {
                const session = Array.from(adminSessions.values()).find((row) => row.token_hash === String(values[0]));
                const user = session ? adminUsers.get(session.user_id) : null;
                if (session && values.length > 1 && session.expires_at <= Number(values[1])) return null as T | null;
                return (session && user
                  ? {
                      session_id: session.id,
                      id: user.id,
                      username: user.username,
                      role: user.role,
                      expires_at: session.expires_at,
                    }
                  : null) as T | null;
              }
              if (sql.includes("FROM admin_users WHERE username")) {
                return (Array.from(adminUsers.values()).find((row) => row.username === String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("FROM admin_users WHERE id")) {
                return (adminUsers.get(String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("FROM runtime_secrets")) {
                return (runtimeSecrets.get(String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("FROM node_init_tokens") && sql.includes("consumed_at IS NULL")) {
                const row = Array.from(nodeInitTokens.values()).find(
                  (item) => item.token_hash === String(values[0]) && item.consumed_at === null && item.expires_at > Number(values[1]),
                );
                return (row ? { node_id: row.node_id, expires_at: row.expires_at } : null) as T | null;
              }
              if (sql.includes("FROM node_init_tokens")) {
                return (Array.from(nodeInitTokens.values()).find((row) => row.token_hash === String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("FROM node_certificate_bundles")) {
                // Three shapes: ACK lookup by (id, node_id); a bare lookup by
                // id (test assertions); and delivery of the newest row/node.
                if (sql.includes("WHERE id = ?") && !sql.includes("node_id")) {
                  const row = nodeCertificateBundles.get(String(values[0]));
                  return (row ? { id: row.id, bundle_id: row.bundle_id, status: row.status, synced_at: row.synced_at } : null) as T | null;
                }
                if (sql.includes("WHERE id = ? AND node_id = ?")) {
                  const row = nodeCertificateBundles.get(String(values[0]));
                  if (!row || row.node_id !== values[1]) return null as T | null;
                  return { id: row.id, bundle_id: row.bundle_id, status: row.status } as T | null;
                }
                const rows = Array.from(nodeCertificateBundles.values())
                  .filter((row) => row.node_id === values[0])
                  .sort((a, b) => Number(b.created_at) - Number(a.created_at));
                const row = rows[0];
                return (row ? { id: row.id, bundle_id: row.bundle_id, status: row.status, encrypted_payload: row.encrypted_payload } : null) as T | null;
              }
              if (sql.includes("FROM certificate_bundles")) {
                const activeOnly = sql.includes("WHERE active = 1");
                const fingerprint = sql.includes("fingerprint_sha256 = ?") ? String(values[0]) : null;
                const domainsJSON = sql.includes("domains_json = ?") ? String(values[1]) : null;
                const expiresAt = sql.includes("cert_expires_at = ?") ? Number(values[2]) : null;
                const row = Array.from(certificateBundles.values())
                  .filter((item) => !activeOnly || Number(item.active) === 1)
                  .filter((item) => fingerprint === null || item.fingerprint_sha256 === fingerprint)
                  .filter((item) => domainsJSON === null || item.domains_json === domainsJSON)
                  .filter((item) => expiresAt === null || Number(item.cert_expires_at) === expiresAt)
                  .sort((a, b) => Number(b.created_at) - Number(a.created_at))[0];
                return (row ?? null) as T | null;
              }
	              if (sql.includes("FROM node_tokens")) {
	                return (Array.from(nodeTokens.values()).find((row) => row.token_hash === String(values[0])) ?? null) as T | null;
	              }
	              if (sql.includes("FROM download_links")) {
	                if (values.length === 1) {
	                  return (downloadLinks.find((item) => item.id === values[0]) ?? null) as T | null;
	                }
	                const row = downloadLinks.find(
	                  (item) =>
	                    item.id === values[0] &&
	                    item.node_id === values[1] &&
	                    item.client_ip_hash === values[2] &&
	                    item.token_hash === values[3],
	                );
	                return (row ?? null) as T | null;
	              }
	              if (sql.includes("FROM iperf_sessions")) {
                const row = iperfSessions.get(String(values[0]));
                if (!row) return null as T | null;
                if (values.length > 1 && row.node_id !== values[1]) return null as T | null;
                if (values.length > 2 && row.client_ip_hash !== values[2]) return null as T | null;
                return row as T;
              }
              return (findNode(values[0]) ?? null) as T | null;
            },
          };
        },
        async all<T>() {
          if (sql.includes("FROM sqlite_master")) {
            return {
              results: schemaTables.map((name) => ({ name })) as T[],
              success: true,
            } as D1Result<T>;
          }
          if (sql.includes("FROM project_settings")) {
            return {
              results: Array.from(projectSettings.values()) as T[],
              success: true,
            } as D1Result<T>;
          }
          if (sql.includes("FROM runtime_secrets")) {
            return {
              results: Array.from(runtimeSecrets.values()).map((row) => ({ key: row.key })) as T[],
              success: true,
            } as D1Result<T>;
          }
          if (sql.includes("FROM certificate_bundles")) {
            return {
              results: Array.from(certificateBundles.values())
                .filter((row) => !sql.includes("WHERE active = 1") || Number(row.active) === 1)
                .sort((a, b) => Number(b.created_at) - Number(a.created_at)) as T[],
              success: true,
            } as D1Result<T>;
          }
          if (sql.includes("FROM download_links")) {
            return {
              results: downloadLinks.map((row) => ({ size: row.size, status: row.status })) as T[],
              success: true,
            } as D1Result<T>;
          }
          if (sql.includes("FROM operation_audit")) {
            if (sql.includes("status") || sql.includes("metadata_json")) {
              return {
                results: operationAudit as T[],
                success: true,
              } as D1Result<T>;
            }
            return {
              results: operationAudit.map((row) => ({ operation_type: row.operation_type })) as T[],
              success: true,
            } as D1Result<T>;
          }
          if (sql.includes("FROM iperf_sessions")) {
            if (sql.includes("id, status, closed_at")) {
              return {
                results: Array.from(iperfSessions.values()).map((row) => ({ id: row.id, status: row.status, closed_at: row.closed_at })) as T[],
                success: true,
              } as D1Result<T>;
            }
            return {
              results: Array.from(iperfSessions.values()) as T[],
              success: true,
            } as D1Result<T>;
          }
          if (sql.includes("FROM admin_users")) {
            if (sql.includes("has_totp")) {
              return {
                results: Array.from(adminUsers.values())
                  .sort((a, b) => a.created_at - b.created_at || a.username.localeCompare(b.username))
                  .map((row) => ({
                    id: row.id,
                    username: row.username,
                    role: row.role,
                    has_totp: row.totp_secret ? 1 : 0,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                  })) as T[],
                success: true,
              } as D1Result<T>;
            }
            return {
              results: Array.from(adminUsers.values()).sort((a, b) => a.created_at - b.created_at || a.username.localeCompare(b.username)) as T[],
              success: true,
            } as D1Result<T>;
          }
          const nodeRows = sql.includes("agent_public_key IS NOT NULL")
            ? Array.from(rows.values()).filter((row) => row.agent_public_key)
            : Array.from(rows.values());
          const results = nodeRows.sort((a, b) => String(a.slug ?? a.id).localeCompare(String(b.slug ?? b.id))) as T[];
          return { results, success: true } as D1Result<T>;
        },
        async first<T>() {
          if (sql.includes("COUNT(*) AS count FROM admin_users")) {
            return { count: adminUsers.size } as T;
          }
          if (sql.includes("FROM acme_pending_orders")) {
            return (acmeOrders.get("current") ?? null) as T | null;
          }
          return null as T | null;
        },
      };
    },
    async batch(statements: Array<{ run(): Promise<unknown> }>) {
      // The other agents' atomic batches (cert bundle swap, password
      // rotation, session deletes) run through the same fake run() handler.
      const results: D1Result[] = [];
      for (const statement of statements) results.push((await statement.run()) as D1Result);
      return results;
    },
  } as unknown as D1Database;
}
