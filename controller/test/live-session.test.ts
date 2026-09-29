import { describe, expect, it } from "vitest";
import type { Env } from "../src/config";
import worker from "../src/index";
import { authorizeLiveJobSocket } from "../src/job-proxy";
import { LIVE_SESSION_TTL_SECONDS, relaxedIPMatch, verifyLiveSessionToken } from "../src/session-token";
import { base64URLToBytes, bytesToBase64URL, signCompact } from "../src/signing";

// Ed25519 signing keys are generated per test run instead of being committed:
// private JWK material must never live in the repository.
async function generateEd25519PrivateJWK(): Promise<JsonWebKey> {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"]);
  const privateKey = "privateKey" in keyPair ? keyPair.privateKey : keyPair;
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return { crv: "Ed25519", d: jwk.d, x: jwk.x, kty: "OKP" };
}

const TEST_TOKEN_SIGN_JWK = await generateEd25519PrivateJWK();
const TEST_AGENT_PUBLIC_KEY = TEST_TOKEN_SIGN_JWK.x;
const TEST_AGENT_ENCRYPTION_PUBLIC_KEY = "BESaVZlSBvPTn8DH7a2HuC4T9mNsSzANH7bM6okjdYfkOX9YZR461tJ91e0iKbH6wy6SwVGZ0AbExqRbsjTmFV4";

function json<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

function compactPayload(token: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64URLToBytes(token.split(".")[0]))) as Record<string, unknown>;
}

async function expectedKidForJWK(jwk: JsonWebKey): Promise<string> {
  if (typeof jwk.x !== "string") throw new Error("missing_public_key");
  const raw = base64URLToBytes(jwk.x);
  const buffer = new ArrayBuffer(raw.byteLength);
  new Uint8Array(buffer).set(raw);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
  return bytesToBase64URL(digest.slice(0, 8));
}

function memoryD1(): D1Database {
  const rows = new Map<string, Record<string, unknown>>([
    [
      "testnode01",
      {
        id: "testnode01",
        slug: "testnode01",
        domain: "testnode01.lgtest-node.example",
        domain_v4: "testnode01.lgtest-node-v4.example",
        domain_v6: "testnode01.lgtest-node-v6.example",
        display_name: "Test Node 01",
        display_label: "TEST",
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
  const runtimeSecrets = new Map<string, { key: string; value: string; updated_at: number }>([
    ["LG_TOKEN_SIGN_JWK", { key: "LG_TOKEN_SIGN_JWK", value: JSON.stringify(TEST_TOKEN_SIGN_JWK), updated_at: 1780000000 }],
  ]);
  const projectSettings = new Map<string, { key: string; value_json: string; updated_at: number }>();
  const operationAudit: Array<Record<string, unknown>> = [];
  return {
    prepare(sql: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async run() {
              let changes = 0;
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
              if (sql.includes("INSERT INTO runtime_secrets")) {
                runtimeSecrets.set(String(values[0]), {
                  key: String(values[0]),
                  value: String(values[1]),
                  updated_at: Number(values[2]),
                });
                changes = 1;
              }
              if (sql.includes("INSERT INTO operation_audit")) {
                operationAudit.push({
                  id: values[0],
                  operation_type: values[1],
                  node_id: values[2],
                  status: values[4],
                  created_at: values[6],
                });
                changes = 1;
              }
              if (sql.includes("INSERT INTO project_settings")) {
                projectSettings.set(String(values[0]), {
                  key: String(values[0]),
                  value_json: String(values[1]),
                  updated_at: Number(values[2]),
                });
                changes = 1;
              }
              return { success: changes > 0, meta: { changes } };
            },
            async first<T>() {
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
              if (sql.includes("FROM rate_limits")) {
                const row = rateRows.get(String(values[0]));
                return (row ? { count: row.count, reset_at: row.reset_at } : null) as T | null;
              }
              if (sql.includes("FROM project_settings")) {
                return (projectSettings.get(String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("FROM runtime_secrets")) {
                return (runtimeSecrets.get(String(values[0])) ?? null) as T | null;
              }
              if (sql.includes("SELECT value FROM runtime_secrets") || sql.includes("SELECT key, value, updated_at FROM runtime_secrets")) {
                return (runtimeSecrets.get(String(values[0])) ?? null) as T | null;
              }
              return ((values[0] !== undefined && (rows.get(String(values[0])) ?? Array.from(rows.values()).find((row) => row.slug === String(values[0])))) ?? null) as T | null;
            },
            async all<T>() {
              if (sql.includes("FROM project_settings")) {
                return { results: Array.from(projectSettings.values()) as T[], success: true } as D1Result<T>;
              }
              if (sql.includes("FROM runtime_secrets")) {
                return { results: Array.from(runtimeSecrets.values()).map((row) => ({ key: row.key })) as T[], success: true } as D1Result<T>;
              }
              if (sql.includes("FROM operation_audit")) {
                return { results: operationAudit as T[], success: true } as D1Result<T>;
              }
              const nodeRows = sql.includes("agent_public_key IS NOT NULL")
                ? Array.from(rows.values()).filter((row) => row.agent_public_key)
                : Array.from(rows.values());
              return { results: nodeRows as T[], success: true } as D1Result<T>;
            },
          };
        },
        async all<T>() {
          if (sql.includes("FROM operation_audit")) {
            return { results: operationAudit as T[], success: true } as D1Result<T>;
          }
          const nodeRows = sql.includes("agent_public_key IS NOT NULL")
            ? Array.from(rows.values()).filter((row) => row.agent_public_key)
            : Array.from(rows.values());
          return { results: nodeRows as T[], success: true } as D1Result<T>;
        },
      };
    },
  } as unknown as D1Database;
}

const liveSessionEnv = {} as Env;

function liveSessionRequest(node: string, turnstileToken?: string): Request {
  return new Request("http://worker.test/api/jobs/live-session", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
    body: JSON.stringify({ node, turnstile_token: turnstileToken }),
  });
}

describe("live session endpoint", () => {
  it("issues a typ=live session token without a challenge when Turnstile is unconfigured", async () => {
    const db = memoryD1();
    const response = await worker.fetch(liveSessionRequest("testnode01"), { ...liveSessionEnv, DB: db });
    expect(response.status).toBe(200);
    const body = await json<{ token: string; expires_at: number; node: string; domain: string }>(response);
    const payload = compactPayload(body.token);
    expect(payload).toMatchObject({
      typ: "live",
      node: "testnode01",
      ip: "203.0.113.44",
      ip_binding: "relaxed",
    });
    const secondsLeft = body.expires_at - Math.floor(Date.now() / 1000);
    expect(secondsLeft).toBeGreaterThanOrEqual(LIVE_SESSION_TTL_SECONDS - 5);
    expect(secondsLeft).toBeLessThanOrEqual(LIVE_SESSION_TTL_SECONDS);
    expect(body.node).toBe("testnode01");
  });

  it("rate limits live session issuance after four requests per minute", async () => {
    const db = memoryD1();
    for (let index = 0; index < 4; index++) {
      const response = await worker.fetch(liveSessionRequest("testnode01"), { ...liveSessionEnv, DB: db });
      expect(response.status).toBe(200);
    }
    const limited = await worker.fetch(liveSessionRequest("testnode01"), { ...liveSessionEnv, DB: db });
    expect(limited.status).toBe(429);
    expect(await json<{ error: string }>(limited)).toMatchObject({ error: "rate_limited" });
  });

  it("returns 404 for an unknown node", async () => {
    const db = memoryD1();
    const response = await worker.fetch(liveSessionRequest("ghostnode"), { ...liveSessionEnv, DB: db });
    expect(response.status).toBe(404);
    expect(await json<{ error: string }>(response)).toMatchObject({ error: "node_not_found" });
  });

  it("requires turnstile when configured", async () => {
    const db = memoryD1();
    await db.prepare("INSERT INTO runtime_secrets (key, value, updated_at) VALUES (?, ?, ?)").bind("TURNSTILE_SECRET_KEY", "turnstile-secret", 1780000000).run();
    const response = await worker.fetch(liveSessionRequest("testnode01"), { ...liveSessionEnv, DB: db });
    expect(response.status).toBe(403);
    expect(await json<{ error: string }>(response)).toMatchObject({ error: "turnstile_required" });
  });
});

describe("live websocket auth", () => {
  it("rejects the live websocket without a token", async () => {
    const db = memoryD1();
    const response = await worker.fetch(
      new Request("http://worker.test/api/jobs/live?node=testnode01", { headers: { upgrade: "websocket", "cf-connecting-ip": "203.0.113.44" } }),
      { ...liveSessionEnv, DB: db },
    );
    expect(response.status).toBe(401);
    expect(await json<{ error: string }>(response)).toEqual({ error: "live_session_required" });
  });

  it("rejects the live websocket with an invalid token", async () => {
    const db = memoryD1();
    const response = await worker.fetch(
      new Request("http://worker.test/api/jobs/live?node=testnode01&token=not-a-token", { headers: { upgrade: "websocket", "cf-connecting-ip": "203.0.113.44" } }),
      { ...liveSessionEnv, DB: db },
    );
    expect(response.status).toBe(401);
    expect(await json<{ error: string }>(response)).toEqual({ error: "invalid_live_session" });
  });

  it("rejects a job token used as a live session token", async () => {
    const db = memoryD1();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const jobToken = await signCompact(
      {
        typ: "job",
        kid: await expectedKidForJWK(TEST_TOKEN_SIGN_JWK),
        node: "testnode01",
        ip: "203.0.113.44",
        ip_binding: "relaxed",
        exp,
        nonce: "browsernoncebrowsernonce",
      },
      TEST_TOKEN_SIGN_JWK,
    );
    const response = await worker.fetch(
      new Request(`http://worker.test/api/jobs/live?node=testnode01&token=${encodeURIComponent(jobToken)}`, {
        headers: { upgrade: "websocket", "cf-connecting-ip": "203.0.113.44" },
      }),
      { ...liveSessionEnv, DB: db },
    );
    expect(response.status).toBe(401);
    expect(await json<{ error: string }>(response)).toEqual({ error: "invalid_live_session" });
  });

  it("rejects a valid live token bound to a different node with 403", async () => {
    const db = memoryD1();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const token = await signCompact(
      {
        typ: "live",
        kid: await expectedKidForJWK(TEST_TOKEN_SIGN_JWK),
        node: "edge02",
        ip: "203.0.113.44",
        ip_binding: "relaxed",
        exp,
        nonce: "livesessionnoncelivesess",
      },
      TEST_TOKEN_SIGN_JWK,
    );
    const response = await worker.fetch(
      new Request(`http://worker.test/api/jobs/live?node=testnode01&token=${encodeURIComponent(token)}`, {
        headers: { upgrade: "websocket", "cf-connecting-ip": "203.0.113.44" },
      }),
      { ...liveSessionEnv, DB: db },
    );
    expect(response.status).toBe(403);
    expect(await json<{ error: string }>(response)).toEqual({ error: "node_mismatch" });
  });

  it("rejects a live token whose client IP is outside the bound /24", async () => {
    const db = memoryD1();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const token = await signCompact(
      {
        typ: "live",
        kid: await expectedKidForJWK(TEST_TOKEN_SIGN_JWK),
        node: "testnode01",
        ip: "203.0.113.44",
        ip_binding: "relaxed",
        exp,
        nonce: "livesessionnoncelivesess",
      },
      TEST_TOKEN_SIGN_JWK,
    );
    const response = await worker.fetch(
      new Request(`http://worker.test/api/jobs/live?node=testnode01&token=${encodeURIComponent(token)}`, {
        headers: { upgrade: "websocket", "cf-connecting-ip": "198.51.100.7" },
      }),
      { ...liveSessionEnv, DB: db },
    );
    expect(response.status).toBe(401);
    expect(await json<{ error: string }>(response)).toEqual({ error: "invalid_live_session" });
  });

  it("authorizes a live connection with a valid session token", async () => {
    const db = memoryD1();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const token = await signCompact(
      {
        typ: "live",
        kid: await expectedKidForJWK(TEST_TOKEN_SIGN_JWK),
        node: "testnode01",
        ip: "203.0.113.44",
        ip_binding: "relaxed",
        exp,
        nonce: "livesessionnoncelivesess",
      },
      TEST_TOKEN_SIGN_JWK,
    );
    const request = new Request(`http://worker.test/api/jobs/live?node=testnode01&token=${encodeURIComponent(token)}`, {
      headers: { upgrade: "websocket", "cf-connecting-ip": "203.0.113.44" },
    });
    const authorized = await authorizeLiveJobSocket(request, { ...liveSessionEnv, DB: db });
    expect("response" in authorized && authorized.response).toBe(false);
    if ("response" in authorized) return;
    expect(authorized.node.internal_id).toBe("testnode01");
    expect(authorized.claims.typ).toBe("live");
    expect(authorized.claims.ip).toBe("203.0.113.44");
  });

  it("routes the upgrade request through worker.fetch to the auth gate", async () => {
    const db = memoryD1();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const token = await signCompact(
      {
        typ: "live",
        kid: await expectedKidForJWK(TEST_TOKEN_SIGN_JWK),
        node: "testnode01",
        ip: "203.0.113.44",
        ip_binding: "relaxed",
        exp,
        nonce: "livesessionnoncelivesess",
      },
      TEST_TOKEN_SIGN_JWK,
    );
    // Without the Workers runtime (no WebSocketPair) the handler fails after the
    // auth gate; with a token but no node it fails before. Compare both.
    const withToken = await worker.fetch(
      new Request(`http://worker.test/api/jobs/live?node=testnode01&token=${encodeURIComponent(token)}`, {
        headers: { upgrade: "websocket", "cf-connecting-ip": "203.0.113.44" },
      }),
      { ...liveSessionEnv, DB: db },
    );
    expect(withToken.status).toBe(500);

    const unknownNode = await worker.fetch(
      new Request(`http://worker.test/api/jobs/live?node=ghostnode&token=${encodeURIComponent(token)}`, {
        headers: { upgrade: "websocket", "cf-connecting-ip": "203.0.113.44" },
      }),
      { ...liveSessionEnv, DB: db },
    );
    expect(unknownNode.status).toBe(404);
  });
});

describe("live session verifier", () => {
  it("accepts a freshly issued token and rejects tampered or foreign types", async () => {
    const db = memoryD1();
    const kid = await expectedKidForJWK(TEST_TOKEN_SIGN_JWK);
    const exp = Math.floor(Date.now() / 1000) + 300;
    const token = await signCompact(
      { typ: "live", kid, node: "testnode01", ip: "203.0.113.44", ip_binding: "relaxed", exp, nonce: "livesessionnoncelivesess" },
      TEST_TOKEN_SIGN_JWK,
    );
    const ok = await verifyLiveSessionToken({ token, env: { DB: db } as Env, expectedNodeID: "testnode01", clientIP: "203.0.113.99" });
    expect(ok).toMatchObject({ claims: { typ: "live", node: "testnode01" } });

    const expired = await signCompact(
      { typ: "live", kid, node: "testnode01", ip: "203.0.113.44", ip_binding: "relaxed", exp: Math.floor(Date.now() / 1000) - 10, nonce: "livesessionnonceliveses0" },
      TEST_TOKEN_SIGN_JWK,
    );
    await expect(verifyLiveSessionToken({ token: expired, env: { DB: db } as Env, expectedNodeID: "testnode01", clientIP: "203.0.113.44" })).resolves.toMatchObject({ error: "bad_claims" });

    const job = await signCompact(
      { typ: "job", kid, node: "testnode01", ip: "203.0.113.44", ip_binding: "relaxed", exp, nonce: "livesessionnonceliveses1" },
      TEST_TOKEN_SIGN_JWK,
    );
    await expect(verifyLiveSessionToken({ token: job, env: { DB: db } as Env, expectedNodeID: "testnode01", clientIP: "203.0.113.44" })).resolves.toMatchObject({ error: "bad_claims" });
  });

  it("matches relaxed prefixes for IPv4 /24 and IPv6 /48 and rejects cross-family", async () => {
    expect(relaxedIPMatch("203.0.113.44", "203.0.113.99")).toBe(true);
    expect(relaxedIPMatch("203.0.113.44", "198.51.100.99")).toBe(false);
    expect(relaxedIPMatch("2001:db8::a", "2001:db8::f")).toBe(true);
    expect(relaxedIPMatch("2001:db8::a", "2001:db8:1::f")).toBe(false);
    expect(relaxedIPMatch("203.0.113.44", "2001:db8::a")).toBe(false);
    expect(relaxedIPMatch("", "203.0.113.44")).toBe(false);
  });
});

describe("agent-facing live job token", () => {
  it("signs ip_binding none so the agent (which only sees the worker egress IP) accepts it", async () => {
    // Regression: the agent validates ip_binding against its TCP peer address
    // (the Cloudflare egress IP for proxied jobs), so a relaxed binding to the
    // browser IP would make every live job fail with invalid_token. The
    // agent-facing token must stay unbound; browser identity is enforced by
    // the live session token upstream.
    const { signAgentJobClaims } = await import("../src/job-proxy");
    const { claims } = await signAgentJobClaims(
      { DB: memoryD1() } as Env,
      "testnode01",
      { tool: "ping" },
      "1.1.1.1",
      "ipv4",
      4,
      false,
    );
    expect(claims.ip_binding).toBe("none");
    expect(claims.ip).toBe("");
    expect(claims.typ).toBe("job");
    expect(claims.node).toBe("testnode01");
    expect(claims.target).toBe("1.1.1.1");
  });
});

describe("guarded socket helpers", () => {
  it("swallows send/close on an already-closed peer instead of throwing", async () => {
    const { safeSocketSend, safeSocketClose } = await import("../src/job-proxy");
    const closed = {
      send() {
        throw new Error("InvalidStateError: readyState is closing");
      },
      close() {
        throw new Error("InvalidStateError: already closed");
      },
    } as unknown as WebSocket;
    // Neither call may throw: these run from event handlers where a throw
    // becomes an unhandled rejection in the Workers runtime.
    expect(() => safeSocketSend(closed, "frame")).not.toThrow();
    expect(() => safeSocketClose(closed, 1000, "done")).not.toThrow();

    const sent: unknown[] = [];
    const open = {
      send(data: unknown) {
        sent.push(data);
      },
      close() {
        sent.push("closed");
      },
    } as unknown as WebSocket;
    safeSocketSend(open, "hello");
    safeSocketClose(open);
    expect(sent).toEqual(["hello", "closed"]);
  });
});

describe("live session audit", () => {
  it("records an issued live_session operation", async () => {
    const db = memoryD1();
    const response = await worker.fetch(liveSessionRequest("testnode01"), { ...liveSessionEnv, DB: db });
    expect(response.status).toBe(200);
    const audit = await db.prepare("SELECT operation_type FROM operation_audit").all<{ operation_type: string }>();
    const types = audit.results.map((row) => row.operation_type);
    expect(types).toContain("live_session");
    expect(types).not.toContain("job");
  });
});
