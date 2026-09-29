import { ServiceConfigError } from "./config";
import type { SqlDatabase } from "./runtime";

export const RUNTIME_SECRET_DEFINITIONS = [
  { key: "LG_TOKEN_SIGN_JWK", label: "Token Signing JWK", can_generate: true, format: "ed25519_jwk" },
  { key: "LG_CONFIG_SIGN_JWK", label: "Config Signing JWK", can_generate: true, format: "ed25519_jwk" },
  { key: "LG_ADMIN_SIGN_JWK", label: "Admin Signing JWK", can_generate: true, format: "ed25519_jwk" },
  { key: "ACME_ACCOUNT_JWK", label: "ACME Account JWK", can_generate: true, format: "p256_jwk" },
  { key: "ACME_EAB_HMAC_KEY", label: "ACME EAB HMAC Key", can_generate: false, format: "string" },
  { key: "CLOUDFLARE_DNSUPDATE_API_KEY", label: "Cloudflare DNS Token", can_generate: false, format: "string" },
  { key: "TURNSTILE_SECRET_KEY", label: "Turnstile Secret Key", can_generate: false, format: "string" },
] as const satisfies ReadonlyArray<{
  key: string;
  label: string;
  can_generate: boolean;
  format: "ed25519_jwk" | "p256_jwk" | "string";
}>;

export const RUNTIME_SECRET_KEYS = RUNTIME_SECRET_DEFINITIONS.map((definition) => definition.key);
export type RuntimeSecretKey = (typeof RUNTIME_SECRET_DEFINITIONS)[number]["key"];
export type RuntimeSecretSource = "d1" | "none";

export interface RuntimeSecretStatus {
  key: RuntimeSecretKey;
  label: string;
  configured: boolean;
  source: RuntimeSecretSource;
  can_generate: boolean;
}

export interface RuntimeSecretReadResult {
  value?: string;
  /** True when the D1 query itself failed (infra error, distinct from "row not found"). */
  dbError?: boolean;
}

export async function readRuntimeSecretStrict(db: SqlDatabase | undefined, key: RuntimeSecretKey): Promise<RuntimeSecretReadResult> {
  if (!db) return {};
  try {
    const row = await db.prepare("SELECT value FROM runtime_secrets WHERE key = ?").bind(key).first<{ value: string }>();
    return { value: row?.value?.trim() || undefined };
  } catch {
    return { dbError: true };
  }
}

export async function getRuntimeSecret(db: SqlDatabase | undefined, key: RuntimeSecretKey): Promise<string | undefined> {
  return (await readRuntimeSecretStrict(db, key)).value;
}

export async function getRuntimeJWK(db: SqlDatabase | undefined, key: Extract<RuntimeSecretKey, "LG_TOKEN_SIGN_JWK" | "LG_CONFIG_SIGN_JWK" | "LG_ADMIN_SIGN_JWK">): Promise<JsonWebKey> {
  const value = await getRuntimeSecret(db, key);
  if (!value) throw new ServiceConfigError(key);
  return parseEd25519PrivateJWK(value, key);
}

export async function listRuntimeSecretStatus(db: SqlDatabase | undefined): Promise<RuntimeSecretStatus[]> {
  let d1Keys = new Set<string>();
  if (db) {
    try {
      const rows = await db.prepare("SELECT key FROM runtime_secrets").all<{ key: RuntimeSecretKey }>();
      d1Keys = new Set(rows.results.map((row) => row.key));
    } catch {
      d1Keys = new Set();
    }
  }
  return RUNTIME_SECRET_DEFINITIONS.map((definition) => runtimeSecretStatusFromSource(definition.key, d1Keys.has(definition.key)));
}

export async function runtimeSecretStatus(db: SqlDatabase | undefined, key: RuntimeSecretKey): Promise<RuntimeSecretStatus> {
  let hasD1Value = false;
  if (db) {
    try {
      const row = await db.prepare("SELECT key FROM runtime_secrets WHERE key = ?").bind(key).first<{ key: string }>();
      hasD1Value = Boolean(row?.key);
    } catch {
      hasD1Value = false;
    }
  }
  return runtimeSecretStatusFromSource(key, hasD1Value);
}

export async function setRuntimeSecret(db: SqlDatabase, key: RuntimeSecretKey, value: string): Promise<void> {
  const normalized = validateRuntimeSecretValue(key, value);
  await db
    .prepare(
      `INSERT INTO runtime_secrets (key, value, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
    .bind(key, normalized, Math.floor(Date.now() / 1000))
    .run();
}

export async function generateRuntimeSecretValue(key: RuntimeSecretKey): Promise<string> {
  const definition = definitionForKey(key);
  if (!definition?.can_generate) throw new Error("secret_not_generatable");
  if (definition.format === "p256_jwk") return generateP256PrivateJWK();
  if (definition.format !== "ed25519_jwk") throw new Error("secret_not_generatable");
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"]);
  const privateKey = "privateKey" in keyPair ? keyPair.privateKey : keyPair;
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return JSON.stringify({
    crv: "Ed25519",
    d: jwk.d,
    x: jwk.x,
    kty: "OKP",
  });
}

export function validateRuntimeSecretValue(key: RuntimeSecretKey, value: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error("secret_value_required");
  const definition = definitionForKey(key);
  if (definition?.format === "ed25519_jwk") parseEd25519PrivateJWK(normalized, key);
  if (definition?.format === "p256_jwk") parseP256PrivateJWK(normalized, key);
  return normalized;
}

export function isRuntimeSecretKey(value: string): value is RuntimeSecretKey {
  return (RUNTIME_SECRET_KEYS as readonly string[]).includes(value);
}

function runtimeSecretStatusFromSource(key: RuntimeSecretKey, hasD1Value: boolean): RuntimeSecretStatus {
  const definition = definitionForKey(key);
  return {
    key,
    label: definition?.label ?? key,
    configured: hasD1Value,
    source: hasD1Value ? "d1" : "none",
    can_generate: definition?.can_generate === true,
  };
}

function definitionForKey(key: RuntimeSecretKey) {
  return RUNTIME_SECRET_DEFINITIONS.find((definition) => definition.key === key);
}

function parseEd25519PrivateJWK(value: string, setting: string): JsonWebKey {
  try {
    const jwk = JSON.parse(value) as JsonWebKey;
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.d !== "string" || typeof jwk.x !== "string") {
      throw new Error("invalid_jwk");
    }
    return jwk;
  } catch {
    throw new ServiceConfigError(setting);
  }
}

async function generateP256PrivateJWK(): Promise<string> {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const privateKey = "privateKey" in keyPair ? keyPair.privateKey : keyPair;
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return JSON.stringify({
    crv: "P-256",
    d: jwk.d,
    kty: "EC",
    x: jwk.x,
    y: jwk.y,
  });
}

function parseP256PrivateJWK(value: string, setting: string): JsonWebKey {
  try {
    const jwk = JSON.parse(value) as JsonWebKey;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.d !== "string" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
      throw new Error("invalid_jwk");
    }
    return jwk;
  } catch {
    throw new ServiceConfigError(setting);
  }
}
