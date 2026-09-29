import { Env } from "./config";
import { databaseReady, dbInitRequiredResponse, inspectDatabase } from "./db-bootstrap";
import { clientIP, dbBindingMissing, json, methodNotAllowed, readJSON } from "./http";
import { workerLog } from "./log";
import { consumeRateLimit } from "./rate-limit";
import type { SqlDatabase } from "./runtime";

const ADMIN_COOKIE = "hlg_admin";
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const ONBOARDING_KEY = "on-boarding";
const ADMIN_LOGIN_LIMIT = 8;
const ADMIN_LOGIN_WINDOW_SECONDS = 300;
// Global per-IP bucket: caps password-guessing across all usernames from a
// single address, so rotating usernames does not sidestep the per-username
// limit. The bucket key uses the sentinel node "*".
const ADMIN_LOGIN_GLOBAL_LIMIT = 30;
const ADMIN_LOGIN_GLOBAL_WINDOW_SECONDS = 300;

export interface AdminUserPublic {
  id: string;
  username: string;
  role: string;
  has_totp: boolean;
  created_at: number;
  updated_at: number;
}

export interface AdminContext {
  id: string;
  username: string;
  role: string;
}

interface AdminUserRow {
  id: string;
  username: string;
  password_hash: string;
  totp_secret: string | null;
  role: string;
  created_at: number;
  updated_at: number;
}

interface AdminUserPublicRow {
  id: string;
  username: string;
  role: string;
  has_totp: number;
  created_at: number;
  updated_at: number;
}

interface AdminSessionRow {
  session_id: string;
  id: string;
  username: string;
  role: string;
  expires_at: number;
}

interface AdminAuthResult {
  user: AdminContext | null;
  response: Response | null;
}

export async function handleAdminSession(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const dbStatus = await inspectDatabase(env.DB);
  if (!databaseReady(dbStatus)) {
    return json({
      authenticated: false,
      onboarding_required: false,
      db_init_required: true,
      db_status: dbStatus,
      user: null,
    });
  }
  const onboardingRequired = await adminOnboardingRequired(env.DB);
  if (onboardingRequired) {
    return json({ authenticated: false, onboarding_required: true, db_init_required: false, db_status: dbStatus, user: null });
  }
  const auth = await adminFromSession(request, env.DB);
  return json({
    authenticated: Boolean(auth.user),
    onboarding_required: false,
    db_init_required: false,
    db_status: dbStatus,
    user: auth.user,
  });
}

export async function handleAdminSetup(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const dbStatus = await inspectDatabase(env.DB);
  if (!databaseReady(dbStatus)) return dbInitRequiredResponse(dbStatus);
  if (!(await adminOnboardingRequired(env.DB))) return json({ error: "already_initialized" }, { status: 409 });
  const body = await readJSON<{ username?: string; password?: string }>(request);
  const input = validateAdminUserInput(body.username, body.password);
  if ("error" in input) return json({ error: input.error }, { status: 400 });

  const now = nowSeconds();
  const row: AdminUserRow = {
    id: `adm_${crypto.randomUUID()}`,
    username: input.username,
    password_hash: await hashAdminPassword(input.password),
    totp_secret: null,
    role: "admin",
    created_at: now,
    updated_at: now,
  };
  // Onboarding race guard: the admin-count check happens inside the INSERT
  // itself, so two concurrent setups cannot both create the first admin.
  // (username is UNIQUE, but a same-name race must return 409, not a 500.)
  const inserted = await insertFirstAdminUser(env.DB, row);
  if (!inserted) return json({ error: "already_initialized" }, { status: 409 });
  await saveOnboardingComplete(env.DB, row.id, now);
  workerLog("admin.setup", { actor: row.username, target_id: row.id });
  return adminSessionResponse(request, env.DB, row, { onboarding_required: false });
}

export async function handleAdminLogin(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const dbStatus = await inspectDatabase(env.DB);
  if (!databaseReady(dbStatus)) return dbInitRequiredResponse(dbStatus);
  if (await adminOnboardingRequired(env.DB)) return json({ error: "onboarding_required", onboarding_required: true }, { status: 403 });
  const body = await readJSON<{ username?: string; password?: string; totp_code?: string }>(request);
  const username = normalizeUsername(body.username);
  const password = body.password || "";
  if (!username || !password) return json({ error: "unauthorized" }, { status: 401 });
  // Check the global per-IP bucket first: it is the cheaper DoS signal and a
  // single address hammering many usernames is blocked without per-user reads.
  const globalRateLimit = await consumeRateLimit({
    db: env.DB,
    action: "admin_login_global",
    node: "*",
    clientIP: clientIP(request),
    limit: ADMIN_LOGIN_GLOBAL_LIMIT,
    windowSeconds: ADMIN_LOGIN_GLOBAL_WINDOW_SECONDS,
  });
  if (!globalRateLimit.allowed) return json({ error: "rate_limited", reset_at: globalRateLimit.resetAt }, { status: 429 });
  const rateLimit = await consumeRateLimit({
    db: env.DB,
    action: "admin_login",
    node: username,
    clientIP: clientIP(request),
    limit: ADMIN_LOGIN_LIMIT,
    windowSeconds: ADMIN_LOGIN_WINDOW_SECONDS,
  });
  if (!rateLimit.allowed) return json({ error: "rate_limited", reset_at: rateLimit.resetAt }, { status: 429 });
  const row = await findAdminUser(env.DB, username);
  if (!row) {
    // Burn the same PBKDF2 cost as a real verify so response timing cannot
    // enumerate usernames.
    await verifyAdminPassword(password, DUMMY_PASSWORD_HASH);
    return json({ error: "unauthorized" }, { status: 401 });
  }
  if (!(await verifyAdminPassword(password, row.password_hash))) return json({ error: "unauthorized" }, { status: 401 });
  if (row.totp_secret) {
    if (!body.totp_code) return json({ error: "totp_required" }, { status: 401 });
    const totpStep = await matchingTOTPStep(row.totp_secret, body.totp_code);
    if (totpStep === null) return json({ error: "invalid_totp" }, { status: 401 });
    if (!(await consumeTOTPCode(env.DB, row.id, totpStep))) return json({ error: "totp_replay" }, { status: 401 });
  }
  await cleanupExpiredAdminSessions(env.DB);
  workerLog("admin.login", { actor: row.username, target_id: row.id });
  return adminSessionResponse(request, env.DB, row, { onboarding_required: false });
}

export async function handleAdminLogout(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const token = adminCookieToken(request);
  if (token) await deleteAdminSessionByToken(env.DB, token);
  return json(
    { ok: true },
    {
      headers: {
        "set-cookie": expiredAdminCookie(request),
      },
    },
  );
}

export async function handleAdminUsers(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdminUser(request, env);
  if (auth.response) return auth.response;
  if (!env.DB) return dbBindingMissing();

  if (request.method === "GET") return json({ users: await listAdminUsers(env.DB) });
  if (request.method === "POST") {
    const body = await readJSON<{ username?: string; password?: string }>(request);
    const input = validateAdminUserInput(body.username, body.password);
    if ("error" in input) return json({ error: input.error }, { status: 400 });
    if (await findAdminUser(env.DB, input.username)) return json({ error: "admin_user_exists" }, { status: 409 });
    const now = nowSeconds();
    const row: AdminUserRow = {
      id: `adm_${crypto.randomUUID()}`,
      username: input.username,
      password_hash: await hashAdminPassword(input.password),
      totp_secret: null,
      role: "admin",
      created_at: now,
      updated_at: now,
    };
    await insertAdminUser(env.DB, row);
    workerLog("admin.user.create", { actor: auth.user?.username, target_id: row.id });
    return json({ user: publicAdminUser(row) });
  }
  if (request.method === "DELETE") {
    const body = await readJSON<{ username?: string; user_id?: string }>(request);
    const target = await findAdminTarget(env.DB, body);
    if (!target) return json({ error: "admin_user_not_found" }, { status: 404 });
    // Last-admin guard lives inside the DELETE: the count is evaluated at
    // delete time, so two concurrent deletions cannot both remove their user.
    const deleted = await env.DB.prepare("DELETE FROM admin_users WHERE id = ? AND (SELECT COUNT(*) FROM admin_users) > 1")
      .bind(target.id)
      .run();
    if ((deleted.meta?.changes ?? 0) === 0) return json({ error: "last_admin_required" }, { status: 400 });
    await env.DB.batch([env.DB.prepare("DELETE FROM admin_sessions WHERE user_id = ?").bind(target.id)]);
    workerLog("admin.user.delete", { actor: auth.user?.username, target_id: target.id });
    return json({ ok: true, user: publicAdminUser(target) });
  }
  return methodNotAllowed();
}

export async function handleAdminUserPassword(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdminUser(request, env);
  if (auth.response) return auth.response;
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const body = await readJSON<{ username?: string; user_id?: string; password?: string }>(request);
  const target = await findAdminTarget(env.DB, body);
  if (!target) return json({ error: "admin_user_not_found" }, { status: 404 });
  if (!body.password || body.password.length < 8) return json({ error: "admin_password_required" }, { status: 400 });
  const now = nowSeconds();
  // Password rotation and session revocation must be atomic: a client that
  // re-authenticates between the two statements would keep a valid session.
  await env.DB.batch([
    env.DB.prepare("UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?").bind(
      await hashAdminPassword(body.password),
      now,
      target.id,
    ),
    env.DB.prepare("DELETE FROM admin_sessions WHERE user_id = ?").bind(target.id),
  ]);
  const updated = await findAdminUserByID(env.DB, target.id);
  workerLog("admin.user.password", { actor: auth.user?.username, target_id: target.id });
  return json({ user: publicAdminUser(updated ?? { ...target, updated_at: now }) });
}

export async function handleAdminUserTotpSetup(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdminUser(request, env);
  if (auth.response) return auth.response;
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const body = await readJSON<{ username?: string; user_id?: string; current_password?: string; totp_code?: string }>(request);
  if (!(await verifyAdminReauthentication(env.DB, auth.user?.username, body.current_password, body.totp_code))) {
    return json({ error: "admin_reauthentication_required" }, { status: 401 });
  }
  const target = await findAdminTarget(env.DB, body);
  if (!target) return json({ error: "admin_user_not_found" }, { status: 404 });
  const secret = randomBase32Secret();
  const now = nowSeconds();
  await env.DB.prepare("UPDATE admin_users SET totp_secret = ?, updated_at = ? WHERE id = ?").bind(secret, now, target.id).run();
  const updated = await findAdminUserByID(env.DB, target.id);
  workerLog("admin.user.totp.setup", { actor: auth.user?.username, target_id: target.id });
  return json({
    secret,
    otpauth_url: totpURL(target.username, secret),
    user: publicAdminUser(updated ?? { ...target, totp_secret: secret, updated_at: now }),
  });
}

export async function handleAdminUserTotpReset(request: Request, env: Env): Promise<Response> {
  const auth = await requireAdminUser(request, env);
  if (auth.response) return auth.response;
  if (request.method !== "POST") return methodNotAllowed();
  if (!env.DB) return dbBindingMissing();
  const body = await readJSON<{ username?: string; user_id?: string; current_password?: string; totp_code?: string }>(request);
  if (!(await verifyAdminReauthentication(env.DB, auth.user?.username, body.current_password, body.totp_code))) {
    return json({ error: "admin_reauthentication_required" }, { status: 401 });
  }
  const target = await findAdminTarget(env.DB, body);
  if (!target) return json({ error: "admin_user_not_found" }, { status: 404 });
  const now = nowSeconds();
  await env.DB.prepare("UPDATE admin_users SET totp_secret = NULL, updated_at = ? WHERE id = ?").bind(now, target.id).run();
  const updated = await findAdminUserByID(env.DB, target.id);
  workerLog("admin.user.totp.reset", { actor: auth.user?.username, target_id: target.id });
  return json({ user: publicAdminUser(updated ?? { ...target, totp_secret: null, updated_at: now }) });
}

async function verifyAdminReauthentication(
  db: SqlDatabase,
  username: string | undefined,
  password: string | undefined,
  totpCode: string | undefined,
): Promise<boolean> {
  if (!username || !password) return false;
  const actor = await findAdminUser(db, username);
  if (!actor || !(await verifyAdminPassword(password, actor.password_hash))) return false;
  if (!actor.totp_secret) return true;
  if (!totpCode) return false;
  const step = await matchingTOTPStep(actor.totp_secret, totpCode);
  // This is proof of recent possession, not a new login. The current code may
  // already have been claimed during login, so don't reject a legitimate
  // credential confirmation as a replay.
  return step !== null;
}

export async function requireAdmin(request: Request, env: Env): Promise<Response | null> {
  return (await requireAdminUser(request, env)).response;
}

/**
 * Raw admin-session check that works on a database that is not yet "ready"
 * (e.g. the destructive /api/admin/db/init reset path). Unlike requireAdmin,
 * it never consults the schema/onboarding state and returns just the context.
 */
export async function adminSessionFromRequest(request: Request, db: SqlDatabase): Promise<AdminContext | null> {
  return (await adminFromSession(request, db)).user;
}

export async function requireAdminUser(request: Request, env: Env): Promise<AdminAuthResult> {
  if (isUnsafeMethod(request.method)) {
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(request.url).origin) {
      return { user: null, response: json({ error: "cross_origin_admin_request" }, { status: 403 }) };
    }
  }
  if (!env.DB) {
    workerLog("config.missing", { setting: "D1", surface: "admin" });
    return { user: null, response: dbBindingMissing() };
  }
  const dbStatus = await inspectDatabase(env.DB);
  if (!databaseReady(dbStatus)) {
    return { user: null, response: dbInitRequiredResponse(dbStatus) };
  }
  if (await adminOnboardingRequired(env.DB)) {
    return {
      user: null,
      response: json({ error: "onboarding_required", onboarding_required: true }, { status: 403 }),
    };
  }
  return adminFromSession(request, env.DB);
}

function isUnsafeMethod(method: string): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

export async function adminOnboardingRequired(db: SqlDatabase): Promise<boolean> {
  const count = await adminUserCount(db);
  if (count === 0) return true;
  const row = await db.prepare("SELECT value_json FROM project_settings WHERE key = ?").bind(ONBOARDING_KEY).first<{ value_json: string }>();
  if (!row?.value_json) return false;
  try {
    const setting = JSON.parse(row.value_json) as { complete?: boolean; required?: boolean; blocked?: boolean };
    if (setting.required === true || setting.blocked === true) return true;
    if (setting.complete === true) return false;
  } catch {
    return false;
  }
  return false;
}

async function adminUserCount(db: SqlDatabase): Promise<number> {
  const row = await db.prepare("SELECT COUNT(*) AS count FROM admin_users").first<{ count: number }>();
  return Number(row?.count ?? 0);
}

async function saveOnboardingComplete(db: SqlDatabase, firstAdminID: string, now: number): Promise<void> {
  await db.prepare(
    `INSERT INTO project_settings (key, value_json, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
  )
    .bind(ONBOARDING_KEY, JSON.stringify({ complete: true, completed_at: now, first_admin_id: firstAdminID }), now)
    .run();
}

async function adminFromSession(request: Request, db: SqlDatabase): Promise<AdminAuthResult> {
  const token = adminCookieToken(request);
  if (!token) return { user: null, response: json({ error: "unauthorized" }, { status: 401 }) };
  const tokenHash = await hashSessionToken(token);
  const now = nowSeconds();
  const row = await db
    .prepare(
      `SELECT s.id AS session_id, u.id AS id, u.username AS username, u.role AS role, s.expires_at AS expires_at
       FROM admin_sessions s
       JOIN admin_users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ?`,
    )
    .bind(tokenHash, now)
    .first<AdminSessionRow>();
  if (!row) return { user: null, response: json({ error: "unauthorized" }, { status: 401 }) };
  return { user: { id: row.id, username: row.username, role: row.role }, response: null };
}

async function adminSessionResponse(request: Request, db: SqlDatabase, user: AdminUserRow, extra: Record<string, unknown>): Promise<Response> {
  const now = nowSeconds();
  const token = `lgs_${base64URL(crypto.getRandomValues(new Uint8Array(32)))}`;
  const expiresAt = now + SESSION_TTL_SECONDS;
  await db.prepare("INSERT INTO admin_sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(`sess_${crypto.randomUUID()}`, user.id, await hashSessionToken(token), expiresAt, now)
    .run();
  return json(
    {
      authenticated: true,
      user: publicAdminUser(user),
      expires_at: expiresAt,
      ...extra,
    },
    {
      headers: {
        "set-cookie": adminCookie(request, token, expiresAt),
      },
    },
  );
}

async function insertAdminUser(db: SqlDatabase, row: AdminUserRow): Promise<void> {
  await db.prepare("INSERT INTO admin_users (id, username, password_hash, totp_secret, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(row.id, row.username, row.password_hash, row.totp_secret, row.role, row.created_at, row.updated_at)
    .run();
}

/**
 * Insert the first admin only while no admin exists yet. The guard lives in
 * the SQL itself so two concurrent setups cannot both succeed.
 */
async function insertFirstAdminUser(db: SqlDatabase, row: AdminUserRow): Promise<boolean> {
  const result = await db
    .prepare(
      `INSERT INTO admin_users (id, username, password_hash, totp_secret, role, created_at, updated_at)
       SELECT ?, ?, ?, ?, ?, ?, ?
       WHERE (SELECT COUNT(*) FROM admin_users) = 0`,
    )
    .bind(row.id, row.username, row.password_hash, row.totp_secret, row.role, row.created_at, row.updated_at)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

async function listAdminUsers(db: SqlDatabase): Promise<AdminUserPublic[]> {
  const rows = await db
    .prepare(
      `SELECT id, username, role, CASE WHEN totp_secret IS NULL THEN 0 ELSE 1 END AS has_totp, created_at, updated_at
       FROM admin_users
       ORDER BY created_at ASC, username ASC`,
    )
    .all<AdminUserPublicRow>();
  return (rows.results ?? []).map((row) => ({
    id: row.id,
    username: row.username,
    role: row.role,
    has_totp: row.has_totp === 1,
    created_at: row.created_at,
    updated_at: row.updated_at,
  }));
}

async function findAdminTarget(db: SqlDatabase, input: { username?: string; user_id?: string }): Promise<AdminUserRow | null> {
  if (input.user_id) return findAdminUserByID(db, input.user_id);
  const username = normalizeUsername(input.username);
  if (!username) return null;
  return findAdminUser(db, username);
}

async function findAdminUser(db: SqlDatabase, username: string): Promise<AdminUserRow | null> {
  return db
    .prepare("SELECT id, username, password_hash, totp_secret, role, created_at, updated_at FROM admin_users WHERE username = ?")
    .bind(username)
    .first<AdminUserRow>();
}

async function findAdminUserByID(db: SqlDatabase, id: string): Promise<AdminUserRow | null> {
  return db
    .prepare("SELECT id, username, password_hash, totp_secret, role, created_at, updated_at FROM admin_users WHERE id = ?")
    .bind(id)
    .first<AdminUserRow>();
}

function publicAdminUser(row: AdminUserRow): AdminUserPublic {
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    has_totp: Boolean(row.totp_secret),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function validateAdminUserInput(usernameRaw?: string, password?: string): { username: string; password: string } | { error: string } {
  const username = normalizeUsername(usernameRaw);
  if (!username) return { error: "admin_username_required" };
  if (!password || password.length < 8) return { error: "admin_password_required" };
  return { username, password };
}

function normalizeUsername(username?: string): string {
  return (username || "").trim().toLowerCase();
}

function adminCookieToken(request: Request): string | null {
  const cookies = request.headers.get("cookie") || "";
  for (const part of cookies.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (rawName === ADMIN_COOKIE) return rawValue.join("=") || null;
  }
  return null;
}

async function deleteAdminSessionByToken(db: SqlDatabase, token: string): Promise<void> {
  await db.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(await hashSessionToken(token)).run();
}

async function cleanupExpiredAdminSessions(db: SqlDatabase): Promise<void> {
  await db.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").bind(nowSeconds()).run();
}

function adminCookie(request: Request, token: string, expiresAt: number): string {
  const maxAge = Math.max(0, expiresAt - nowSeconds());
  return `${ADMIN_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureCookieSuffix(request)}`;
}

function expiredAdminCookie(request: Request): string {
  return `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureCookieSuffix(request)}`;
}

function secureCookieSuffix(request: Request): string {
  return new URL(request.url).protocol === "https:" ? "; Secure" : "";
}

async function hashSessionToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return base64URL(new Uint8Array(digest));
}

export async function hashAdminPassword(password: string, iterations = 100_000): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, iterations);
  return `pbkdf2-sha256$${iterations}$${base64URL(salt)}$${base64URL(hash)}`;
}

async function verifyAdminPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, iterationsRaw, saltRaw, hashRaw] = stored.split("$");
  if (scheme !== "pbkdf2-sha256") return false;
  const iterations = Number(iterationsRaw);
  if (!Number.isFinite(iterations) || iterations < 100_000) return false;
  const expected = base64URLToBytes(hashRaw);
  const actual = await pbkdf2(password, base64URLToBytes(saltRaw), iterations);
  return bytesEqual(actual, expected);
}

// Fixed hash of a random throwaway password. Logging in as an unknown username
// runs the same PBKDF2 cost against it so the 401 timing does not reveal
// whether the username exists.
const DUMMY_PASSWORD_HASH = "pbkdf2-sha256$100000$VpAatkpnsce0mThppmqf7Q$AxuCh-xvyR1j7RtPHuf-DEzStTv6CM2usgVcHzLg9hE";

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const saltBuffer = salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength) as ArrayBuffer;
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBuffer, iterations }, key, 256);
  return new Uint8Array(bits);
}

async function matchingTOTPStep(secret: string, code: string): Promise<number | null> {
  const normalized = code.trim().replace(/\s/g, "");
  if (!/^\d{6}$/.test(normalized)) return null;
  const step = Math.floor(Date.now() / 1000 / 30);
  // Constant-time compare so a string comparison cannot leak the expected code.
  for (const offset of [-1, 0, 1]) {
    const candidate = step + offset;
    if (constantTimeEqual(await totpCode(secret, candidate), normalized)) return candidate;
  }
  return null;
}

export async function consumeTOTPCode(db: SqlDatabase, userID: string, step: number): Promise<boolean> {
  const now = nowSeconds();
  await db.prepare("DELETE FROM used_totp_codes WHERE expires_at <= ?").bind(now).run();
  const result = await db
    .prepare(
      `INSERT INTO used_totp_codes (user_id, step, used_at, expires_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id, step) DO NOTHING`,
    )
    .bind(userID, step, now, now + 120)
    .run();
  // Strict: only exactly one winning insert counts. meta.changes === 1 means
  // this request claimed the (user_id, step) slot; anything else is a replay.
  return result.meta?.changes === 1;
}

export async function totpCode(secret: string, step = Math.floor(Date.now() / 1000 / 30)): Promise<string> {
  const secretBytes = base32ToBytes(secret);
  const secretBuffer = secretBytes.buffer.slice(secretBytes.byteOffset, secretBytes.byteOffset + secretBytes.byteLength) as ArrayBuffer;
  const key = await crypto.subtle.importKey("raw", secretBuffer, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new ArrayBuffer(8);
  const view = new DataView(counter);
  view.setUint32(4, step);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

/** Character-wise XOR compare; runtime does not short-circuit on a mismatch. */
function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index++) {
    diff |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return diff === 0;
}

function randomBase32Secret(): string {
  return base32(crypto.getRandomValues(new Uint8Array(20)));
}

function totpURL(username: string, secret: string): string {
  const issuer = "HLG";
  const label = `${issuer}:${username}`;
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32ToBytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("invalid_totp_secret");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index++) diff |= a[index] ^ b[index];
  return diff === 0;
}

function base64URL(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64URLToBytes(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
