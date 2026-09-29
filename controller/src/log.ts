import { getBooleanProjectSetting } from "./project-settings";
import type { SqlDatabase } from "./runtime";

type LogFields = Record<string, unknown>;

/** Severity of a structured worker log line. */
export type LogLevel = "debug" | "info" | "warn" | "error";

/** How long the debug-enabled flag is cached per isolate before re-reading D1. */
const DEBUG_FLAG_TTL_MS = 30_000;

// Time-based cache so per-request workerDebug calls don't each hit project_settings.
let debugCache: { value: boolean; until: number } | null = null;

export function workerDebugEnabled(db: SqlDatabase | undefined): Promise<boolean> {
  return getBooleanProjectSetting(db, "LG_WORKER_DEBUG_LOGS");
}

export async function workerDebugEnabledCached(db: SqlDatabase | undefined): Promise<boolean> {
  const now = Date.now();
  if (debugCache && debugCache.until > now) return debugCache.value;
  let value: boolean;
  try {
    value = await workerDebugEnabled(db);
  } catch {
    value = false;
  }
  debugCache = { value, until: now + DEBUG_FLAG_TTL_MS };
  return value;
}

/** Test hook: drop the cached debug flag. */
export function resetWorkerDebugCache(): void {
  debugCache = null;
}

export function workerLogPayload(event: string, fields: LogFields = {}): LogFields {
  const payload: LogFields = { app: "hlg", event };
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    if (key === "url" && typeof value === "string") {
      payload.path = new URL(value).pathname;
      continue;
    }
    payload[key] = value;
  }
  return payload;
}

/**
 * Emit one structured line at the given level. Levels map onto the console
 * methods Cloudflare Workers exposes (console.debug/info/warn/error), which
 * the dashboard and `wrangler tail` surface and filter by.
 *
 * Callers pass a `level` only when it is always emitted (info/warn/error);
 * debug is emitted through `workerDebug` so it can be gated on the
 * LG_WORKER_DEBUG_LOGS setting.
 */
function emit(level: LogLevel, event: string, fields: LogFields = {}): void {
  const line = JSON.stringify(workerLogPayload(event, fields));
  switch (level) {
    case "debug":
      console.debug(line);
      return;
    case "warn":
      console.warn(line);
      return;
    case "error":
      console.error(line);
      return;
    default:
      console.log(line);
  }
}

/** Info-level structured log (the default). */
export function workerLog(event: string, fields: LogFields = {}): void {
  emit("info", event, fields);
}

/** Warn-level structured log. */
export function workerWarn(event: string, fields: LogFields = {}): void {
  emit("warn", event, fields);
}

/** Error-level structured log. */
export function workerError(event: string, fields: LogFields = {}): void {
  emit("error", event, fields);
}

/**
 * Debug-level structured log, emitted only when LG_WORKER_DEBUG_LOGS is on.
 * The flag is read through a short-lived cache so per-request calls don't each
 * hit D1.
 */
export async function workerDebug(db: SqlDatabase | undefined, event: string, fields: LogFields = {}): Promise<void> {
  if (!(await workerDebugEnabledCached(db))) return;
  emit("debug", event, fields);
}
