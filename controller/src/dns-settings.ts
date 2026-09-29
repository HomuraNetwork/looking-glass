import type { SqlDatabase } from "./runtime";
export interface DNSSettings {
  base: string;
  v4_base: string;
  v6_base: string;
  single_base: boolean;
}

const DNS_SETTINGS_KEY = "dns";

export async function getDNSSettings(db: SqlDatabase | undefined): Promise<DNSSettings | null> {
  if (!db) return null;
  const row = await db.prepare("SELECT value_json FROM project_settings WHERE key = ?").bind(DNS_SETTINGS_KEY).first<{ value_json: string }>();
  if (!row?.value_json) return null;
  try {
    return normalizeDNSSettings(JSON.parse(row.value_json) as DNSSettings);
  } catch {
    // A corrupt stored value must not take down every route that needs DNS
    // settings; fall back to the neutral defaults instead of throwing.
    return normalizeDNSSettings({ base: "", v4_base: "", v6_base: "", single_base: false });
  }
}

export async function saveDNSSettings(db: SqlDatabase, settings: DNSSettings): Promise<DNSSettings> {
  const normalized = normalizeDNSSettings(settings);
  await db
    .prepare(
      `INSERT INTO project_settings (key, value_json, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
    )
    .bind(DNS_SETTINGS_KEY, JSON.stringify(normalized), Math.floor(Date.now() / 1000))
    .run();
  return normalized;
}

export function normalizeDNSSettings(settings: DNSSettings): DNSSettings {
  return {
    base: settings.base.trim(),
    v4_base: settings.v4_base.trim(),
    v6_base: settings.v6_base.trim(),
    single_base: settings.single_base === true,
  };
}
