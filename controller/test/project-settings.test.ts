import { describe, expect, it } from "vitest";
import { getPublicBrandingConfig, listProjectSettingStatus, setProjectSetting } from "../src/project-settings";

interface FakeSettingsD1 extends D1Database {
  selectAllCalls: number;
}

/**
 * D1 fake whose project_settings rows are returned verbatim, including rows
 * with value_json that does not parse — the corrupt-row scenario.
 */
function fakeSettingsD1(rows: Array<{ key: string; value_json: string }>): FakeSettingsD1 {
  let selectAllCalls = 0;
  return {
    get selectAllCalls() {
      return selectAllCalls;
    },
    prepare(sql: string) {
      return {
        bind(..._values: unknown[]) {
          return {};
        },
        async all<T>() {
          selectAllCalls += 1;
          if (sql.includes("FROM project_settings")) {
            return { results: rows as unknown as T[], success: true, meta: d1Meta() } as D1Result<T>;
          }
          return { results: [], success: true, meta: d1Meta() } as D1Result<T>;
        },
        async first<T>(): Promise<T | null> {
          return null as T | null;
        },
      };
    },
  } as unknown as FakeSettingsD1;
}

function d1Meta(): D1Meta & Record<string, unknown> {
  return { duration: 0, size_after: 0, rows_read: 0, rows_written: 0, last_row_id: 0, changed_db: false, changes: 0 };
}

describe("project settings reads", () => {
  it("keeps valid rows when one row holds invalid JSON", async () => {
    const db = fakeSettingsD1([
      { key: "PUBLIC_SITE_NAME", value_json: "\"Broken Site\"" },
      { key: "PUBLIC_THEME", value_json: "{not json" },
      { key: "PUBLIC_PAGE_TITLE", value_json: "\"Custom Title\"" },
    ]);
    const branding = await getPublicBrandingConfig(db);
    expect(branding.site_name).toBe("Broken Site");
    expect(branding.page_title).toBe("Custom Title");
    // The corrupt row falls back to its default value.
    expect(branding.theme).toBe("homura");
  });

  it("computes branding statuses from a single batched D1 read", async () => {
    const db = fakeSettingsD1([{ key: "PUBLIC_SITE_NAME", value_json: "\"Batched\"" }]);
    await getPublicBrandingConfig(db);
    expect(db.selectAllCalls).toBe(1);
  });

  it("derives configured/source flags from the batched map for listProjectSettingStatus", async () => {
    const db = fakeSettingsD1([{ key: "PUBLIC_SITE_NAME", value_json: "\"Custom\"" }]);
    const statuses = await listProjectSettingStatus(db);
    const siteName = statuses.find((status) => status.key === "PUBLIC_SITE_NAME");
    const theme = statuses.find((status) => status.key === "PUBLIC_THEME");
    expect(siteName).toMatchObject({ value: "Custom", configured: true, source: "d1" });
    expect(theme).toMatchObject({ value: "homura", configured: false, source: "default" });
  });
});

describe("branding image URL validation at save time", () => {
  function fakeWriteD1(): D1Database {
    const written: Array<{ key: string; value: string }> = [];
    return {
      prepare(sql: string) {
        return {
          bind(key: string, value: string, _at: number) {
            if (sql.includes("INSERT INTO project_settings")) written.push({ key, value });
            return {
              async run() {
                return { success: true, meta: { changes: 1 } };
              },
            };
          },
        };
      },
      // eslint-disable-next-line
      get written() {
        return written;
      },
    } as unknown as D1Database & { written: Array<{ key: string; value: string }> };
  }

  it("rejects non-https/relative schemes for favicon and OG/Twitter image URLs", async () => {
    const db = fakeWriteD1();
    for (const key of ["PUBLIC_FAVICON_URL", "PUBLIC_OG_IMAGE_URL", "PUBLIC_TWITTER_IMAGE_URL"] as const) {
      await expect(setProjectSetting(db, key, "javascript:alert(1)")).rejects.toThrow("invalid_setting_value");
      await expect(setProjectSetting(db, key, "http://insecure.example.test/a.png")).rejects.toThrow("invalid_setting_value");
      await expect(setProjectSetting(db, key, "data:image/png;base64,AAAA")).rejects.toThrow("invalid_setting_value");
      // Protocol-relative URLs resolve against the page scheme and point
      // off-site; they must not pass as "relative".
      await expect(setProjectSetting(db, key, "//evil.example.test/a.png")).rejects.toThrow("invalid_setting_value");
    }
  });

  it("accepts https and site-relative image URLs", async () => {
    const db = fakeWriteD1();
    await setProjectSetting(db, "PUBLIC_FAVICON_URL", "/favicon.ico");
    await setProjectSetting(db, "PUBLIC_OG_IMAGE_URL", "https://cdn.example.test/og.png");
    await setProjectSetting(db, "PUBLIC_TWITTER_IMAGE_URL", "/twitter.png");
  });
});