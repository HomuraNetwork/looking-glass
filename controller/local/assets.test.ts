import { describe, expect, it, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileAssetServer } from "./assets";

/** Mirrors the Cloudflare assets behavior: SPA fallback for navigations. */
describe("local file asset server", () => {
  const root = mkdtempSync(join(tmpdir(), "lg-assets-"));
  mkdirSync(join(root, "assets"), { recursive: true });
  writeFileSync(join(root, "index.html"), "<html><title>shell</title></html>");
  writeFileSync(join(root, "assets", "app-abc123.js"), "console.log(1)");

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  const get = (path: string) => fileAssetServer(root).fetch(new Request(`http://localhost${path}`));

  it("serves index.html for the root", async () => {
    const response = await get("/");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
  });

  it("falls back to the SPA shell for extensionless paths", async () => {
    // On Cloudflare this is not_found_handling: single-page-application; the
    // local runtime must match it or /admin 404s behind the Node entry.
    for (const path of ["/admin", "/admin/", "/nodes/test"]) {
      const response = await get(path);
      expect(response.status, path).toBe(200);
      expect(await response.text(), path).toContain("shell");
    }
  });

  it("404s missing extensionless-but-dotted assets instead of returning HTML", async () => {
    const response = await get("/assets/missing-abc123.js");
    expect(response.status).toBe(404);
  });

  it("serves real static files with their content type", async () => {
    const response = await get("/assets/app-abc123.js");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/javascript");
  });

  it("serves extensionless files that exist (e.g. agent binaries)", async () => {
    writeFileSync(join(root, "hlg-agent-linux-amd64"), "BINARY");
    const response = await get("/hlg-agent-linux-amd64");
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("BINARY");
  });

  it("never sees dot segments: the URL parser normalizes them first", async () => {
    // Literal and percent-encoded dot segments are collapsed by the URL
    // constructor before the asset server runs, so no "../" ever reaches the
    // file layer; the resolve-under-root check remains as defense-in-depth
    // for callers that bypass URL parsing.
    const response = await get("/%2e%2e/%2e%2e/etc/passwd");
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("shell");
  });
});
