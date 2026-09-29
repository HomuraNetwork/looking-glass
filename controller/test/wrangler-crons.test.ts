import { describe, expect, it } from "vitest";

// Vitest runs in node, so these work at runtime even though the tsconfig targets
// Cloudflare workers types (no node types / no allowJs). The specifiers are
// computed so tsc does not try to resolve them.
type ChildProcess = { execFileSync(file: string, args: string[], options: { cwd: string; env: Record<string, string | undefined> }): unknown };
type UrlModule = { fileURLToPath(url: string): string };
type PathModule = { dirname(path: string): string; join(...parts: string[]): string; resolve(...parts: string[]): string };
type FsModule = {
  mkdtempSync(prefix: string): string;
  readFileSync(path: string, encoding: string): string;
  writeFileSync(path: string, data: string): void;
};
type OsModule = { tmpdir(): string };
type CronModule = {
  DEFAULT_CRON: string;
  parseCron(expression: string): { expression: string } | null;
};

const { execFileSync } = (await import(`node:` + `child_process`)) as unknown as ChildProcess;
const { fileURLToPath } = (await import(`node:` + `url`)) as unknown as UrlModule;
const { dirname, join, resolve } = (await import(`node:` + `path`)) as unknown as PathModule;
const { mkdtempSync, readFileSync, writeFileSync } = (await import(`node:` + `fs`)) as unknown as FsModule;
const { tmpdir } = (await import(`node:` + `os`)) as unknown as OsModule;
const { DEFAULT_CRON, parseCron } = (await import(`../` + `shared/cron.mjs`)) as unknown as CronModule;

const workerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Run the config writer in an isolated dir and return the rendered crons. */
function renderCrons(raw: string | undefined): { json: string[]; status: number } {
  const dir = mkdtempSync(join(tmpdir(), "lg-wrc-"));
  writeFileSync(join(dir, "wrangler.template.jsonc"), '{"triggers":{"crons":__WORKER_CRONS__}}');
  // Copy the scripts + shared module so the relative imports resolve.
  execFileSync("cp", ["-r", join(workerRoot, "scripts"), join(workerRoot, "shared"), dir], { cwd: dir, env: process.env });
  const env: Record<string, string | undefined> = {
    ...process.env,
    WORKER_NAME: "t",
    D1_NAME: "d",
    D1_DATABASE_ID: "00000000-0000-0000-0000-000000000000",
  };
  delete env.WORKER_CRONS;
  if (raw !== undefined) env.WORKER_CRONS = raw;
  const nodeBin = (process as unknown as { execPath: string }).execPath;
  const run = () => execFileSync(nodeBin, [join(dir, "scripts", "write-wrangler-config.mjs")], { cwd: dir, env });
  try {
    run();
  } catch {
    return { json: [], status: 1 };
  }
  const rendered = JSON.parse(readFileSync(join(dir, "wrangler.jsonc"), "utf8")) as { triggers: { crons: string[] } };
  return { json: rendered.triggers.crons, status: 0 };
}

describe("WORKER_CRONS rendering", () => {
  it("defaults to every 30 minutes", () => {
    expect(renderCrons(undefined)).toEqual({ json: [DEFAULT_CRON], status: 0 });
    expect(renderCrons("  ")).toEqual({ json: [DEFAULT_CRON], status: 0 });
  });

  it("accepts multiple comma-separated schedules", () => {
    expect(renderCrons("*/10 * * * *, 0 3 * * *")).toEqual({ json: ["*/10 * * * *", "0 3 * * *"], status: 0 });
  });

  it("renders none as an empty cron list", () => {
    expect(renderCrons("none")).toEqual({ json: [], status: 0 });
    expect(renderCrons("NONE")).toEqual({ json: [], status: 0 });
  });

  it("fails the config step on an invalid schedule (wrangler does not validate)", () => {
    expect(renderCrons("not a cron").status).toBe(1);
    expect(renderCrons("0 0 * * *, 99 * * * *").status).toBe(1);
  });

  it("uses the same parser as the runtime, so accepted input is always runnable", () => {
    for (const entry of ["*/30 * * * *", "0 0 * * 0", "0 0 1 * *", "15 2 * * 1-5"]) {
      expect(renderCrons(entry), entry).toEqual({ json: [entry], status: 0 });
      expect(parseCron(entry), entry).not.toBeNull();
    }
  });
});
