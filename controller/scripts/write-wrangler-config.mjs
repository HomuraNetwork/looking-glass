import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { loadDeployEnv } from "./load-env.mjs";
import { DEFAULT_CRON, parseCron } from "../shared/cron.mjs";

// Consume .env.cloudflare if present (CI uses its process environment): existing
// environment variables win, so CI secrets/vars are never overridden.
loadDeployEnv();

const workerName = requireEnv("WORKER_NAME");
const d1Name = requireEnv("D1_NAME");
const d1DatabaseID = requireEnv("D1_DATABASE_ID");
const crons = renderCrons(process.env.WORKER_CRONS);
const source = resolve("wrangler.template.jsonc");
const target = resolve("wrangler.jsonc");

const rendered = readFileSync(source, "utf8")
  .replaceAll("__WORKER_NAME__", workerName)
  .replaceAll("__D1_NAME__", d1Name)
  .replaceAll("__D1_DATABASE_ID__", d1DatabaseID)
  .replaceAll("__WORKER_CRONS__", crons.json);

mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, rendered);
console.log(`wrote ${target} for worker=${workerName} d1=${d1Name} crons=${crons.json}`);

/**
 * Render WORKER_CRONS into a JSON array literal for wrangler.jsonc.
 *
 * Unset defaults to every 30 minutes. A comma separates multiple schedules.
 * The value "none" (case-insensitive) or an empty string emits an empty array,
 * which disables the scheduled pass — note that this also stops ACME renewal
 * and the availability sweep.
 *
 * Every schedule is validated with the shared parser (the same one the local
 * runtime uses); wrangler does not validate crons itself, so a typo would
 * otherwise deploy silently and the schedule would never fire. Invalid input
 * fails the config step.
 */
function renderCrons(raw) {
  const value = (raw ?? "").trim();
  if (value === "") return { json: JSON.stringify([DEFAULT_CRON]) };
  if (value.toLowerCase() === "none") return { json: "[]" };
  const schedules = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (schedules.length === 0) return { json: "[]" };
  const invalid = schedules.filter((entry) => parseCron(entry) === null);
  if (invalid.length > 0) {
    console.error(`invalid WORKER_CRONS entry (not a 5-field cron expression): ${invalid.join(", ")}`);
    process.exit(1);
  }
  return { json: JSON.stringify(schedules) };
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`missing required env: ${name}`);
    process.exit(1);
  }
  return value;
}
