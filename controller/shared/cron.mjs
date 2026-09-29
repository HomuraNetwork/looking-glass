/**
 * Minimal 5-field cron support, shared by BOTH runtimes:
 *  - the Cloudflare config writer (controller/scripts/write-wrangler-config.mjs)
 *    validates WORKER_CRONS before emitting triggers.crons;
 *  - the local Node runtime (controller/local) parses LG_SCHEDULE_CRON into run
 *    times.
 *
 * It lives in .mjs (plain JS with JSDoc types) so it can be imported from both
 * the ESM build scripts and the TypeScript sources without a build step, and
 * so there is exactly one parser (no chance of the validator and the runtime
 * disagreeing about what is valid). tsc reads the JSDoc types.
 *
 * Grammar per field (minute hour day-of-month month day-of-week):
 *   *            any value
 *   a            a single value
 *   a-b          an inclusive range
 *   a/n          a..max, step n
 *   a-b/n        every n within the range
 *   *\/n         every n across the whole range
 * Comma-separated lists of any of the above.
 *
 * Day-of-week is 0-6 with 0 = Sunday (7 is accepted as Sunday too). When both
 * day-of-month and day-of-week are restricted, a day matches if EITHER matches
 * (standard cron behavior); otherwise both must match.
 */

/**
 * @typedef {Object} CronSchedule
 * @property {string} expression
 * @property {Set<number>} minutes
 * @property {Set<number>} hours
 * @property {Set<number>} daysOfMonth
 * @property {Set<number>} months
 * @property {Set<number>} daysOfWeek
 * @property {boolean} domRestricted
 * @property {boolean} dowRestricted
 */

/**
 * @typedef {Object} FieldSpec
 * @property {number} min
 * @property {number} max
 * @property {boolean} [wrapDayOfWeek]
 */

/** @type {FieldSpec[]} */
const FIELDS = [
  { min: 0, max: 59 }, // minute
  { min: 0, max: 23 }, // hour
  { min: 1, max: 31 }, // day of month
  { min: 1, max: 12 }, // month
  { min: 0, max: 6, wrapDayOfWeek: true }, // day of week
];

/**
 * Parse a 5-field cron expression.
 * @param {string} expression
 * @returns {CronSchedule | null} null for anything unsupported or invalid
 */
export function parseCron(expression) {
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) return null;
  /** @type {Array<{values: Set<number>, restricted: boolean}>} */
  const parsed = [];
  for (let index = 0; index < FIELDS.length; index++) {
    const values = parseField(fields[index], FIELDS[index]);
    if (!values) return null;
    parsed.push({ values, restricted: fields[index].trim() !== "*" });
  }
  return {
    expression: expression.trim(),
    minutes: parsed[0].values,
    hours: parsed[1].values,
    daysOfMonth: parsed[2].values,
    months: parsed[3].values,
    // Normalise a stray 7 (=Sunday) down to 0 so the day set only holds 0-6.
    daysOfWeek: new Set([...parsed[4].values].map((value) => (value === 7 ? 0 : value))),
    domRestricted: parsed[2].restricted,
    dowRestricted: parsed[4].restricted,
  };
}

/**
 * @param {string} field
 * @param {FieldSpec} spec
 * @returns {Set<number> | null}
 */
function parseField(field, spec) {
  const out = new Set();
  for (const part of field.split(",")) {
    const piece = part.trim();
    if (piece === "") return null;
    const [rangePart, stepPart] = piece.split("/");
    let step = 1;
    if (stepPart !== undefined) {
      step = Number(stepPart);
      if (!Number.isInteger(step) || step < 1) return null;
    }
    let start;
    let end;
    if (rangePart === "*") {
      start = spec.min;
      end = spec.max;
    } else if (rangePart.includes("-")) {
      const [rawStart, rawEnd] = rangePart.split("-");
      start = Number(rawStart);
      end = Number(rawEnd);
      if (!Number.isInteger(start) || !Number.isInteger(end)) return null;
    } else {
      start = Number(rangePart);
      if (!Number.isInteger(start)) return null;
      // "a/n" means a..max step n; a bare "a" is a single value.
      end = stepPart === undefined ? start : spec.max;
    }
    if (spec.wrapDayOfWeek) {
      if (start === 7) start = 0;
      if (end === 7) end = 0;
    }
    if (start < spec.min || end > spec.max || start > end) return null;
    for (let value = start; value <= end; value += step) out.add(value);
  }
  return out;
}

/**
 * The next time at or after `from` (excluding the current minute) that matches.
 * @param {CronSchedule} schedule
 * @param {Date} from
 * @returns {Date | null}
 */
export function nextCronRun(schedule, from) {
  const cursor = new Date(from.getTime());
  cursor.setSeconds(0, 0);
  cursor.setMinutes(cursor.getMinutes() + 1);
  // A leap year's worth of minutes safely covers any reachable schedule
  // (e.g. Feb 29). Null means nothing matches within that horizon.
  const limit = 366 * 24 * 60;
  for (let step = 0; step < limit; step++) {
    if (matches(schedule, cursor)) return new Date(cursor.getTime());
    cursor.setMinutes(cursor.getMinutes() + 1);
  }
  return null;
}

/**
 * @param {CronSchedule} schedule
 * @param {Date} at
 * @returns {boolean}
 */
function matches(schedule, at) {
  if (!schedule.minutes.has(at.getMinutes())) return false;
  if (!schedule.hours.has(at.getHours())) return false;
  if (!schedule.months.has(at.getMonth() + 1)) return false;
  const domMatch = schedule.daysOfMonth.has(at.getDate());
  const dowMatch = schedule.daysOfWeek.has(at.getDay());
  if (schedule.domRestricted && schedule.dowRestricted) return domMatch || dowMatch;
  return domMatch && dowMatch;
}

/**
 * @param {CronSchedule} schedule
 * @param {Date} [from]
 * @returns {number | null} milliseconds until the next run
 */
export function msUntilNextRun(schedule, from = new Date()) {
  const next = nextCronRun(schedule, from);
  return next ? next.getTime() - from.getTime() : null;
}

/** The default schedule when the value is unset (every 30 minutes). */
export const DEFAULT_CRON = "*/30 * * * *";

/**
 * Resolve a cron value into a schedule, or null when the pass is disabled.
 * Unset (empty) means the default; "none" (case-insensitive) disables it.
 * @param {string | undefined} raw
 * @returns {CronSchedule | null}
 */
export function resolveSchedule(raw) {
  const value = (raw ?? "").trim();
  if (value === "") return parseCron(DEFAULT_CRON);
  if (value.toLowerCase() === "none") return null;
  return parseCron(value);
}
