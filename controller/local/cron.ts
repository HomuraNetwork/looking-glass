/**
 * Local-runtime cron support.
 *
 * The implementation is the shared, framework-free module in
 * controller/shared/cron.mjs so the config writer (which validates WORKER_CRONS to
 * emit Cloudflare triggers.crons) and this runtime use the exact same parser —
 * a value accepted at deploy time cannot fail at runtime, and vice versa.
 *
 * This wrapper only re-exports it with proper TypeScript types.
 */

import {
  DEFAULT_CRON,
  msUntilNextRun as msUntilNextRunShared,
  nextCronRun as nextCronRunShared,
  parseCron as parseCronShared,
  resolveSchedule as resolveScheduleShared,
} from "../shared/cron.mjs";

export interface CronSchedule {
  expression: string;
  minutes: Set<number>;
  hours: Set<number>;
  daysOfMonth: Set<number>;
  months: Set<number>;
  daysOfWeek: Set<number>;
  domRestricted: boolean;
  dowRestricted: boolean;
}

export function parseCron(expression: string): CronSchedule | null {
  return parseCronShared(expression) as CronSchedule | null;
}

export function nextCronRun(schedule: CronSchedule, from: Date): Date | null {
  return nextCronRunShared(schedule, from) as Date | null;
}

export function msUntilNextRun(schedule: CronSchedule, from: Date = new Date()): number | null {
  return msUntilNextRunShared(schedule, from) as number | null;
}

export function resolveSchedule(raw: string | undefined): CronSchedule | null {
  return resolveScheduleShared(raw) as CronSchedule | null;
}

export { DEFAULT_CRON };
