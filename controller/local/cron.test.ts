import { describe, expect, it } from "vitest";
import { msUntilNextRun, nextCronRun, parseCron, resolveSchedule } from "./cron";

/** Local-time date helper (cron is evaluated in local time). */
function at(year: number, month: number, day: number, hour: number, minute: number): Date {
  return new Date(year, month - 1, day, hour, minute, 0, 0);
}

describe("cron parsing", () => {
  it("parses supported expressions and rejects malformed input", () => {
    const schedule = parseCron("*/30 * * * *");
    expect(schedule).not.toBeNull();
    expect([...schedule!.minutes].sort((a, b) => a - b)).toEqual([0, 30]);
    expect(schedule!.hours.size).toBe(24);
    const fields = parseCron("0,15,45 9-17/2 1-10 3,6 *");
    expect([...fields!.minutes].sort((a, b) => a - b)).toEqual([0, 15, 45]);
    expect([...fields!.hours].sort((a, b) => a - b)).toEqual([9, 11, 13, 15, 17]);
    expect([...fields!.daysOfMonth]).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect([...fields!.months].sort((a, b) => a - b)).toEqual([3, 6]);
    expect([...parseCron("0 0 * * 7")!.daysOfWeek]).toEqual([0]);
    expect([...parseCron("0 0 * * 0")!.daysOfWeek]).toEqual([0]);
    for (const bad of ["", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "a * * * *", "*/0 * * * *"]) {
      expect(parseCron(bad), bad).toBeNull();
    }
  });
});

describe("cron next run", () => {
  it("advances to the next matching minute", () => {
    const schedule = parseCron("*/30 * * * *")!;
    expect(nextCronRun(schedule, at(2026, 9, 23, 10, 0))).toEqual(at(2026, 9, 23, 10, 30));
    expect(nextCronRun(schedule, at(2026, 9, 23, 10, 30))).toEqual(at(2026, 9, 23, 11, 0));
    expect(nextCronRun(schedule, at(2026, 9, 23, 10, 31))).toEqual(at(2026, 9, 23, 11, 0));
    expect(msUntilNextRun(schedule, at(2026, 9, 23, 10, 0))).toBe(30 * 60 * 1000);
  });

  it("skips to the next matching day for a daily schedule", () => {
    const schedule = parseCron("0 3 * * *")!;
    expect(nextCronRun(schedule, at(2026, 9, 23, 10, 0))).toEqual(at(2026, 9, 24, 3, 0));
  });

  it("uses OR semantics when both day-of-month and day-of-week are set", () => {
    // Fires on the 1st of the month OR on Sundays.
    const schedule = parseCron("0 0 1 * 0")!;
    // 2026-09-23 is a Wednesday; the next match is Sunday 2026-09-27.
    expect(nextCronRun(schedule, at(2026, 9, 23, 10, 0))).toEqual(at(2026, 9, 27, 0, 0));
  });

});

describe("resolveSchedule", () => {
  it("resolves default, disabled, invalid, and custom schedules", () => {
    expect(resolveSchedule(undefined)!.expression).toBe("*/30 * * * *");
    expect(resolveSchedule("   ")!.expression).toBe("*/30 * * * *");
    expect(resolveSchedule("none")).toBeNull();
    expect(resolveSchedule("NONE")).toBeNull();
    expect(resolveSchedule("not a cron")).toBeNull();
    expect(resolveSchedule("* * * *")).toBeNull();
    expect(resolveSchedule("*/10 * * * *")!.expression).toBe("*/10 * * * *");
  });
});
