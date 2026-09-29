import { describe, expect, it } from "vitest";
import { buildSampleTicks, sampleIndexFromPointer } from "./RttChart";

describe("RTT chart hover", () => {
  it("maps pointer x to nearest sample", () => {
    expect(sampleIndexFromPointer(0, 500, 8)).toBe(0);
    expect(sampleIndexFromPointer(250, 500, 8)).toBe(4);
    expect(sampleIndexFromPointer(500, 500, 8)).toBe(7);
  });
});

describe("RTT chart sample ticks", () => {
  it("keeps long sample runs to first, middle, and last labels", () => {
    expect(buildSampleTicks(8)).toEqual([1, 4, 8]);
  });

  it("shows every label for very short runs", () => {
    expect(buildSampleTicks(3)).toEqual([1, 2, 3]);
  });
});
