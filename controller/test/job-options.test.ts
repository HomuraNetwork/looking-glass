import { describe, expect, it } from "vitest";
import { normalizeJobCount } from "../src/job-options";

describe("job options", () => {
  it("allows only the exposed count choices", () => {
    expect(normalizeJobCount(5)).toBe(5);
    expect(normalizeJobCount(10)).toBe(10);
    expect(normalizeJobCount(4)).toBe(5);
    expect(normalizeJobCount(7)).toBe(5);
    expect(normalizeJobCount(undefined)).toBe(5);
  });
});
