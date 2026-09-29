import { describe, expect, it } from "vitest";
import { isValidNodeIP } from "../src/node-ip";

describe("isValidNodeIP", () => {
  it.each(["1.1.1.1", "192.168.1.1", "2001:db8::1", "::1"])("accepts valid IP %s", (value) => {
    expect(isValidNodeIP(value)).toBe(true);
  });

  it.each([".....", "123.456.789.000", "1.2.3", "gggg::1"])("rejects invalid IP %s", (value) => {
    expect(isValidNodeIP(value)).toBe(false);
  });
});
