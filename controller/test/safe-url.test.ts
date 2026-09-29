import { describe, expect, it } from "vitest";
import { isSafePublicLink } from "../src/safe-url";

describe("isSafePublicLink", () => {
  it.each(["https://example.com", "http://example.com:8080", "/pricing", ""]) ("accepts %s", (value) => {
    expect(isSafePublicLink(value)).toBe(true);
  });

  it.each(["javascript:alert(1)", "data:text/html,x", "//attacker.example", "https://user:pass@example.com"]) (
    "rejects %s",
    (value) => expect(isSafePublicLink(value)).toBe(false),
  );
});
