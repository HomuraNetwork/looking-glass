import { describe, expect, it } from "vitest";
import { certificateDomainsMatch, findCertificateBundleForDomain } from "../src/certificates";

/**
 * The auto-issuance trigger decides "does this node lack a certificate?" by
 * matching each node domain against the stored bundle patterns. That decision
 * must be exact — a false negative would skip issuing a needed certificate, a
 * false positive would hammer the CA. These lock down the matching rules.
 */
describe("certificate domain matching", () => {
  it("applies exact, wildcard-depth, and case-insensitive matching rules", () => {
    const cases = [
      { name: "single-label wildcard", patterns: ["*.lg-test.example"], domain: "node.lg-test.example", matches: true },
      { name: "wildcard does not cover multiple labels", patterns: ["*.example.com"], domain: "a.b.example.com", matches: false },
      { name: "wildcard does not cover its bare base", patterns: ["*.example.com"], domain: "example.com", matches: false },
      { name: "exact domain", patterns: ["node.example.com"], domain: "node.example.com", matches: true },
      { name: "case insensitive", patterns: ["*.Example.COM"], domain: "node.example.com", matches: true },
    ];
    for (const testCase of cases) {
      expect(certificateDomainsMatch(testCase.patterns, testCase.domain), testCase.name).toBe(testCase.matches);
    }
  });

  it("finds the bundle covering a node and reports none otherwise", () => {
    const bundles = [
      { domain: "a.example.com", domains: ["*.a.example.com"] },
      { domain: "b.example.com", domains: ["*.b.example.com"] },
    ];
    expect(findCertificateBundleForDomain(bundles, "node.a.example.com")).toMatchObject({ domain: "a.example.com" });
    expect(findCertificateBundleForDomain(bundles, "node.c.example.com")).toBeNull();
  });
});
