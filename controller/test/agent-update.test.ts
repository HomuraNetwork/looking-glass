import { describe, expect, it } from "vitest";
import { isAgentOutdated } from "../src/admin-api";

/**
 * Update detection compares a node's reported build id with the one the
 * controller distributes (from the agent manifest). Ids are opaque (agent-source
 * commit SHAs), so any difference is "outdated". A node that has reported a
 * version but no build id runs an agent predating the feature, so it is
 * outdated too — that is the common case right after this ships. A node with no
 * version at all has no agent yet and must not be flagged, and neither must an
 * unknown distributed build.
 */
describe("agent update detection", () => {
  it("flags a node whose build differs from the distributed one", () => {
    expect(isAgentOutdated({ version: "0.3.0", build_id: "abc1234" }, "def5678")).toBe(true);
  });

  it("does not flag a node on the same build", () => {
    expect(isAgentOutdated({ version: "0.3.0", build_id: "abc1234" }, "abc1234")).toBe(false);
  });

  it("flags a node that reported a version but no build id (pre-feature agent)", () => {
    expect(isAgentOutdated({ version: "0.3.0", build_id: null }, "abc1234")).toBe(true);
    expect(isAgentOutdated({ version: "0.3.0" }, "abc1234")).toBe(true);
    expect(isAgentOutdated({ version: "0.3.0", build_id: "unknown" }, "abc1234")).toBe(true);
  });

  it("does not flag a node with no agent yet", () => {
    expect(isAgentOutdated({ version: null, build_id: null }, "abc1234")).toBe(false);
    expect(isAgentOutdated({}, "abc1234")).toBe(false);
  });

  it("does not flag when the distributed build is unknown", () => {
    expect(isAgentOutdated({ version: "0.3.0", build_id: "abc1234" }, null)).toBe(false);
    expect(isAgentOutdated({ version: "0.3.0", build_id: "abc1234" }, "unknown")).toBe(false);
    expect(isAgentOutdated({ version: "0.3.0", build_id: null }, null)).toBe(false);
  });
});
