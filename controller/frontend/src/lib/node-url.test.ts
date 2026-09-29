// @vitest-environment jsdom

import { beforeEach, describe, expect, it, vi } from "vitest";
import { nodeIDFromSearch, resolveSelectedNodeID, writeNodeIDToURL } from "./node-url";

const nodes = [
  { id: "hk-1" },
  { id: "sg-1" },
];

beforeEach(() => {
  window.history.replaceState(null, "", "/");
});

describe("node URL selection", () => {
  it("reads the requested node id from the query string", () => {
    expect(nodeIDFromSearch("?node=sg-1")).toBe("sg-1");
    expect(nodeIDFromSearch("?node=hk-1&view=lg")).toBe("hk-1");
  });

  it("prefers a valid query node over the current selected node", () => {
    expect(resolveSelectedNodeID(nodes, "hk-1", "?node=sg-1")).toBe("sg-1");
  });

  it("keeps the current node when the query node is missing or invalid", () => {
    expect(resolveSelectedNodeID(nodes, "hk-1", "")).toBe("hk-1");
    expect(resolveSelectedNodeID(nodes, "hk-1", "?node=unknown")).toBe("hk-1");
  });

  it("falls back to the first node when no valid selection exists", () => {
    expect(resolveSelectedNodeID(nodes, "", "?node=unknown")).toBe("hk-1");
    expect(resolveSelectedNodeID([], "", "?node=sg-1")).toBe("");
  });

  it("writes selected nodes to the URL while preserving existing params and hash", () => {
    window.history.replaceState(null, "", "/?view=lg#output");
    writeNodeIDToURL("sg-1", "replace");
    expect(window.location.pathname).toBe("/");
    expect(window.location.search).toBe("?view=lg&node=sg-1");
    expect(window.location.hash).toBe("#output");
  });

  it("does not push a duplicate history entry for the current node", () => {
    window.history.replaceState(null, "", "/?node=sg-1");
    const push = vi.spyOn(window.history, "pushState");
    writeNodeIDToURL("sg-1");
    expect(push).not.toHaveBeenCalled();
    push.mockRestore();
  });
});
