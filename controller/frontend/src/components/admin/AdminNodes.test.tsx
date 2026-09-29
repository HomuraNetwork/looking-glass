// @vitest-environment jsdom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { checkAdminNodeMock } = vi.hoisted(() => ({ checkAdminNodeMock: vi.fn() }));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    checkAdminNode: checkAdminNodeMock,
    // The component imports these; give inert implementations so rendering
    // does not hit the network. None are exercised by this test.
    upsertAdminNode: vi.fn(),
    deleteAdminNode: vi.fn(),
    issueAdminNodeInit: vi.fn(),
    upsertAdminNodeDNS: vi.fn(),
  };
});

import { AdminNodes, formatNodeTime, type DNSConfig } from "./AdminNodes";
import type { AdminNode } from "@/lib/api";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const dnsConfig: DNSConfig = { base: "example.com", v4Base: "", v6Base: "", singleBase: true, mode: "id", prefix: "", autoDNS: false };

function node(overrides: Partial<AdminNode> = {}): AdminNode {
  return {
    id: "edge01",
    internal_id: "edge01",
    domain: "edge01.example.com",
    display_name: "Edge 01",
    features: ["ping"],
    enabled: true,
    hidden: false,
    config_version: 1,
    config_applied_version: 1,
    created_at: 0,
    updated_at: 0,
    ...overrides,
  } as AdminNode;
}

describe("formatNodeTime", () => {
  beforeEach(() => {
    vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
  });

  afterEach(() => {
    vi.mocked(Date.now).mockRestore();
  });

  it("renders past timestamps as 'ago'", () => {
    const now = Date.now() / 1000;
    expect(formatNodeTime(now - 5)).toBe("just now");
    expect(formatNodeTime(now - 120)).toBe("2m ago");
    expect(formatNodeTime(now - 7200)).toBe("2h ago");
  });

  it("renders future timestamps (e.g. a certificate expiry) as 'in', not 'just now'", () => {
    const now = Date.now() / 1000;
    expect(formatNodeTime(now + 7200)).toBe("in 2h");
    expect(formatNodeTime(now + 30)).toBe("in <1m");
    expect(formatNodeTime(now + 3 * 24 * 3600)).toBe("in 3d");
    // Beyond a week it falls back to an absolute date, not a bogus "just now".
    const far = formatNodeTime(now + 89 * 24 * 3600);
    expect(far).not.toBe("just now");
    expect(far).toMatch(/\d/);
  });

  it("treats a missing timestamp as never", () => {
    expect(formatNodeTime(0)).toBe("never");
    expect(formatNodeTime(undefined)).toBe("never");
  });
});

describe("AdminNodes check refresh", () => {  let root: Root | null = null;
  let container: HTMLDivElement | null = null;

  beforeEach(() => {
    checkAdminNodeMock.mockReset();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    if (root) act(() => root?.unmount());
    container?.remove();
  });

  it("refreshes the node list after a check so the liveness badge updates in place", async () => {
    checkAdminNodeMock.mockResolvedValue({
      healthy: false,
      domain: "edge01.example.com",
      checked_at: 1,
      checks: { generate_204: { ok: false, duration_ms: 5000, error: "timeout" }, info: { ok: false, duration_ms: 5000, error: "timeout" } },
    });
    const onRefresh = vi.fn();

    await act(async () => root?.render(createElement(AdminNodes, {
      nodes: [node()],
      dnsConfig,
      onDNSConfig: vi.fn(),
      onSaved: vi.fn(),
      onError: vi.fn(),
      onRefresh,
      busy: "",
      setBusy: vi.fn(),
    })));
    await act(async () => { await new Promise((r) => setTimeout(r, 10)); });

    const buttons = Array.from(container?.querySelectorAll("button") ?? []);
    const check = buttons.find((button) => button.textContent?.includes("Check"));
    expect(check, "Check button not found").toBeDefined();
    await act(async () => check?.click());
    await act(async () => { await new Promise((r) => setTimeout(r, 10)); });

    expect(checkAdminNodeMock).toHaveBeenCalledWith("edge01");
    // The availability badge reads node.availability from the parent list, so
    // the check must trigger a refresh rather than only updating local state.
    expect(onRefresh).toHaveBeenCalled();
  });
});
