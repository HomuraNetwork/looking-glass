// @vitest-environment jsdom
import { act, createElement, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The section-level refresh callbacks are the fix under test, so the shell and
// leaf sections are replaced with stubs that expose those callbacks directly.
const holders: {
  section?: (s: string) => void;
  nodesRefresh?: () => Promise<void> | void;
  certRefresh?: () => Promise<void> | void;
  usersRefresh?: () => Promise<void> | void;
} = {};

const { listAdminNodesMock, listAdminUsersMock, listAdminCertificatesMock } = vi.hoisted(() => ({
  listAdminNodesMock: vi.fn(),
  listAdminUsersMock: vi.fn(),
  listAdminCertificatesMock: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    adminSession: vi.fn(async () => ({ authenticated: true, onboarding_required: false, user: { username: "admin" }, db_status: undefined })),
    listAdminNodes: listAdminNodesMock,
    listAdminUsers: listAdminUsersMock,
    listAdminCertificates: listAdminCertificatesMock,
    listAdminRuntimeSecrets: vi.fn(async () => []),
    listAdminProjectSettings: vi.fn(async () => []),
    getAdminDNSSettings: vi.fn(async () => null),
  };
});

vi.mock("./admin/AdminShell", () => ({
  default: undefined,
  AdminShell: ({ onSection, children }: { onSection: (s: string) => void; children: ReactNode }) => {
    holders.section = onSection;
    return createElement("div", null, children);
  },
}));

vi.mock("./admin/AdminNodes", () => ({
  AdminNodes: (props: { onRefresh: () => Promise<void> | void }) => {
    holders.nodesRefresh = props.onRefresh;
    return createElement("div", null, "stub-nodes");
  },
}));

vi.mock("./admin/AdminSystem", () => ({
  AdminSystem: (props: { onRefreshCertificates: () => Promise<void> | void }) => {
    holders.certRefresh = props.onRefreshCertificates;
    return createElement("div", null, "stub-system");
  },
}));

vi.mock("./admin/AdminUsers", () => ({
  AdminUsers: (props: { onRefresh: () => Promise<void> | void }) => {
    holders.usersRefresh = props.onRefresh;
    return createElement("div", null, "stub-users");
  },
}));

vi.mock("./admin/AdminOverview", () => ({ AdminOverview: () => createElement("div", null, "stub-overview") }));
vi.mock("./admin/AdminBranding", () => ({ AdminBranding: () => createElement("div", null, "stub-branding") }));
vi.mock("./admin/AdminRawConfig", () => ({ AdminRawConfig: () => createElement("div", null, "stub-advanced") }));

import { AdminPanel } from "./AdminPanel";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe("AdminPanel session expiry on section refresh", () => {
  let root: Root | null = null;
  let container: HTMLDivElement | null = null;

  beforeEach(() => {
    for (const key of ["section", "nodesRefresh", "certRefresh", "usersRefresh"] as const) delete holders[key];
    listAdminNodesMock.mockReset();
    listAdminUsersMock.mockReset();
    listAdminCertificatesMock.mockReset();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    if (root) act(() => root?.unmount());
    container?.remove();
  });

  /** Render the panel and wait for the initial load to settle. */
  async function renderPanel() {
    await act(async () => root?.render(createElement(AdminPanel)));
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
  }

  /** Switch to a section so its leaf stub mounts and its refresh is captured. */
  async function showSection(section: string) {
    await act(async () => { holders.section?.(section); });
  }

  it("signs out when the nodes refresh hits a 401 instead of silently keeping data", async () => {
    listAdminNodesMock.mockResolvedValue([]);
    listAdminUsersMock.mockResolvedValue([]);
    listAdminCertificatesMock.mockResolvedValue({ certificates: [], managed_domains: [] });
    await renderPanel();
    await showSection("nodes");
    expect(container?.textContent).toContain("stub-nodes");

    // Session expires: the next section refresh must drop back to the login gate.
    listAdminNodesMock.mockRejectedValue(new Error("unauthorized"));
    await act(async () => { await holders.nodesRefresh?.(); });
    expect(container?.textContent).toContain("Sign In");
    expect(container?.textContent).not.toContain("stub-nodes");
  });

  it("signs out when the certificate refresh hits a 401", async () => {
    listAdminNodesMock.mockResolvedValue([]);
    listAdminUsersMock.mockResolvedValue([]);
    listAdminCertificatesMock.mockResolvedValue({ certificates: [], managed_domains: [] });
    await renderPanel();
    await showSection("system");

    listAdminCertificatesMock.mockRejectedValue(new Error("unauthorized"));
    await act(async () => { await holders.certRefresh?.(); });
    expect(container?.textContent).toContain("Sign In");
  });

  it("signs out when the users refresh hits a 401", async () => {
    listAdminNodesMock.mockResolvedValue([]);
    listAdminUsersMock.mockResolvedValue([]);
    listAdminCertificatesMock.mockResolvedValue({ certificates: [], managed_domains: [] });
    await renderPanel();
    await showSection("users");

    listAdminUsersMock.mockRejectedValue(new Error("unauthorized"));
    await act(async () => { await holders.usersRefresh?.(); });
    expect(container?.textContent).toContain("Sign In");
  });

  it("keeps the session and surfaces a non-auth refresh error", async () => {
    listAdminNodesMock.mockResolvedValue([]);
    listAdminUsersMock.mockResolvedValue([]);
    listAdminCertificatesMock.mockResolvedValue({ certificates: [], managed_domains: [] });
    await renderPanel();
    await showSection("nodes");

    // A transient failure (not a 401) must not log the admin out.
    listAdminNodesMock.mockRejectedValue(new Error("node_refresh_failed"));
    await act(async () => { await holders.nodesRefresh?.(); });
    expect(container?.textContent).not.toContain("Sign In");
    expect(container?.textContent).toContain("stub-nodes");
  });
});
