// @vitest-environment jsdom

import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createDownloadLinkState,
  compactDownloadHostLabel,
  DownloadTest,
  downloadHostOptions,
  downloadLinkURL,
  formatDownloadTTL,
  shouldAutoRunDownloadChallenge,
  upsertDownloadLinkState,
} from "./DownloadTest";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let container: HTMLDivElement | null = null;

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(
        JSON.stringify({
          token: "tok.sig",
          expires_at: Math.floor(Date.now() / 1000) + 900,
          node: "testnode01",
          domain: "testnode01.lgtest-node.example",
          link_id: "dl_123",
          sizes: ["10M", "100M", "1G"],
          extensions_remaining: 2,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    ),
  );
  window.turnstile = {
    render: (_element, options) => {
      queueMicrotask(() => options.callback("challenge-token"));
      return "widget";
    },
    reset: vi.fn(),
    remove: vi.fn(),
  };
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root?.unmount());
  container?.remove();
  root = null;
  container = null;
  delete window.turnstile;
  vi.unstubAllGlobals();
});

async function renderDownload() {
  await act(async () => {
    root?.render(createElement(DownloadTest, {
      challengeSiteKey: "site-key",
      node: {
        id: "testnode01",
        domain: "testnode01.lgtest-node.example",
        domain_v4: "testnode01.lgtest-node-v4.example",
        domain_v6: "testnode01.lgtest-node-v6.example",
        has_ipv4: true,
        has_ipv6: true,
      },
    }));
  });
}

function buttonWithText(text: string): HTMLButtonElement {
  const button = Array.from(container?.querySelectorAll("button") || []).find((element) => element.textContent?.includes(text));
  if (!button) throw new Error(`missing button: ${text}`);
  return button as HTMLButtonElement;
}

async function waitFor(check: () => boolean) {
  for (let i = 0; i < 20; i += 1) {
    if (check()) return;
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
  throw new Error("timed out waiting for condition");
}

describe("download link state", () => {
  it("uses the issued host for direct download links", () => {
    const state = createDownloadLinkState(
      {
        token: "tok.sig",
        expires_at: 2_000,
        node: "node-a",
        domain: "node-a.example.test",
        link_id: "dl_123",
        sizes: ["10M", "100M", "1G"],
        extensions_remaining: 2,
      },
    );

    expect(downloadLinkURL({ domain: "node-a.example.test" }, state, "100M")).toBe(
      "https://node-a.example.test/download/tok.sig/100M",
    );
    expect(downloadLinkURL(undefined, state, "100M")).toBe(
      "https://node-a.example.test/download/tok.sig/100M",
    );
    expect(state.sizes).toEqual(["10M", "100M", "1G"]);
    expect(state.linkID).toBe("dl_123");
    expect(state.domain).toBe("node-a.example.test");
    expect(state.extensionsRemaining).toBe(2);
  });

  it("labels expired links without a negative countdown", () => {
    expect(formatDownloadTTL(-1)).toBe("expired");
  });

  it("replaces the visible generated token without making size-specific state", () => {
    const first = createDownloadLinkState(
      { token: "first.a", expires_at: 1_000, node: "testnode01", domain: "testnode01.lgtest-node.example", link_id: "dl_a" },
    );
    const second = createDownloadLinkState(
      { token: "second.a", expires_at: 1_100, node: "testnode01", domain: "testnode01.lgtest-node.example", link_id: "dl_b" },
    );

    const state = upsertDownloadLinkState(upsertDownloadLinkState(null, first), second);

    expect(state?.linkID).toBe("dl_b");
    expect(state?.token).toBe("second.a");
    expect(state?.sizes).toEqual(["10M", "100M", "1G"]);
  });

  it("offers primary, IPv4, and IPv6 download hosts", () => {
    expect(
      downloadHostOptions({
        id: "testnode01",
        domain: "testnode01.lgtest-node.example",
        domain_v4: "testnode01.lgtest-node-v4.example",
        domain_v6: "testnode01.lgtest-node-v6.example",
        has_ipv4: true,
        has_ipv6: true,
      }),
    ).toEqual([
      { key: "primary", label: "Primary", domain: "testnode01.lgtest-node.example" },
      { key: "ipv4", label: "IPv4", domain: "testnode01.lgtest-node-v4.example" },
      { key: "ipv6", label: "IPv6", domain: "testnode01.lgtest-node-v6.example" },
    ]);
    expect(compactDownloadHostLabel("primary")).toBe("Auto");
  });

  it("auto-generates after a challenge token arrives", () => {
    expect(shouldAutoRunDownloadChallenge(true, "token", false)).toBe(true);
    expect(shouldAutoRunDownloadChallenge(true, "", false)).toBe(false);
    expect(shouldAutoRunDownloadChallenge(true, "token", true)).toBe(false);
    expect(shouldAutoRunDownloadChallenge(false, "token", false)).toBe(false);
  });

  it("shows one compact generated URL per download size after challenge", async () => {
    await renderDownload();
    expect(container?.textContent).not.toContain("No generated link yet.");
    expect(container?.querySelectorAll("input[readonly]")).toHaveLength(3);
    await act(async () => {
      buttonWithText("Generate Link").click();
    });
    await waitFor(() => {
      const first = container?.querySelector("input[readonly]") as HTMLInputElement | null;
      return Boolean(first?.value.includes("tok.sig"));
    });

    const readonlyInputs = Array.from(container?.querySelectorAll("input[readonly]") || []) as HTMLInputElement[];
    expect(readonlyInputs.map((input) => input.value)).toEqual([
      "https://testnode01.lgtest-node.example/download/tok.sig/10M",
      "https://testnode01.lgtest-node.example/download/tok.sig/100M",
      "https://testnode01.lgtest-node.example/download/tok.sig/1G",
    ]);
    expect(container?.querySelector("button[aria-label='Copy 10M download link']")).toBeTruthy();
    expect(container?.textContent).toContain("15m");
  });
});
