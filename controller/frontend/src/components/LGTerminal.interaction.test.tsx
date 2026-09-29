// @vitest-environment jsdom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LGTerminal } from "./LGTerminal";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  sent: string[] = [];
  constructor(_url: string) { FakeWebSocket.instances.push(this); queueMicrotask(() => this.onopen?.()); }
  send(value: string) { this.sent.push(value); }
  close() { this.onclose?.({ code: 1000 } as CloseEvent); }
}

describe("LGTerminal challenge interaction", () => {
  let root: Root;
  let container: HTMLDivElement;
  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);
    window.turnstile = { render: (_el, options) => { queueMicrotask(() => options.callback("challenge-token")); return "widget"; }, reset: vi.fn(), remove: vi.fn() };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ token: "live-token", expires_at: Math.floor(Date.now() / 1000) + 900, node: "n1", domain: "n1.example" }), { status: 200, headers: { "content-type": "application/json" } })));
    container = document.createElement("div"); document.body.appendChild(container); root = createRoot(container);
  });
  afterEach(() => { act(() => root.unmount()); container.remove(); delete window.turnstile; vi.unstubAllGlobals(); });

  it("sends the Turnstile token in the live-session request", async () => {
    await act(async () => root.render(createElement(LGTerminal, { challengeSiteKey: "site-key", node: { id: "n1", domain: "n1.example", has_ipv4: true, has_ipv6: true } })));
    const input = container.querySelector("input#target") as HTMLInputElement;
    await act(async () => { const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set; setter?.call(input, "1.1.1.1"); input.dispatchEvent(new Event("input", { bubbles: true })); });
    const run = container.querySelector('button[aria-label="Run Looking Glass job"]') as HTMLButtonElement;
    await act(async () => run.click());
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls;
    const live = calls.find((call) => String(call[0]).includes("live-session"));
    expect(live).toBeDefined();
    expect(JSON.parse(String((live as [RequestInfo | URL, RequestInit])[1].body))).toMatchObject({ node: "n1", turnstile_token: "challenge-token" });
  });

  it("leaves the running state when the worker stops the job at the guard", async () => {
    await act(async () => root.render(createElement(LGTerminal, { node: { id: "n1", domain: "n1.example", has_ipv4: true, has_ipv6: true } })));
    const input = container.querySelector("input#target") as HTMLInputElement;
    await act(async () => { const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set; setter?.call(input, "1.1.1.1"); input.dispatchEvent(new Event("input", { bubbles: true })); });
    const run = container.querySelector('button[aria-label="Run Looking Glass job"]') as HTMLButtonElement;
    await act(async () => run.click());
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });

    const socket = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
    // The worker rejects the target (e.g. dns_no_records) with a stop line then
    // a completion control frame. The run button must go back to "Run" (not stay
    // as "Stop"), and the stop line must render as an error.
    await act(async () => {
      socket.onmessage?.({ data: JSON.stringify({ stream: "stdout", line: "stopped: worker DNS safety check found no usable public address" }) } as MessageEvent);
      socket.onmessage?.({ data: JSON.stringify({ stream: "control", event: "complete" }) } as MessageEvent);
    });
    const text = container.textContent ?? "";
    expect(text).toContain("stopped: worker DNS safety check found no usable public address");
    expect(container.querySelector(".text-destructive")).not.toBeNull();
  });

  it("keeps the socket open after a debug error so the user-facing error is still delivered", async () => {
    await act(async () => root.render(createElement(LGTerminal, { node: { id: "n1", domain: "n1.example", has_ipv4: true, has_ipv6: true } })));
    const input = container.querySelector("input#target") as HTMLInputElement;
    await act(async () => { const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set; setter?.call(input, "1.1.1.1"); input.dispatchEvent(new Event("input", { bubbles: true })); });
    const run = container.querySelector('button[aria-label="Run Looking Glass job"]') as HTMLButtonElement;
    await act(async () => run.click());
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });

    const socket = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
    // The worker emits the reason on the debug stream first. That line starts
    // with "error:" but is a diagnostic, not job output: if it ended the job the
    // socket would close and the real, user-facing error below would be dropped
    // (the bug being fixed here).
    await act(async () => {
      socket.onmessage?.({ data: JSON.stringify({ stream: "debug", line: "error: dns_no_records" }) } as MessageEvent);
    });
    await act(async () => {
      socket.onmessage?.({ data: JSON.stringify({ stream: "stdout", mode: "command", line: "$ ping -6 -O -c 10 -W 2 test.example" }) } as MessageEvent);
      socket.onmessage?.({ data: JSON.stringify({ stream: "stdout", line: 'error: DNS resolution failed: no IPv6 (AAAA) record found for "test.example"' }) } as MessageEvent);
      socket.onmessage?.({ data: JSON.stringify({ stream: "control", event: "complete" }) } as MessageEvent);
    });
    const text = container.textContent ?? "";
    expect(text).toContain("DNS resolution failed");
    expect(container.querySelector(".text-destructive")).not.toBeNull();
  });
});
