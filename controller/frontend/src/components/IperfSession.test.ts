// @vitest-environment jsdom

import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildIperfClientCommand,
  buildIperfServerCommand,
  agentIperfFlowFromPayload,
  agentIperfFlowFromCommand,
  formatIperfAgentDebugEvent,
  formatIperfDisplayEvent,
  effectiveIperfHostFamily,
  IperfSession,
  iperfOutcomeFromCloseReason,
  iperfOutcomeFromOutput,
  preferredIperfClientHost,
  shouldAutoRunIperfChallenge,
} from "./IperfSession";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(public readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  emit(payload: unknown) {
    this.onmessage?.({ data: JSON.stringify(payload) } as MessageEvent);
  }

  close() {
    this.onclose?.();
  }
}

let root: Root | null = null;
let container: HTMLDivElement | null = null;

beforeEach(() => {
  FakeWebSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(
        JSON.stringify({
          session_id: "ipf_123",
          host: "testnode01.lgtest-node.example",
          port: 32657,
          command: "iperf3 -c testnode01.lgtest-node.example -p 32657 -P 1 -t 10",
          expires_at: Math.floor(Date.now() / 1000) + 180,
          max_runs: 20,
          mode: "udp",
          reverse: true,
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

async function renderIperf() {
  await act(async () => {
    root?.render(createElement(IperfSession, {
      challengeSiteKey: "site-key",
      node: {
        id: "testnode01",
        domain: "testnode01.lgtest-node.example",
        public_ipv4: "203.0.113.9",
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

describe("iperf display event formatting", () => {
  it("shows the server command as shell-style user output", () => {
    expect(buildIperfServerCommand(32657)).toBe("$ iperf3 -s -p 32657");
  });

  it("builds a minimal copyable client command and omits udp bitrate", () => {
    expect(buildIperfClientCommand("203.0.113.9", 32657, { mode: "tcp", reverse: false, duration: 10, parallel: 1 })).toBe(
      "iperf3 -c 203.0.113.9 -p 32657",
    );
    expect(buildIperfClientCommand("testnode01.lgtest-node.example", 32657, { mode: "udp", reverse: true, duration: 40, parallel: 10 })).toBe(
      "iperf3 -u -c testnode01.lgtest-node.example -p 32657 -P 10 -t 40 -R",
    );
  });

  it("selects iPerf client host by address family", () => {
    const node = {
      id: "testnode01",
      domain: "testnode01.lgtest-node.example",
      domain_v6: "testnode01.lgtest-node-v6.example",
      display_name: "Test Node 01",
      region: "TEST",
      features: ["iperf3"],
      has_ipv4: true,
      has_ipv6: true,
      maintenance: false,
      public_ipv4: "203.0.113.9",
      public_ipv6: "2001:db8::a",
    };

    expect(effectiveIperfHostFamily("default")).toBe("ipv4");
    expect(preferredIperfClientHost(node, "", "ipv4")).toBe("203.0.113.9");
    expect(preferredIperfClientHost(node, "", "ipv6")).toBe("2001:db8::a");
  });

  it("routes server listening markers to debug", () => {
    expect(
      formatIperfDisplayEvent({
        type: "output",
        line: "server listening: testnode01.lgtest-node.example:32657",
      }),
    ).toEqual({
      stream: "debug",
      line: "server listening: testnode01.lgtest-node.example:32657",
    });
  });

  it("renders closed events as a visible end line", () => {
    expect(formatIperfDisplayEvent({ type: "closed", close_reason: "closed_by_request", at: 1780334186 })).toEqual({
      stream: "output",
      line: "cancelled: closed_by_request\n----- END AT 2026-06-01T17:16:26Z -----",
      closeReason: "closed_by_request",
    });
    expect(formatIperfDisplayEvent({ type: "closed", close_reason: "run_limit", at: 1780334186 })).toEqual({
      stream: "output",
      line: "completed: run_limit\n----- END AT 2026-06-01T17:16:26Z -----",
      closeReason: "run_limit",
    });
  });

  it("formats every agent event class for the debug stream", () => {
    expect(formatIperfAgentDebugEvent({ type: "status", port: 32657, remaining_seconds: 120, remaining_runs: 3, runs_used: 1 })).toBe(
      "agent status: port=32657 remaining=120s runs_left=3 runs_used=1",
    );
    expect(formatIperfAgentDebugEvent({ type: "output", line: "cancelled: client stopped" })).toBe("agent output: cancelled: client stopped");
    expect(formatIperfAgentDebugEvent({ type: "closed", close_reason: "ttl_expired", at: 1780334186 })).toBe(
      "agent closed: reason=ttl_expired at=2026-06-01T17:16:26Z",
    );
  });

  it("auto-starts after a challenge token arrives", () => {
    expect(shouldAutoRunIperfChallenge(true, "token", false, false)).toBe(true);
    expect(shouldAutoRunIperfChallenge(true, "", false, false)).toBe(false);
    expect(shouldAutoRunIperfChallenge(true, "token", true, false)).toBe(false);
    expect(shouldAutoRunIperfChallenge(true, "token", false, true)).toBe(false);
    expect(shouldAutoRunIperfChallenge(false, "token", false, false)).toBe(false);
  });

  it("accepts iPerf flow only from agent payloads", () => {
    expect(agentIperfFlowFromPayload({ mode: "udp", reverse: true })).toEqual({ mode: "udp", reverse: true });
    expect(agentIperfFlowFromPayload({ mode: "tcp", reverse: false })).toEqual({ mode: "tcp", reverse: false });
    expect(agentIperfFlowFromPayload({ mode: "http", reverse: true })).toBeNull();
    expect(agentIperfFlowFromCommand("iperf3 -u -c testnode01.lgtest-node.example -p 32657 -R")).toEqual({
      mode: "udp",
      reverse: true,
    });
    expect(agentIperfFlowFromCommand("iperf3 -c testnode01.lgtest-node.example -p 32657")).toEqual({
      mode: "tcp",
      reverse: false,
    });
  });

  it("derives visible run outcomes from output and close reasons", () => {
    expect(iperfOutcomeFromOutput("cancelled: the client has terminated")).toBe("cancelled");
    expect(iperfOutcomeFromOutput("---------- RUN COMPLETE ----------")).toBe("finished");
    expect(iperfOutcomeFromOutput("client rejected: duration_limit requested_duration=90s max_duration=40s")).toBe("error");
    expect(iperfOutcomeFromOutput("accepted connection from 203.0.113.10, port 5000")).toBe("");
    // The per-run summary line ends a run even though iperf3 servers never print "RUN COMPLETE".
    expect(iperfOutcomeFromOutput("[  5]   0.00-10.00  sec  68.5 GBytes  58.8 Gbits/sec    0    sender")).toBe("finished");
    expect(iperfOutcomeFromOutput("[  5]   3.00-4.00   sec  7.45 GBytes  64.0 Gbits/sec")).toBe("");
    expect(iperfOutcomeFromCloseReason("closed_by_request")).toBe("cancelled");
    expect(iperfOutcomeFromCloseReason("run_limit")).toBe("finished");
    expect(iperfOutcomeFromCloseReason("ttl_expired")).toBe("expired");
  });

  it("scrolls iPerf output to the newest line", async () => {
    await renderIperf();

    const output = container?.querySelector("[data-iperf-terminal] pre") as HTMLPreElement | null;
    expect(output).not.toBeNull();
    Object.defineProperty(output, "scrollHeight", { configurable: true, value: 900 });

    await act(async () => {
      buttonWithText("Start iPerf3").click();
    });
    await waitFor(() => FakeWebSocket.instances.length === 1);

    expect(output?.scrollTop).toBe(900);
  });

  it("keeps session output visible after close and moves restart outside the overlay", async () => {
    await renderIperf();
    await act(async () => {
      buttonWithText("Start iPerf3").click();
    });
    await waitFor(() => FakeWebSocket.instances.length === 1);

    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "output", line: "accepted client: tcp parallel=10 duration=10s reverse=false" });
      FakeWebSocket.instances[0].emit({ type: "closed", close_reason: "ttl_expired", at: 1780334186 });
    });

    expect(container?.textContent).toContain("Stopped");
    expect(container?.textContent).toContain("accepted client: tcp parallel=10");
    expect(buttonWithText("Restart").closest(".absolute")).toBeNull();
    expect(container?.querySelector("input[aria-label='iPerf3 client command']")).toBeNull();
    expect(container?.querySelector("[data-iperf-command-action]")?.textContent).toContain("Restart");
    // After the session closes the flow card resets to a neutral "Not started" state.
    expect(container?.querySelector("[data-iperf-session-status]")?.textContent).toContain("Not started");
  });

  it("shows one stopped status after the run limit ends a session", async () => {
    await renderIperf();
    await act(async () => {
      buttonWithText("Start iPerf3").click();
    });
    await waitFor(() => FakeWebSocket.instances.length === 1);

    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "closed", close_reason: "run_limit", at: 1780334186 });
    });

    expect(container?.textContent?.match(/Stopped/g)).toHaveLength(1);
    expect(container?.textContent).not.toContain("Run limit reached");
    expect(container?.textContent).toContain("completed: run_limit");
    expect(container?.querySelector("input[aria-label='iPerf3 client command']")).toBeNull();
    expect(container?.querySelector("[data-iperf-command-action]")?.textContent).toContain("Restart");
  });

  it("updates the status card when a client run is cancelled before session close", async () => {
    await renderIperf();
    await act(async () => {
      buttonWithText("Start iPerf3").click();
    });
    await waitFor(() => FakeWebSocket.instances.length === 1);

    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "output", line: "cancelled: the client has terminated" });
    });

    const status = container?.querySelector("[data-iperf-session-status]");
    // The session stays open after a single run is cancelled, so the card reads "Listening";
    // no flow event arrived, so direction stays neutral.
    expect(status?.textContent).toContain("Listening");
    expect(container?.querySelector("[data-iperf-direction-status]")?.textContent).toContain("--");
  });

  it("closes the agent session if the event websocket drops before a closed event", async () => {
    await renderIperf();
    await act(async () => {
      buttonWithText("Start iPerf3").click();
    });
    await waitFor(() => FakeWebSocket.instances.length === 1);

    await act(async () => {
      FakeWebSocket.instances[0].close();
    });
    await waitFor(() => {
      const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls;
      return calls.some(([path]) => path === "/api/iperf/session/close");
    });

    const closeCall = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.find(([path]) => path === "/api/iperf/session/close");
    expect(JSON.parse(String(closeCall?.[1]?.body))).toEqual({ node: "testnode01", session_id: "ipf_123" });
    expect(container?.querySelector("input[aria-label='iPerf3 client command']")).toBeNull();
    expect(container?.textContent).toContain("event stream closed; session closed");
  });

  it("keeps a single visible close line when stopping a live session", async () => {
    await renderIperf();
    await act(async () => {
      buttonWithText("Start iPerf3").click();
    });
    await waitFor(() => FakeWebSocket.instances.length === 1);

    await act(async () => {
      buttonWithText("Stop").click();
    });
    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "closed", close_reason: "closed_by_request", at: 1780334186 });
    });

    const terminal = container?.querySelector("[data-iperf-terminal] pre");
    const visibleCloseLines = terminal?.textContent?.match(/cancelled: closed_by_request/g) || [];
    expect(visibleCloseLines).toHaveLength(1);
    expect(container?.querySelector("input[aria-label='iPerf3 client command']")).toBeNull();
    expect(container?.textContent).toContain("cancelled: closed_by_request");
  });

  it("keeps command generator pill choices editable after start", async () => {
    await renderIperf();
    expect(container?.querySelector("[data-iperf-command-generator]")?.textContent).toContain("Command generator");
    expect(container?.querySelector("[data-iperf-command-generator]")?.textContent).toContain("Protocol");
    expect(container?.querySelector("[data-iperf-command-generator]")?.textContent).toContain("Direction");
    expect(container?.querySelector("[data-iperf-command-generator]")?.textContent).toContain("Limits");
    expect((container?.querySelector("input[aria-label='iPerf3 client command']") as HTMLInputElement | null)?.value).toBe(
      "iperf3 -c 203.0.113.9",
    );

    await act(async () => {
      buttonWithText("Start iPerf3").click();
    });
    await waitFor(() => FakeWebSocket.instances.length === 1);

    // Host + Protocol + Direction stay inline; Time/Parallel live in the limits popover.
    const options = Array.from(container?.querySelectorAll("[data-iperf-generator-option]") || []) as HTMLButtonElement[];
    expect(options).toHaveLength(6);
    for (const option of options) {
      expect(option.disabled).toBe(false);
    }
    // The limits trigger shares the same editable state and names its visible summary.
    const limitsButton = container?.querySelector("[aria-label^='iPerf3 limits']") as HTMLButtonElement | null;
    expect(limitsButton?.getAttribute("aria-label")).toContain("10s · 1 stream");
    expect(limitsButton?.disabled).toBe(false);
    expect((container?.querySelector("input[aria-label='iPerf3 client command']") as HTMLInputElement | null)?.value).toBe(
      "iperf3 -c 203.0.113.9 -p 32657",
    );
    const status = container?.querySelector("[data-iperf-session-status]");
    const protocol = container?.querySelector("[data-iperf-protocol-status]");
    const direction = container?.querySelector("[data-iperf-direction-status]");
    // Session open, no client connected yet: "Listening", neutral direction/protocol.
    expect(status?.textContent).toContain("Listening");
    expect(direction?.textContent).toContain("--");
    expect(status?.textContent).not.toContain("udp");
    expect(protocol?.textContent).toContain("--");

    await act(async () => {
      FakeWebSocket.instances[0].emit({
        type: "status",
        command: "iperf3 -u -c testnode01.lgtest-node.example -p 32657 -R",
        remaining_seconds: 121,
        remaining_runs: 4,
      });
    });

    // A command without an explicit mode does not establish a flow.
    expect(direction?.textContent).toContain("--");
    expect(status?.textContent).not.toContain("udp");
    expect(protocol?.textContent).toContain("--");

    // A client connects (server output) — the flow is live once a mode is known.
    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "output", line: "accepted connection from 203.0.113.10, port 50000" });
    });

    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "status", mode: "udp", reverse: true, remaining_seconds: 120, remaining_runs: 3 });
    });

    // reverse → the server streams to you (download).
    expect(status?.textContent).toContain("Running");
    expect(protocol?.textContent).toContain("udp");
    expect(direction?.textContent).toContain("server to you");

    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "status", mode: "tcp", reverse: false, remaining_seconds: 119, remaining_runs: 3 });
    });

    expect(protocol?.textContent).toContain("tcp");
    expect(direction?.textContent).toContain("you to server");

    await act(async () => {
      FakeWebSocket.instances[0].emit({ type: "closed", close_reason: "closed_by_request", at: 1780334186 });
    });

    // Session closed → card resets to "Not started"; no lingering protocol.
    expect(status?.textContent).toContain("Not started");
    expect(protocol?.textContent).toContain("--");
  });
});
