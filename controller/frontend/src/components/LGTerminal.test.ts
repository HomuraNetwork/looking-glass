import { describe, expect, it } from "vitest";
import {
  applyLiveJobFrame,
  buildLiveJobPayload,
  getMtrLatencyColor,
  getMtrLossColor,
  isJobFinishedOutput,
  isJobStopLine,
  liveSessionUsable,
  parseLiveJobFrame,
  type LiveSessionState,
} from "./LGTerminal";

describe("live job websocket frame parsing", () => {
  it("routes structured debug frames away from terminal stdout", () => {
    expect(parseLiveJobFrame(JSON.stringify({ stream: "debug", line: "command closed" }))).toEqual({
      stream: "debug",
      line: "command closed",
    });
  });

  it("identifies final command completion lines to reset terminal to idle", () => {
    expect(isJobFinishedOutput("command closed")).toBe(true);
    expect(isJobFinishedOutput("5 packets transmitted, 5 received, 0% packet loss")).toBe(true);
    expect(isJobFinishedOutput("rtt min/avg/max/mdev = 1.1/2.2/3.3/0.4 ms")).toBe(true);
    expect(isJobFinishedOutput("round-trip min/avg/max/stddev = 1.1/2.2/3.3/0.4 ms")).toBe(true);
    expect(isJobFinishedOutput("Map trace: https://traceroute.net/12345")).toBe(true);
    expect(isJobFinishedOutput("error: command_rate_limited")).toBe(true);
    expect(isJobFinishedOutput("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=1.23 ms")).toBe(false);
    expect(isJobFinishedOutput("1  edge01 (192.0.2.1) 1.234 ms")).toBe(false);
  });

  it("treats a worker target-guard stop as a finished, error-styled line", () => {
    const stop = "stopped: worker DNS safety check found no usable public address";
    expect(isJobFinishedOutput(stop)).toBe(true);
    expect(isJobStopLine(stop)).toBe(true);

    expect(isJobStopLine("stopped: target is not a valid domain or IP")).toBe(true);
    expect(isJobStopLine("frontend dns: example.com")).toBe(false);
    expect(isJobStopLine("1  edge01 (192.0.2.1) 1.234 ms")).toBe(false);
  });

  it("parses control frames and never renders them", () => {
    const frame = parseLiveJobFrame(JSON.stringify({ stream: "control", event: "complete" }));
    expect(frame).toEqual({ stream: "control", line: "", event: "complete" });
    expect(applyLiveJobFrame([{ text: "existing" }], frame)).toEqual([{ text: "existing" }]);
  });

  it("parses command and replace frames for terminal rendering", () => {
    expect(parseLiveJobFrame(JSON.stringify({ stream: "stdout", mode: "command", line: "$ ping -4 1.1.1.1 -c 5" }))).toEqual({
      stream: "stdout",
      mode: "command",
      line: "$ ping -4 1.1.1.1 -c 5",
    });
    expect(parseLiveJobFrame(JSON.stringify({ stream: "stdout", mode: "replace", key: "mtr-hop-1", line: "[1] edge 1.20 ms" }))).toEqual({
      stream: "stdout",
      mode: "replace",
      key: "mtr-hop-1",
      line: "[1] edge 1.20 ms",
    });
  });

  it("keeps legacy plain text frames as stdout", () => {
    expect(parseLiveJobFrame("[1] 1.1.1.1 0.80 ms")).toEqual({
      stream: "stdout",
      line: "[1] 1.1.1.1 0.80 ms",
    });
  });

  it("requires an explicit frontend DNS selection when remote DNS is off", () => {
    expect(buildLiveJobPayload({ tool: "ping", target: "example.com", ipver: "ipv4", remoteDNS: false })).toBeNull();
    expect(
      buildLiveJobPayload({ tool: "ping", target: "example.com", ipver: "ipv4", remoteDNS: false, selectedAddress: "192.0.2.34" }),
    ).toMatchObject({
      target: "192.0.2.34",
      remote_dns: false,
    });
  });

  it("passes hostnames through unchanged when remote DNS is on", () => {
    expect(
      buildLiveJobPayload({ tool: "ping", target: "example.com", ipver: "ipv4", count: 10, remoteDNS: true, selectedAddress: "192.0.2.34" }),
    ).toMatchObject({
      target: "example.com",
      count: 10,
      remote_dns: true,
    });
  });

  it("defaults unsupported counts to five", () => {
    expect(buildLiveJobPayload({ tool: "ping", target: "1.1.1.1", ipver: "ipv4", count: 7, remoteDNS: true })).toMatchObject({
      count: 5,
    });
  });

  it("includes original target context so the worker can render the real command", () => {
    expect(
      buildLiveJobPayload({ tool: "ping", target: "example.com", ipver: "ipv4", count: 10, remoteDNS: false, selectedAddress: "192.0.2.34" }),
    ).toMatchObject({
      target: "192.0.2.34",
      original_target: "example.com",
    });
  });

  it("applies command and replacement frames without growing mtr output forever", () => {
    const first = applyLiveJobFrame([], { stream: "stdout", mode: "command", line: "$ mtr -4 --split 1.1.1.1" });
    const second = applyLiveJobFrame(first, { stream: "stdout", mode: "replace", key: "mtr-hop-1", line: "[1] edge 1.00 ms" });
    const third = applyLiveJobFrame(second, { stream: "stdout", mode: "replace", key: "mtr-hop-1", line: "[1] edge 2.00 ms" });

    expect(third.map((line) => line.text)).toEqual(["$ mtr -4 --split 1.1.1.1", "[1] edge 2.00 ms"]);
  });
});

describe("live session token cache", () => {
  const farFuture = Math.floor(Date.now() / 1000) + 1700;
  const nearExpiry = Math.floor(Date.now() / 1000) + 15;

  it("reuses only a fresh session bound to the selected node", () => {
    const session: LiveSessionState = { nodeID: "node-a", token: "session-token", expiresAt: farFuture };
    const cases = [
      { name: "same node with time remaining", cached: session, selectedNode: "node-a", usable: true },
      { name: "different node", cached: session, selectedNode: "node-b", usable: false },
      { name: "no selected node", cached: session, selectedNode: undefined, usable: false },
      { name: "near expiry", cached: { ...session, expiresAt: nearExpiry }, selectedNode: "node-a", usable: false },
      { name: "no cached session", cached: null, selectedNode: "node-a", usable: false },
    ];
    for (const testCase of cases) {
      expect(liveSessionUsable(testCase.cached, testCase.selectedNode), testCase.name).toBe(testCase.usable);
    }
  });
});

describe("MTR color helpers", () => {
  it("returns correct color classes for loss and latencies", () => {
    expect(getMtrLossColor("0.0%")).toContain("text-emerald-400");
    expect(getMtrLossColor("20.0%")).toContain("text-amber-400");
    expect(getMtrLossColor("100.0%")).toContain("text-rose-400");

    expect(getMtrLatencyColor("12.5", "0.0%")).toContain("text-emerald-400");
    expect(getMtrLatencyColor("75.0", "0.0%")).toContain("text-sky-300");
    expect(getMtrLatencyColor("180.0", "0.0%")).toContain("text-amber-300");
    expect(getMtrLatencyColor("-", "100.0%")).toContain("text-slate-500");
    expect(getMtrLatencyColor("???", "0.0%")).toContain("text-slate-500");
  });
});

describe("mtr row ordering", () => {
  const headerFrame = { stream: "stdout" as const, mode: "replace" as const, key: "mtr-header", line: "Hop AS Host Loss% Snt Last Avg Best Wrst", kind: "mtr-header" as const };
  const mk = (hop: number, host = `10.0.0.${hop}`) => ({
    stream: "stdout" as const, mode: "replace" as const, key: `mtr-hop-${hop}`, line: `${hop} ${host}`,
    kind: "mtr" as const, hop,
    mtr: { hop, asn: "AS1", host, loss: "0.0%", snt: "1", last: "1", avg: "1", best: "1", wrst: "1" },
  });

  it("orders, fills, and updates hop rows over a live MTR cycle", () => {
    let lines = applyLiveJobFrame([], headerFrame);
    lines = applyLiveJobFrame(lines, mk(4));
    expect(lines.map((l) => l.key)).toEqual(["mtr-header", "mtr-hop-1", "mtr-hop-2", "mtr-hop-3", "mtr-hop-4"]);
    expect(lines[1].mtr?.host).toBe("???");
    expect(lines[4].mtr?.host).toBe("10.0.0.4");

    lines = applyLiveJobFrame(lines, mk(2, "real-2"));
    lines = applyLiveJobFrame(lines, mk(1));
    expect(lines.map((l) => l.key)).toEqual(["mtr-header", "mtr-hop-1", "mtr-hop-2", "mtr-hop-3", "mtr-hop-4"]);
    expect(lines[1].mtr?.host).toBe("10.0.0.1");
    expect(lines[2].mtr?.host).toBe("real-2");

    lines = applyLiveJobFrame(lines, { ...mk(1), line: " 1. updated", mtr: { ...mk(1).mtr, host: "updated" } });
    expect(lines.map((l) => l.key)).toEqual(["mtr-header", "mtr-hop-1", "mtr-hop-2", "mtr-hop-3", "mtr-hop-4"]);
    expect(lines[1].mtr?.host).toBe("updated");
  });
});
