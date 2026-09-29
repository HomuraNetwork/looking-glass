import { describe, expect, it, vi } from "vitest";
import { agentJobWebSocketTarget, LiveJobSlot, liveJobCommandDisplay, liveJobControlFrame, mtrHeaderFrame, mtrHeaderLines, mtrReplaceFrameForLine } from "../src/job-proxy";

describe("agent job websocket target", () => {
  it("keeps the configured connection port out of the agent-accepted Origin", () => {
    const target = agentJobWebSocketTarget("node.example", 8443, "token/with-slash");
    expect(target.url.href).toBe("https://node.example:8443/jobs/token%2Fwith-slash/ws");
    expect(target.headers).toEqual({ upgrade: "websocket", origin: "https://node.example" });
  });
});

describe("live job proxy display frames", () => {
  it("serializes the completion control frame so it is never rendered", () => {
    expect(JSON.parse(liveJobControlFrame("complete"))).toEqual({ stream: "control", event: "complete" });
  });
  it("generates the visible command server-side for frontend-resolved DNS", () => {
    expect(
      liveJobCommandDisplay({
        tool: "ping",
        target: "1.1.1.1",
        ipver: "ipv4",
        count: 10,
        remoteDNS: false,
        originalTarget: "one.one.one.one",
      }),
    ).toBe("ping -4 -O -c 10 -W 2 1.1.1.1 # one.one.one.one");
  });

  it("renders mtr without count mode", () => {
    expect(
      liveJobCommandDisplay({
        tool: "mtr",
        target: "one.one.one.one",
        ipver: "ipv6",
        count: 5,
        remoteDNS: true,
      }),
    ).toBe("mtr -6 --split one.one.one.one");
  });

  it("parses real mtr --split -n -z hop rows into structured fields", () => {
    // The agent runs `mtr --split -n -z`, so a hop line is
    // "<hop>. <AS>  <ip>  <loss%> <snt> <last> <avg> <best> <wrst> <stdev>".
    expect(mtrReplaceFrameForLine("  8. AS15169  192.0.2.91        0.0%     2   55.0  54.3  53.7  55.0   0.9")).toEqual({
      stream: "stdout",
      mode: "replace",
      key: "mtr-hop-8",
      line: "AS15169 192.0.2.91 0.0% 2 55.0 54.3 53.7 55.0",
      kind: "mtr",
      hop: 8,
      mtr: {
        hop: 8,
        asn: "AS15169",
        host: "192.0.2.91",
        loss: "0.0%",
        snt: "2",
        last: "55.0",
        avg: "54.3",
        best: "53.7",
        wrst: "55.0",
      },
    });
    // Unresolved AS and unreachable hop.
    expect(mtrReplaceFrameForLine("  1. AS???    127.0.0.1            0.0%     2    0.1   0.1   0.0   0.1   0.0")?.mtr).toMatchObject({
      hop: 1,
      asn: "AS???",
      host: "127.0.0.1",
    });
    // Legacy format (no -n/-z) still parses, with no ASN column.
    expect(mtrReplaceFrameForLine("  1.|-- localhost                  0.0%     2    0.1   0.1   0.1   0.1   0.0")?.mtr).toMatchObject({
      hop: 1,
      asn: "",
      host: "localhost",
    });
    // traceroute hop lines must NOT be mistaken for mtr.
    expect(mtrReplaceFrameForLine(" 1  192.168.1.1 (192.168.1.1)  0.500 ms  0.400 ms  0.380 ms")).toBeNull();
  });

  it("parses bare-hop rows with integer loss (the regression)", () => {
    // A real mtr build emits "hop host loss snt ..." with no dot after the hop
    // and a bare integer loss. The parser used to require "1." so these rows
    // were dropped, no replace frame was emitted, and every split cycle
    // appended a fresh copy of the table.
    expect(mtrReplaceFrameForLine("1 203.0.113.1 0 1 1 0 0 0")).toEqual({
      stream: "stdout",
      mode: "replace",
      key: "mtr-hop-1",
      line: "203.0.113.1 0.0% 1 1 0 0 0",
      kind: "mtr",
      hop: 1,
      mtr: {
        hop: 1,
        asn: "",
        host: "203.0.113.1",
        loss: "0.0%",
        snt: "1",
        last: "1",
        avg: "0",
        best: "0",
        wrst: "0",
      },
    });
    // A later cycle for the same hop updates in place (same key).
    expect(mtrReplaceFrameForLine("2 192.0.2.24 0 12 12 0 0 1")?.mtr).toMatchObject({
      hop: 2,
      host: "192.0.2.24",
      loss: "0.0%",
      snt: "12",
      last: "12",
      wrst: "1",
    });
    // A hop that skips ahead keeps its own number, so the client can hold gaps.
    expect(mtrReplaceFrameForLine("12 192.0.2.197 0 8 8 1 1 3")?.hop).toBe(12);
    // Bracketed labels parse too.
    expect(mtrReplaceFrameForLine("[3] 192.0.2.221 0.0% 4 4 4 4 4")?.mtr).toMatchObject({ hop: 3, host: "192.0.2.221" });
    // ppm-style loss normalizes to a percentage.
    expect(mtrReplaceFrameForLine("3 cloudflare-sgp.example 50000 5 5 0 7 24")?.mtr).toMatchObject({ hop: 3, loss: "50.0%" });
  });

  it("renders the AS column in an MTR header replace frame", () => {
    expect(mtrHeaderLines()).toEqual([
      "Hop  AS        Host                             Loss%   Snt   Last   Avg  Best  Wrst",
    ]);
    expect(mtrHeaderFrame()).toMatchObject({ stream: "stdout", mode: "replace", key: "mtr-header", kind: "mtr-header" });
  });

  it("replaces an active agent websocket when the browser sends another live command", () => {
    const first = { close: vi.fn() } as unknown as WebSocket;
    const second = { close: vi.fn() } as unknown as WebSocket;
    const slot = new LiveJobSlot();

    const firstRun = slot.next();
    expect(firstRun.replaced).toBe(false);
    expect(slot.setAgent(firstRun.id, first)).toBe(true);

    const secondRun = slot.next();
    expect(secondRun.replaced).toBe(true);
    expect(first.close).toHaveBeenCalledWith(1000, "replaced");
    expect(slot.isCurrent(firstRun.id)).toBe(false);
    expect(slot.setAgent(secondRun.id, second)).toBe(true);

    slot.clear(firstRun.id);
    expect(slot.isCurrent(secondRun.id)).toBe(true);
  });

  it("invalidates an in-flight generation when the browser disconnects", () => {
    const agent = { close: vi.fn() } as unknown as WebSocket;
    const slot = new LiveJobSlot();
    const run = slot.next();
    expect(slot.setAgent(run.id, agent)).toBe(true);
    slot.closeActive();
    expect(agent.close).toHaveBeenCalled();
    expect(slot.isCurrent(run.id)).toBe(false);
    expect(slot.setAgent(run.id, { close: vi.fn() } as unknown as WebSocket)).toBe(false);
  });
});
