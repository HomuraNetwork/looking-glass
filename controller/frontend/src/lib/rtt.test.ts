// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import {
  getRttHideFirstSample,
  maxAcrossSeries,
  measureRtt,
  nodeRttStats,
  runWithConcurrency,
  seriesToPointSegments,
  seriesToPoints,
  setRttHideFirstSample,
} from "./rtt";

describe("seriesToPoints", () => {
  it("maps samples across width and RTT values across chart height", () => {
    const pts = seriesToPoints([0, 50, 100], 100, 200, 100);
    expect(pts[0].x).toBe(0);
    expect(pts[2].x).toBe(200);
    expect(pts[1].x).toBe(100);
    expect(pts[0].y).toBe(100);
    expect(pts[2].y).toBe(0);
    const zero = seriesToPoints([0], 100, 200, 100);
    expect(zero[0].y).toBe(100);
  });
});

describe("maxAcrossSeries", () => {
  it("uses the chart minimum and ignores failures when finding the maximum", () => {
    expect(maxAcrossSeries([{ key: "a", label: "", color: "", samples: [1, null] }])).toBe(20);
    expect(maxAcrossSeries([{ key: "a", label: "", color: "", samples: [null, 7, null] }])).toBe(20);
    const result = maxAcrossSeries([
      { key: "a", label: "", color: "", samples: [10, 50] },
      { key: "b", label: "", color: "", samples: [5, 80] },
    ]);
    expect(result).toBe(80);
  });
});

describe("seriesToPointSegments", () => {
  it("breaks chart lines around failed RTT samples", () => {
    const segments = seriesToPointSegments([10, 20, null, 40, 50], 50, 400, 100);
    expect(segments).toHaveLength(2);
    expect(segments[0]).toHaveLength(2);
    expect(segments[1]).toHaveLength(2);
    expect(segments[1][0].x).toBe(300);
  });
});

describe("measureRtt", () => {
  it("returns null when the probe request fails", async () => {
    const sample = await measureRtt(
      "https://unreachable.example/generate_204",
      async () => { throw new TypeError("network failed"); },
      () => 100,
    );
    expect(sample).toBeNull();
  });

  it("returns elapsed milliseconds when the probe request resolves", async () => {
    let now = 100;
    const sample = await measureRtt(
      "https://probe.example/generate_204",
      async () => {
        now = 137;
        return new Response(null, { status: 204 });
      },
      () => now,
    );
    expect(sample).toBe(37);
  });
});

describe("runWithConcurrency", () => {
  it("processes all items without exceeding limit", async () => {
    const items = [1, 2, 3, 4, 5, 6, 7, 8];
    let active = 0;
    let maxActive = 0;
    const processed: number[] = [];

    await runWithConcurrency(items, 3, async (item) => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 10));
      processed.push(item);
      active--;
    });

    expect(processed.sort((a, b) => a - b)).toEqual(items);
    expect(maxActive).toBeLessThanOrEqual(3);
  });

});

describe("nodeRttStats", () => {
  it("returns null for empty samples", () => {
    expect(nodeRttStats([])).toBeNull();
    expect(nodeRttStats([null, null])).toBeNull();
  });

  it("calculates stats ignoring first sample by default when sampleCount > 1", () => {
    // 250 is the cold start; 20, 22, 24 are warm samples
    const stats = nodeRttStats([250, 20, 22, 24], { ignoreFirst: true });
    expect(stats).not.toBeNull();
    expect(stats?.best).toBe(20);
    expect(stats?.worst).toBe(24);
    expect(stats?.avg).toBe(22);
    expect(stats?.count).toBe(3);
  });

  it("includes all samples when ignoreFirst is disabled", () => {
    const stats = nodeRttStats([250, 20, 22, 24], { ignoreFirst: false });
    expect(stats?.worst).toBe(250);
    expect(stats?.count).toBe(4);
  });

  it("uses the single sample when length is 1", () => {
    const stats = nodeRttStats([100]);
    expect(stats?.best).toBe(100);
    expect(stats?.worst).toBe(100);
    expect(stats?.count).toBe(1);
  });
});

describe("getRttHideFirstSample / setRttHideFirstSample", () => {
  it("defaults to true and allows toggling", () => {
    expect(getRttHideFirstSample()).toBe(true);
    setRttHideFirstSample(false);
    expect(getRttHideFirstSample()).toBe(false);
    setRttHideFirstSample(true);
    expect(getRttHideFirstSample()).toBe(true);
  });
});
