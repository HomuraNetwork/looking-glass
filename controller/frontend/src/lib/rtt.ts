import { useEffect, useState } from "react";
import type { PublicNode } from "./api";

export interface RttSeries {
  key: string;
  label: string;
  color: string;
  samples: RttSample[];
  dashed?: boolean;
}

export type RttSample = number | null;
export interface ChartPoint { x: number; y: number; }
type RttFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export const NODE_RTT_SAMPLES = 5;

export interface NodeProbeState {
  samples: RttSample[];
  usable: boolean;
}

export interface NodeRttStats {
  latest: RttSample;
  best: number;
  worst: number;
  avg: number;
  count: number;
}

export type NodeRttMap = Record<string, { v4: NodeProbeState; v6: NodeProbeState }>;

export function nodeProbeURL(node: PublicNode, family: "ipv4" | "ipv6"): string | null {
  if (family === "ipv6") {
    if (node.has_ipv6 === false || !node.domain_v6) return null;
    return `https://${node.domain_v6}/generate_204`;
  }
  if (node.has_ipv4 === false) return null;
  const host = node.domain_v4 || node.domain;
  return host ? `https://${host}/generate_204` : null;
}

export const RTT_HIDE_FIRST_STORAGE_KEY = "lg-rtt-hide-first";

export function getRttHideFirstSample(): boolean {
  try {
    const stored = localStorage.getItem(RTT_HIDE_FIRST_STORAGE_KEY);
    return stored !== null ? stored === "true" : true;
  } catch {
    return true;
  }
}

export function setRttHideFirstSample(hide: boolean): void {
  try {
    localStorage.setItem(RTT_HIDE_FIRST_STORAGE_KEY, String(hide));
  } catch {
    // ignore
  }
}

export function nodeRttStats(
  samples: RttSample[],
  options?: { ignoreFirst?: boolean },
): NodeRttStats | null {
  const ignoreFirst = options?.ignoreFirst ?? getRttHideFirstSample();
  const effectiveSamples = ignoreFirst && samples.length > 1 ? samples.slice(1) : samples;
  const ok = effectiveSamples.filter((sample): sample is number => typeof sample === "number");
  if (ok.length === 0) return null;
  const latest = [...effectiveSamples].reverse().find((sample): sample is number => typeof sample === "number") ?? null;
  return {
    latest,
    best: Math.min(...ok),
    worst: Math.max(...ok),
    avg: Math.round(ok.reduce((sum, value) => sum + value, 0) / ok.length),
    count: ok.length,
  };
}

export const PROBE_CONCURRENCY = 6;

export async function runWithConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;
  const concurrency = Math.max(1, Math.min(limit, items.length));
  let index = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (index < items.length) {
      const i = index++;
      await fn(items[i]);
    }
  });
  await Promise.all(workers);
}

export function useNodesRtt(nodes: PublicNode[]): { results: NodeRttMap; running: boolean } {
  const [results, setResults] = useState<NodeRttMap>({});
  const [running, setRunning] = useState(false);
  const key = nodes.map((node) => `${node.id}:${node.domain_v4 ?? ""}:${node.domain_v6 ?? ""}`).join("|");

  useEffect(() => {
    if (nodes.length === 0) {
      setResults({});
      setRunning(false);
      return;
    }
    const init: NodeRttMap = {};
    const targets: Array<{ nodeId: string; slot: "v4" | "v6"; url: string }> = [];
    for (const node of nodes) {
      const v4Url = nodeProbeURL(node, "ipv4");
      const v6Url = nodeProbeURL(node, "ipv6");
      init[node.id] = {
        v4: { samples: [], usable: v4Url !== null },
        v6: { samples: [], usable: v6Url !== null },
      };
      if (v4Url) targets.push({ nodeId: node.id, slot: "v4", url: v4Url });
      if (v6Url) targets.push({ nodeId: node.id, slot: "v6", url: v6Url });
    }
    setResults(init);
    if (targets.length === 0) {
      setRunning(false);
      return;
    }

    let cancelled = false;
    const controller = new AbortController();
    setRunning(true);
    (async () => {
      for (let round = 0; round < NODE_RTT_SAMPLES; round++) {
        if (cancelled) return;
        await runWithConcurrency(targets, PROBE_CONCURRENCY, async (target) => {
          if (cancelled) return;
          const timeout = round === 0 ? 2500 : 3500;
          const ms = await measureRtt(target.url, fetch, () => performance.now(), timeout, controller.signal);
          if (cancelled) return;
          setResults((prev) => {
            const current = prev[target.nodeId];
            if (!current) return prev;
            return {
              ...prev,
              [target.nodeId]: {
                ...current,
                [target.slot]: {
                  ...current[target.slot],
                  samples: [...current[target.slot].samples, ms],
                },
              },
            };
          });
        });
        if (round < NODE_RTT_SAMPLES - 1 && !cancelled) {
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
      }
      if (!cancelled) setRunning(false);
    })();
    return () => {
      cancelled = true;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return { results, running };
}

export function seriesToPoints(
  samples: number[],
  maxMs: number,
  width: number,
  height: number,
): ChartPoint[] {
  return samples.map((ms, i) => ({
    x: samples.length <= 1 ? width / 2 : (i / (samples.length - 1)) * width,
    y: height - (ms / maxMs) * height,
  }));
}

export function pointsToPolyline(points: ChartPoint[]): string {
  return points.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
}

export function seriesToPointSegments(
  samples: RttSample[],
  maxMs: number,
  width: number,
  height: number,
): ChartPoint[][] {
  const segments: ChartPoint[][] = [];
  let segment: ChartPoint[] = [];
  samples.forEach((sample, i) => {
    if (typeof sample !== "number" || !Number.isFinite(sample)) {
      if (segment.length > 0) segments.push(segment);
      segment = [];
      return;
    }
    segment.push({
      x: samples.length <= 1 ? width / 2 : (i / (samples.length - 1)) * width,
      y: height - (sample / maxMs) * height,
    });
  });
  if (segment.length > 0) segments.push(segment);
  return segments;
}

export function maxAcrossSeries(series: RttSeries[]): number {
  const flat = series.flatMap((s) => s.samples.filter((sample): sample is number => typeof sample === "number"));
  return Math.max(20, ...flat);
}

export async function measureRtt(
  url: string,
  fetchImpl: RttFetch = fetch,
  now: () => number = () => performance.now(),
  timeoutMs = 3500,
  signal?: AbortSignal,
): Promise<RttSample> {
  const controller = new AbortController();
  const started = now();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  signal?.addEventListener("abort", abort, { once: true });
  try {
    await fetchImpl(url, {
      cache: "no-store",
      mode: "no-cors",
      signal: controller.signal,
    });
    return Math.max(0, Math.round(now() - started));
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}
