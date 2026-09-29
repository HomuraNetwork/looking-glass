import { memo, useMemo, useState } from "react";
import { maxAcrossSeries, pointsToPolyline, seriesToPointSegments, type RttSample, type RttSeries } from "@/lib/rtt";
import { cn } from "@/lib/utils";

interface Props {
  series: RttSeries[];
  hiddenKeys?: Set<string>;
  vw?: number;
  vh?: number;
}

const EMPTY_SET = new Set<string>();

export function sampleIndexFromPointer(x: number, width: number, sampleCount: number): number {
  if (sampleCount <= 1 || width <= 0) return 0;
  const clamped = Math.min(width, Math.max(0, x));
  return Math.min(sampleCount - 1, Math.max(0, Math.round((clamped / width) * (sampleCount - 1))));
}

export const RttChart = memo(function RttChart({ series, hiddenKeys = EMPTY_SET, vw = 500, vh = 100 }: Props) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const visibleSeries = useMemo(() => series.filter((entry) => !hiddenKeys.has(entry.key)), [series, hiddenKeys]);
  const viewWidth = Math.max(vw, 240);
  const viewHeight = Math.max(vh, 120);
  const maxMs = maxAcrossSeries(visibleSeries);
  const maxSamples = Math.max(0, ...visibleSeries.map((entry) => entry.samples.length));
  const hoverPct = hoverIndex !== null && maxSamples > 0
    ? maxSamples <= 1 ? 50 : (hoverIndex / (maxSamples - 1)) * 100
    : 0;
  const hoverValues = hoverIndex === null
    ? []
    : visibleSeries
      .map((entry) => ({ ...entry, value: entry.samples[hoverIndex] }))
      .filter((entry): entry is RttSeries & { value: RttSample } => entry.value !== undefined);
  const ticks = [1, 0.75, 0.5, 0.25, 0];
  const xTicks = buildSampleTicks(maxSamples);

  return (
    <div className="relative h-full min-h-[15rem] min-w-0" aria-live="polite">
      {visibleSeries.length === 0 ? (
        <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
          All RTT series are hidden.
        </div>
      ) : (
        <div className="grid h-full grid-cols-[2.75rem_minmax(0,1fr)] grid-rows-[minmax(0,1fr)_1.5rem] gap-x-2 sm:grid-cols-[3.5rem_minmax(0,1fr)]">
          <div className="flex flex-col justify-between py-1 text-right">
            {ticks.map((tick) => (
              <span key={tick} className="font-mono text-xs leading-none text-muted-foreground">
                {tick === 0 ? "0" : `${Math.round(tick * maxMs)}ms`}
              </span>
            ))}
          </div>

          <div className="relative overflow-hidden rounded-md bg-muted/20">
            <svg
              viewBox={`0 0 ${viewWidth} ${viewHeight}`}
              className="absolute inset-0 size-full"
              preserveAspectRatio="none"
              role="img"
              aria-label={rttChartAriaLabel(visibleSeries)}
              onPointerMove={(event) => {
                const rect = event.currentTarget.getBoundingClientRect();
                setHoverIndex(sampleIndexFromPointer(event.clientX - rect.left, rect.width, maxSamples));
              }}
              onPointerLeave={() => setHoverIndex(null)}
            >
              {ticks.map((tick) => {
                const y = (1 - tick) * viewHeight;
                return (
                  <line
                    key={tick}
                    x1={0}
                    y1={y}
                    x2={viewWidth}
                    y2={y}
                    stroke="currentColor"
                    strokeWidth={0.75}
                    strokeOpacity={0.13}
                    vectorEffect="non-scaling-stroke"
                  />
                );
              })}

              {visibleSeries.map((entry) => {
                if (entry.samples.length === 0) return null;
                const segments = seriesToPointSegments(entry.samples, maxMs, viewWidth, viewHeight);
                return (
                  <g key={entry.key}>
                    {segments.map((segment, index) => (
                      segment.length > 1 ? (
                      <polyline
                        key={index}
                        points={pointsToPolyline(segment)}
                        fill="none"
                        stroke={entry.color}
                        strokeWidth={2.25}
                        strokeLinejoin="round"
                        strokeLinecap="round"
                        strokeDasharray={entry.dashed ? "6 4" : undefined}
                        vectorEffect="non-scaling-stroke"
                      />
                      ) : null
                    ))}
                  </g>
                );
              })}

              {hoverIndex !== null && (
                <line
                  x1={(hoverPct / 100) * viewWidth}
                  y1={0}
                  x2={(hoverPct / 100) * viewWidth}
                  y2={viewHeight}
                  stroke="currentColor"
                  strokeWidth={1}
                  strokeOpacity={0.35}
                  vectorEffect="non-scaling-stroke"
                />
              )}
            </svg>

            {visibleSeries.map((entry) => (
              entry.samples.map((sample, index) => {
                if (typeof sample !== "number") return null;
                const left = entry.samples.length <= 1 ? 50 : (index / (entry.samples.length - 1)) * 100;
                const top = 100 - (sample / maxMs) * 100;
                const active = hoverIndex === index;
                return (
                  <span
                    key={`${entry.key}:${index}`}
                    className={cn(
                      "pointer-events-none absolute rounded-full transition-transform",
                      active ? "size-2.5" : "size-2",
                    )}
                    style={{
                      left: `${left}%`,
                      top: `${top}%`,
                      background: entry.color,
                      transform: "translate(-50%, -50%)",
                    }}
                  />
                );
              })
            ))}

            {hoverValues.length > 0 && (
              <div
                className="pointer-events-none absolute top-2 z-10 w-64 max-w-[calc(100%-1rem)] rounded-md border bg-card p-2 text-sm text-card-foreground opacity-100 shadow-xl ring-1 ring-border"
                style={{
                  left: `${hoverPct}%`,
                  transform: hoverPct > 62 ? "translateX(calc(-100% - 0.5rem))" : "translateX(0.5rem)",
                }}
              >
                <div className="mb-1.5 font-mono font-bold">sample {Number(hoverIndex) + 1}</div>
                <div className="flex flex-col gap-1">
                  {hoverValues.map((entry) => (
                    <div key={entry.key} className="flex min-w-0 items-center gap-2">
                      <span className="h-2 w-3.5 flex-shrink-0 rounded-full" style={{ background: entry.color }} />
                      <span className="min-w-0 truncate">{entry.label}</span>
                      <span className="ml-auto font-mono">
                        {typeof entry.value === "number" ? `${entry.value}ms` : "failed"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="col-start-2 row-start-2 flex justify-between pt-1">
            {xTicks.map((sampleNumber) => (
              <span key={sampleNumber} className="font-mono text-xs leading-none text-muted-foreground">
                {sampleNumber}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
});

export function buildSampleTicks(sampleCount: number): number[] {
  if (sampleCount <= 0) return [1, 4, 8];
  if (sampleCount <= 3) return Array.from({ length: sampleCount }, (_, index) => index + 1);
  const middle = Math.max(2, Math.round(sampleCount / 2));
  return Array.from(new Set([1, middle, sampleCount]));
}

function rttChartAriaLabel(series: RttSeries[]): string {
  const latest = series
    .map((entry) => {
      const sample = [...entry.samples].reverse().find((value) => value !== undefined);
      return `${entry.label}: ${typeof sample === "number" ? `${sample}ms` : "failed"}`;
    })
    .join(", ");
  return latest ? `RTT probe chart. Latest samples: ${latest}` : "RTT probe chart";
}
