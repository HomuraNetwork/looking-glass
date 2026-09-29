import { memo, useEffect, useMemo, useRef, useState } from "react";
import { Activity, Check, ChevronsUpDown, Eraser, Play, Square, Network, ExternalLink, Copy, MapPin, X, ShoppingCart } from "lucide-react";
import { type PublicNode, type ClientInfo } from "@/lib/api";
import { getRttHideFirstSample, measureRtt, setRttHideFirstSample, type RttSeries } from "@/lib/rtt";
import { RttChart } from "./RttChart";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Dialog, DialogContent, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

function safeActionHref(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.startsWith("//") || /[\u0000-\u001f\\]/.test(normalized)) return "";
  if (normalized.startsWith("/")) return normalized;
  try {
    const url = new URL(normalized);
    return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.hostname) && !url.username && !url.password
      ? normalized
      : "";
  } catch {
    return "";
  }
}

const NODE_COLORS = ["#2563eb", "#dc2626", "#0891b2", "#9333ea", "#16a34a"];

export interface RttTarget {
  key: string;
  label: string;
  color: string;
  url: string;
  nodeID?: string;
  family?: "ipv4" | "ipv6";
}

export interface NodeInfoPanelProps {
  className?: string;
  selected?: PublicNode;
  clientInfo: ClientInfo | null;
  loading?: boolean;
}

export interface RttProbePopoverProps {
  className?: string;
  nodes: PublicNode[];
  selected?: PublicNode;
  onRttComplete?: (results: Record<string, number>) => void;
}

export function buildRttTargets(nodes: PublicNode[], _selectedID?: string): RttTarget[] {
  const targets: RttTarget[] = [
    { key: "cf", label: "Cloudflare 204", color: "#f97316", url: "https://cp.cloudflare.com/generate_204" },
    { key: "google", label: "Google 204", color: "#4ade80", url: "https://www.google.com/generate_204" },
  ];
  nodes.forEach((node, index) => {
    const nodeLabel = node.display_name || node.id;
    if (node.has_ipv4 !== false && node.domain_v4) {
      targets.push({
        key: `${node.id}:ipv4`,
        label: `${nodeLabel} v4`,
        color: NODE_COLORS[index % NODE_COLORS.length],
        url: `https://${node.domain_v4}/generate_204`,
        nodeID: node.id,
        family: "ipv4",
      });
    }
    if (node.has_ipv6 !== false && node.domain_v6) {
      targets.push({
        key: `${node.id}:ipv6`,
        label: `${nodeLabel} v6`,
        color: NODE_COLORS[(index + 1) % NODE_COLORS.length],
        url: `https://${node.domain_v6}/generate_204`,
        nodeID: node.id,
        family: "ipv6",
      });
    }
  });
  const seen = new Set<string>();
  return targets.filter((target) => {
    if (seen.has(target.url)) return false;
    seen.add(target.url);
    return true;
  });
}

export function defaultRttTargetKeys(targets: RttTarget[]): Set<string> {
  return new Set(targets.filter((target) => target.key === "cf" || target.nodeID).map((target) => target.key));
}

export function RttProbePopover({ className, nodes, selected, onRttComplete }: RttProbePopoverProps) {
  const [rttOpen, setRttOpen] = useState(false);
  const [rttRunning, setRttRunning] = useState(false);
  const [rttSeries, setRttSeries] = useState<RttSeries[]>([]);
  const [selectedTargetKeys, setSelectedTargetKeys] = useState<Set<string>>(new Set());
  const [hiddenKeys, setHiddenKeys] = useState<Set<string>>(new Set());
  const [hideFirstSample, setHideFirstSample] = useState(getRttHideFirstSample);
  const [comboOpen, setComboOpen] = useState(false);
  const abortRef = useRef(false);
  // Invalidates samples from older probe loops.
  const rttRunIDRef = useRef(0);

  function handleToggleHideFirst(checked: boolean) {
    setHideFirstSample(checked);
    setRttHideFirstSample(checked);
  }

  const displaySeries = useMemo(() => {
    if (!hideFirstSample) return rttSeries;
    return rttSeries.map((s) => ({
      ...s,
      samples: s.samples.length > 1 ? s.samples.slice(1) : s.samples,
    }));
  }, [rttSeries, hideFirstSample]);

  const allTargets = buildRttTargets(nodes, selected?.id);
  const effectiveKeys = selectedTargetKeys.size > 0
    ? selectedTargetKeys
    : defaultRttTargetKeys(allTargets);

  const activeTargets = allTargets.filter((t) => effectiveKeys.has(t.key));
  const selectedTargets = allTargets.filter((target) => effectiveKeys.has(target.key));

  function toggleTarget(key: string) {
    // Stop the current probe when its target set changes.
    if (rttRunning) stopRtt();
    setSelectedTargetKeys((prev) => {
      const next = new Set(prev.size === 0 ? allTargets.map((t) => t.key) : prev);
      if (next.has(key)) {
        next.delete(key);
        if (next.size === 0) return new Set();
      } else {
        next.add(key);
      }
      return next;
    });
  }

  async function runRtt() {
    if (rttRunning) return;
    abortRef.current = false;
    const runID = ++rttRunIDRef.current;
    setRttRunning(true);
    setHiddenKeys(new Set());
    const series: RttSeries[] = activeTargets.map((t) => ({
      key: t.key, label: t.label, color: t.color, samples: [],
    }));
    setRttSeries(series.map((s) => ({ ...s })));

    for (let i = 0; i < 20; i++) {
      if (abortRef.current) break;
      for (const target of activeTargets) {
        if (abortRef.current) break;
        const ms = await measureRtt(target.url);
        // A newer run (or Stop) invalidates this loop's samples.
        if (abortRef.current || runID !== rttRunIDRef.current) return;
        const s = series.find((s) => s.key === target.key)!;
        s.samples = [...s.samples, ms];
        setRttSeries(series.map((s) => ({ ...s })));
      }
    }
    if (abortRef.current || runID !== rttRunIDRef.current) return;

    setRttRunning(false);
    const results: Record<string, number> = {};
    const nodeSamples: Record<string, number[]> = {};
    for (const entry of series) {
      const target = activeTargets.find((candidate) => candidate.key === entry.key);
      const effective = hideFirstSample && entry.samples.length > 1 ? entry.samples.slice(1) : entry.samples;
      const successful = effective.filter((sample): sample is number => typeof sample === "number");
      if (target?.nodeID && successful.length > 0) {
        nodeSamples[target.nodeID] = [...(nodeSamples[target.nodeID] || []), ...successful];
      }
    }
    for (const [nodeID, samples] of Object.entries(nodeSamples)) {
      results[nodeID] = Math.round(samples.reduce((a, b) => a + b, 0) / samples.length);
    }
    onRttComplete?.(results);
  }

  function stopRtt() { rttRunIDRef.current++; abortRef.current = true; setRttRunning(false); }
  function clearRtt() { setRttSeries([]); setHiddenKeys(new Set()); }
  function handleOpenChange(open: boolean) {
    setRttOpen(open);
    if (!open) stopRtt();
  }
  function toggleHidden(key: string) {
    setHiddenKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <Dialog open={rttOpen} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button
          size="sm"
          variant="default"
          className={cn(
            "h-7 gap-1 rounded-md px-2.5 text-xs font-semibold shadow-xs transition-all",
            className,
          )}
          aria-label="Open RTT probe"
        >
          <Play className="size-3 fill-current" />
          <span className="hidden lg:inline">Test</span>
          <span className="lg:hidden">Latency</span>
          {rttRunning && <span className="size-1.5 animate-pulse rounded-full bg-white" aria-hidden />}
        </Button>
      </DialogTrigger>
      <DialogContent
        className={cn(
          "flex flex-col gap-0 overflow-hidden rounded-2xl border bg-card p-0 text-card-foreground shadow-2xl",
          "h-[min(34rem,calc(100dvh-2rem))] w-[calc(100vw-1.5rem)] max-w-md",
          "sm:h-[min(42rem,calc(100dvh-3rem))] sm:w-[calc(100vw-3rem)] sm:max-w-3xl",
        )}
      >
        <div className="flex items-center gap-3 border-b bg-muted/30 px-5 py-3.5 pr-12">
          <div className="flex size-7 items-center justify-center rounded-lg border border-primary/25 bg-primary/10 text-primary">
            <Activity className="size-4" />
          </div>
          <div className="min-w-0">
            <DialogTitle className="text-sm font-bold text-foreground">RTT Latency Probe</DialogTitle>
            <p className="text-xs text-muted-foreground">Browser-to-node round-trip measurements</p>
          </div>
          {selected && (
            <span className="ml-auto hidden rounded-md border bg-card px-2 py-0.5 font-mono text-xs font-medium text-muted-foreground sm:inline-block">
              {selected.display_name || selected.id}
            </span>
          )}
        </div>
        <div className="flex min-h-0 flex-1 flex-col gap-3 p-4 sm:p-5">
          <div className="flex flex-wrap items-center justify-between gap-2.5">
            <Popover open={comboOpen} onOpenChange={setComboOpen}>
              <PopoverTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 gap-1.5 rounded-lg border-border/80 bg-background px-2.5 text-xs font-medium"
                  aria-label="Select RTT probe targets"
                >
                  <ChevronsUpDown className="size-3.5 text-muted-foreground" />
                  <span>Select Targets</span>
                  <span className="rounded-full bg-primary/10 px-1.5 py-px font-mono text-[0.625rem] font-bold text-primary">
                    {selectedTargets.length}
                  </span>
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-[min(26rem,calc(100vw-2rem))] overflow-hidden rounded-xl bg-card p-0 text-card-foreground shadow-2xl ring-1 ring-border" align="start" sideOffset={8}>
                <Command className="bg-card text-card-foreground">
                  <CommandInput placeholder="Search probe targets..." className="text-xs" />
                  <CommandList className="max-h-64">
                    <CommandEmpty className="py-3 text-center text-xs text-muted-foreground">
                      No targets found.
                    </CommandEmpty>
                    <CommandGroup>
                      {allTargets.map((target) => {
                        const checked = effectiveKeys.has(target.key);
                        return (
                          <CommandItem
                            key={target.key}
                            value={target.label}
                            onSelect={() => toggleTarget(target.key)}
                            className="gap-2.5 px-3 py-2 text-xs"
                          >
                            <div className={cn(
                              "flex size-4 items-center justify-center rounded border transition-colors",
                              checked ? "border-primary bg-primary text-primary-foreground" : "border-input",
                            )}>
                              {checked && <Check className="size-3" />}
                            </div>
                            <span
                              className="size-2 flex-shrink-0 rounded-full"
                              style={{ background: target.color }}
                            />
                            <span className="min-w-0 truncate font-mono font-medium">{target.label}</span>
                          </CommandItem>
                        );
                      })}
                    </CommandGroup>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>

            <div className="flex flex-wrap items-center gap-2">
              <label className="flex cursor-pointer select-none items-center gap-1.5 rounded-md border border-border/50 bg-muted/20 px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted/40">
                <Switch
                  id="rtt-hide-first"
                  checked={hideFirstSample}
                  onCheckedChange={handleToggleHideFirst}
                  className="scale-[0.65]"
                  aria-label="Omit initial warm-up probe"
                />
                <span className="whitespace-nowrap text-[0.6875rem] font-medium text-foreground">Omit 1st</span>
              </label>

              {rttRunning ? (
                <Button size="sm" variant="destructive" className="h-8 gap-1.5 rounded-lg px-3.5 text-xs font-semibold shadow-xs" onClick={stopRtt}>
                  <Square className="size-3 fill-current" /> Stop
                </Button>
              ) : (
                <Button size="sm" variant="default" className="h-8 gap-1.5 rounded-lg px-3.5 text-xs font-semibold shadow-xs" onClick={runRtt} disabled={activeTargets.length === 0}>
                  <Play className="size-3 fill-current" /> Run Probe
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                className="h-8 gap-1 rounded-lg px-2 text-xs font-medium text-muted-foreground hover:text-foreground"
                onClick={clearRtt}
                disabled={rttRunning || rttSeries.length === 0}
                aria-label="Clear RTT results"
              >
                <Eraser className="size-3.5" /> Clear
              </Button>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-border/60 bg-muted/15 p-2">
            <span className="mr-1 text-[0.6875rem] font-semibold text-muted-foreground">Selected:</span>
            {selectedTargets.length > 0 ? (
              selectedTargets.map((target) => {
                const series = displaySeries.find((s) => s.key === target.key);
                const latest = series ? [...series.samples].reverse().find((value): value is number => typeof value === "number") : undefined;
                const hidden = hiddenKeys.has(target.key);
                return (
                  <span
                    key={target.key}
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[0.6875rem] font-medium shadow-2xs transition-all",
                      hidden
                        ? "border-dashed border-border/40 bg-muted/20 opacity-40"
                        : "border-border/70 bg-card text-foreground hover:bg-muted/50",
                    )}
                  >
                    <button
                      type="button"
                      onClick={() => series && toggleHidden(target.key)}
                      className={cn("flex items-center gap-1.5 focus:outline-none", series && "cursor-pointer")}
                      title={series ? (hidden ? `Show ${target.label} in chart` : `Hide ${target.label} in chart`) : target.label}
                    >
                      <span className="size-2 shrink-0 rounded-full" style={{ background: target.color }} />
                      <span className="max-w-[10rem] truncate">{target.label}</span>
                      {typeof latest === "number" && (
                        <span className="font-mono text-[0.625rem] font-bold text-muted-foreground">
                          {latest}ms
                        </span>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => toggleTarget(target.key)}
                      className="ml-0.5 text-muted-foreground transition-colors hover:text-destructive"
                      title={`Unselect ${target.label}`}
                      aria-label={`Unselect ${target.label}`}
                    >
                      <X className="size-3" />
                    </button>
                  </span>
                );
              })
            ) : (
              <span className="text-xs italic text-muted-foreground">None selected. Click "Select Targets" to pick targets.</span>
            )}
          </div>

          <div className="relative min-h-0 flex-1 overflow-hidden rounded-xl border border-border/80 bg-background/50 p-2.5 shadow-inner">
            {displaySeries.length > 0 ? (
              <RttChart series={displaySeries} hiddenKeys={hiddenKeys} />
            ) : (
              <div className="flex h-full min-h-28 items-center justify-center text-xs text-muted-foreground">
                Press Run Probe to start measurements.
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function getActionIcon(label: string) {
  const lower = label.toLowerCase();
  if (lower.includes("buy") || lower.includes("order") || lower.includes("购") || lower.includes("shop") || lower.includes("cart") || lower.includes("vps")) {
    return ShoppingCart;
  }
  return ExternalLink;
}

export const NodeInfoPanel = memo(function NodeInfoPanel({ className, selected, clientInfo, loading }: NodeInfoPanelProps) {
  const { actionUrl, actionLabel } = resolveNodeAction(selected);
  const ActionIcon = getActionIcon(actionLabel);
  const nodeBgpIPv4 = selected?.public_ipv4 ? bgpSearchURL(selected.public_ipv4) : "";
  const nodeBgpIPv6 = selected?.public_ipv6 ? bgpSearchURL(selected.public_ipv6) : "";
  const userIsV6 = clientInfo?.ip.includes(":") ?? false;

  return (
    <TooltipProvider delayDuration={150}>
      <Card className={cn("overflow-hidden rounded-xl border bg-card", className)}>
        <CardHeader className="flex h-10 flex-row items-center gap-2.5 border-b bg-muted/30 px-3.5 py-0">
          <div className="flex size-6 shrink-0 items-center justify-center rounded-md border border-primary/25 bg-primary/10 text-primary">
            <MapPin className="size-3.5" />
          </div>
          <CardTitle className="min-w-0 flex-1 truncate text-sm font-semibold tracking-tight text-foreground">Node Info</CardTitle>
        </CardHeader>

        <CardContent className="flex flex-col gap-2 p-3">
          {/* Identity row: name + location on the left, description then the CTA
              on the right (the button spans the name/location height). */}
          {selected ? (
            <div className="flex items-stretch gap-3 px-0.5">
              <div className="flex min-w-0 max-w-[45%] flex-col justify-center">
                <div className="flex items-center gap-1.5">
                  <span
                    className={cn("size-1.5 shrink-0 rounded-full", selected.maintenance ? "bg-warning" : "bg-success")}
                    title={selected.maintenance ? "Maintenance" : "Online"}
                  />
                  <span className="truncate text-sm font-semibold tracking-tight text-foreground" title={selected.display_name || selected.id}>
                    {selected.display_name || selected.id}
                  </span>
                </div>
                {selected.display_label && (
                  <div className="truncate pl-3.5 text-xs text-muted-foreground" title={selected.display_label}>
                    {selected.display_label}
                  </div>
                )}
              </div>
              {selected.description && (
                <p
                  className="line-clamp-2 min-w-0 flex-1 self-center text-right text-xs leading-snug text-muted-foreground"
                  title={selected.description}
                >
                  {selected.description}
                </p>
              )}
              {actionUrl ? (
                <Button
                  asChild
                  size="sm"
                  variant="default"
                  className="h-auto shrink-0 gap-1.5 self-stretch rounded-md px-3 text-xs font-semibold shadow-xs [&_svg]:size-3.5"
                >
                  <a href={actionUrl} target="_blank" rel="noreferrer">
                    <ActionIcon />
                    <span className="max-w-[7rem] truncate">{actionLabel}</span>
                  </a>
                </Button>
              ) : null}
            </div>
          ) : loading ? (
            <Skeleton className="h-8 w-2/3 rounded" />
          ) : null}

          {selected ? (
            <DefinitionList>
              <Field term="IPv4" ariaLabel="Node IPv4" value={selected.public_ipv4 || ""} bgpUrl={selected.public_ipv4 ? nodeBgpIPv4 : undefined} />
              <Field term="IPv6" ariaLabel="Node IPv6" value={selected.public_ipv6 || ""} bgpUrl={selected.public_ipv6 ? nodeBgpIPv6 : undefined} />
            </DefinitionList>
          ) : loading ? (
            <div className="space-y-2">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
            </div>
          ) : (
            <p className="px-0.5 text-xs text-muted-foreground">Select a node to view its addresses.</p>
          )}

          {(clientInfo || loading) && (
            <div className="flex items-center gap-1.5 border-t border-border/50 px-0.5 pt-1.5">
              <span className="shrink-0 text-[0.6875rem] text-muted-foreground/80">Your IP</span>
              <VisitorAddress label="v4" value={clientInfo && !userIsV6 ? clientInfo.ip : ""} />
              <VisitorAddress label="v6" value={clientInfo && userIsV6 ? clientInfo.ip : ""} />
            </div>
          )}
        </CardContent>
      </Card>
    </TooltipProvider>
  );
});

function DefinitionList({ className, children }: { className?: string; children: React.ReactNode }) {
  return <dl className={cn("divide-y divide-border/50", className)}>{children}</dl>;
}

// Display truncates long values; copy still uses the full address.
function VisitorAddress({ label, value }: { label: string; value: string }) {
  const has = Boolean(value);
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    };
  }, []);

  function handleCopy() {
    if (!value || !navigator.clipboard) return;
    navigator.clipboard.writeText(value)
      .then(() => {
        setCopied(true);
        if (timerRef.current !== null) window.clearTimeout(timerRef.current);
        timerRef.current = window.setTimeout(() => setCopied(false), 1400);
      })
      .catch(() => {});
  }

  return (
    <button
      type="button"
      onClick={has ? handleCopy : undefined}
      disabled={!has}
      title={has ? `Copy ${value}` : undefined}
      aria-label={`Copy Visitor ${label}`}
      className={cn(
        "flex min-w-0 items-baseline gap-1 rounded px-1 py-0.5 font-mono text-xs transition-colors",
        has ? "cursor-pointer text-foreground hover:bg-muted" : "cursor-default text-muted-foreground/50",
      )}
    >
      <span className="shrink-0 text-[0.625rem] font-bold uppercase tracking-wider text-muted-foreground/70">{label}</span>
      <span className={cn("min-w-0", has ? "font-medium" : "italic")}>
        {has ? middleTruncate(value) : "—"}
      </span>
      {has && (
        <span className="shrink-0 self-center" aria-hidden>
          {copied ? <Check className="size-3 text-success" /> : <Copy className="size-3 text-muted-foreground/60" />}
        </span>
      )}
    </button>
  );
}

export function middleTruncate(value: string, maxLength = 21): string {
  if (value.length <= maxLength) return value;
  const keep = Math.max(4, Math.floor((maxLength - 1) / 2));
  return `${value.slice(0, keep)}…${value.slice(value.length - keep)}`;
}

function Field({
  term,
  ariaLabel,
  value,
  placeholder = "—",
  accent = "text-muted-foreground",
  bgpUrl,
}: {
  term: string;
  ariaLabel: string;
  value: string;
  placeholder?: string;
  accent?: string;
  bgpUrl?: string;
}) {
  const has = Boolean(value);
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    };
  }, []);

  function handleCopy() {
    if (!value || !navigator.clipboard) return;
    navigator.clipboard.writeText(value)
      .then(() => {
        setCopied(true);
        if (timerRef.current !== null) window.clearTimeout(timerRef.current);
        timerRef.current = window.setTimeout(() => setCopied(false), 1400);
      })
      .catch(() => {});
  }

  return (
    <div className="flex min-h-9 items-center justify-between gap-2 py-1.5">
      <div
        onClick={has ? handleCopy : undefined}
        className={cn(
          "flex min-w-0 flex-1 items-center gap-2.5 rounded-md px-1.5 py-1 -mx-1.5 transition-colors",
          has && "cursor-pointer hover:bg-muted/50 group",
        )}
        title={has ? `Click to copy ${value}` : undefined}
      >
        <dt className={cn("w-10 shrink-0 font-mono text-xs font-bold uppercase tracking-wider", accent)}>
          {term}
        </dt>
        <dd
          aria-label={ariaLabel}
          title={value || undefined}
          className={cn(
            "min-w-0 flex-1 truncate font-mono text-xs select-all",
            has ? "font-medium text-foreground group-hover:text-primary transition-colors" : "italic font-normal text-muted-foreground/60",
          )}
        >
          {value || placeholder}
        </dd>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {has && (
          <CopyButton
            value={value}
            label={ariaLabel}
            copied={copied}
            onCopy={handleCopy}
            iconOnly
          />
        )}
        {bgpUrl ? <BgpButton href={bgpUrl} /> : null}
      </div>
    </div>
  );
}

function CopyButton({
  value,
  label,
  className,
  copied: externalCopied,
  onCopy: externalOnCopy,
  iconOnly = false,
}: {
  value: string;
  label: string;
  className?: string;
  copied?: boolean;
  onCopy?: () => void;
  iconOnly?: boolean;
}) {
  const [internalCopied, setInternalCopied] = useState(false);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    };
  }, []);

  const isCopied = externalCopied !== undefined ? externalCopied : internalCopied;

  function copy() {
    if (externalOnCopy) {
      externalOnCopy();
      return;
    }
    if (!value || !navigator.clipboard) return;
    navigator.clipboard.writeText(value)
      .then(() => {
        setInternalCopied(true);
        if (timerRef.current !== null) window.clearTimeout(timerRef.current);
        timerRef.current = window.setTimeout(() => setInternalCopied(false), 1400);
      })
      .catch(() => {});
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          size="sm"
          variant={isCopied ? "default" : "outline"}
          aria-label={`Copy ${label}`}
          className={cn(
            "h-7 gap-1 rounded-md text-xs font-medium transition-all shadow-2xs",
            iconOnly ? "w-7 justify-center px-0" : "px-2",
            isCopied
              ? "bg-success hover:bg-success text-success-foreground border-success"
              : "border-border/70 bg-background/80 text-muted-foreground hover:border-border hover:bg-muted/80 hover:text-foreground",
            className,
          )}
          disabled={!value}
          onClick={copy}
        >
          {isCopied ? (
            <>
              <Check className="size-3 text-white" />
              {!iconOnly && <span>Copied!</span>}
            </>
          ) : (
            <>
              <Copy className="size-3" />
              {!iconOnly && <span>Copy</span>}
            </>
          )}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{isCopied ? "Copied to clipboard!" : `Copy ${label}`}</TooltipContent>
    </Tooltip>
  );
}

function BgpButton({ href }: { href: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          asChild
          size="sm"
          variant="outline"
          className="h-7 gap-1 rounded-md border-border/70 bg-background/80 px-2 text-xs font-medium text-muted-foreground shadow-2xs transition-colors hover:border-border hover:bg-muted/80 hover:text-foreground [&_svg]:size-3"
        >
          <a href={href} target="_blank" rel="noreferrer">
            <Network />
            <span>bgp.tools</span>
          </a>
        </Button>
      </TooltipTrigger>
      <TooltipContent>Look up this prefix on bgp.tools</TooltipContent>
    </Tooltip>
  );
}

export function bgpSearchURL(value: string): string {
  return `https://bgp.tools/search?q=${encodeURIComponent(value)}`;
}

export function resolveNodeAction(
  node?: Pick<PublicNode, "action_url" | "action_label" | "buy_url" | "buy_label">,
): { actionUrl: string; actionLabel: string } {
  return {
    actionUrl: safeActionHref(node?.action_url?.trim() || node?.buy_url?.trim() || ""),
    actionLabel: node?.action_label?.trim() || node?.buy_label?.trim() || "Action",
  };
}
