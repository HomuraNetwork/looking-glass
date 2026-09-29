import { memo, type ReactNode } from "react";
import { Activity, Globe, Radio, ShieldCheck } from "lucide-react";
import { type PublicNode, type ClientInfo, type ClientTraceInfo } from "@/lib/api";
import { nodeRttStats, type NodeProbeState, type NodeRttMap } from "@/lib/rtt";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { NodeRttDetail } from "@/components/public/NodeRttDetail";
import { SiteFooter } from "@/components/layout/SiteFooter";
import { cn } from "@/lib/utils";

interface Props {
  nodes: PublicNode[];
  selected?: PublicNode;
  onSelect: (node: PublicNode) => void;
  clientInfo: ClientInfo | null;
  clientTrace: ClientTraceInfo | null;
  nodeRtt: NodeRttMap; // nodeId → { v4, v6 } auto-probe state
  rttControl?: ReactNode;
  loading?: boolean;
}

export const Sidebar = memo(function Sidebar({ nodes, selected, onSelect, clientInfo, clientTrace, nodeRtt, rttControl, loading }: Props) {
  return (
    <aside className="hidden w-[236px] flex-shrink-0 flex-col border-r bg-card lg:sticky lg:top-[var(--nav-height)] lg:flex lg:h-[calc(100dvh-var(--nav-height))] lg:self-start [@media_(min-height:846px)]:lg:static [@media_(min-height:846px)]:lg:h-full [@media_(min-height:846px)]:lg:min-h-0">
      <div className="flex items-center justify-between border-b bg-muted/20 px-3.5 py-2.5">
        <span className="text-xs font-bold text-muted-foreground">
          Nodes
        </span>
        <span className="rounded-full border border-primary/20 bg-primary/10 px-2 py-0.5 font-mono text-[0.6875rem] font-bold text-primary">
          {nodes.length}
        </span>
      </div>

      <TooltipProvider delayDuration={200}>
        <div className="flex-1 overflow-y-auto p-1.5 space-y-1">
          {loading && nodes.length === 0 ? (
            <div className="flex flex-col gap-2 p-2">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg border border-border/40 p-2">
                  <Skeleton className="size-2 rounded-full" />
                  <Skeleton className="h-4 flex-1 rounded" />
                  <Skeleton className="h-4 w-12 rounded" />
                </div>
              ))}
            </div>
          ) : (
            nodes.map((node) => {
            const rtt = nodeRtt[node.id];
            const isActive = selected?.id === node.id;
            return (
              <Tooltip key={node.id}>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    type="button"
                    onClick={() => onSelect(node)}
                    className={cn(
                      "group relative h-auto w-full flex-col items-stretch justify-start rounded-lg border px-3 py-2 text-left shadow-none transition-all duration-150 whitespace-normal",
                      isActive
                        ? "border-primary/30 bg-primary/10 text-foreground shadow-xs"
                        : "border-transparent text-muted-foreground hover:border-border/60 hover:bg-muted/50 hover:text-foreground",
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <span className="relative mt-1 flex size-2 flex-shrink-0 items-center justify-center">
                        {isActive && (
                          <span
                            className={cn(
                              "absolute inline-flex h-full w-full animate-ping rounded-full opacity-60",
                              node.maintenance ? "bg-warning" : "bg-success",
                            )}
                          />
                        )}
                        <span
                          className={cn(
                            "relative inline-flex size-2 rounded-full ring-2 ring-background",
                            node.maintenance ? "bg-warning" : "bg-success",
                          )}
                        />
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className={cn("truncate text-xs font-bold leading-tight", isActive ? "text-foreground" : "group-hover:text-foreground")}>
                          {node.display_name || node.id}
                        </div>
                        {node.display_label && (
                          <div className="truncate text-[0.6875rem] leading-tight text-muted-foreground">
                            {node.display_label}
                          </div>
                        )}
                      </div>
                      <div className="flex flex-shrink-0 flex-col items-end gap-1">
                        <RttCell family="v4" state={rtt?.v4} />
                        <RttCell family="v6" state={rtt?.v6} hidden={node.has_ipv6 === false} />
                      </div>
                    </div>
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="right" sideOffset={8} className="bg-card text-card-foreground shadow-xl ring-1 ring-border">
                  <NodeRttDetail rtt={rtt} />
                </TooltipContent>
              </Tooltip>
            );
          }))}
        </div>
      </TooltipProvider>

      <div className="flex-shrink-0 border-t bg-muted/15 p-2.5 space-y-1.5">
        {rttControl && (
          <div className="flex items-center justify-between gap-2 px-1 py-0.5">
            <div className="flex min-w-0 items-center gap-1.5">
              <Activity className="size-3.5 shrink-0 text-primary" />
              <span className="truncate text-xs font-semibold text-foreground">
                Latency Probe
              </span>
            </div>
            {rttControl}
          </div>
        )}

        {clientInfo && <ConnectionInfo info={clientInfo} trace={clientTrace} />}

        <SiteFooter className="pt-0.5" />
      </div>
    </aside>
  );
});

function RttCell({ family, state, hidden = false }: { family: "v4" | "v6"; state?: NodeProbeState; hidden?: boolean }) {
  const usable = state?.usable ?? false;
  const samples = state?.samples ?? [];
  const stats = nodeRttStats(samples);

  let value: string;
  let bad = false;
  if (!usable) {
    value = "--";
    bad = true;
  } else if (!stats) {
    value = samples.length === 0 ? "···" : "--";
    bad = samples.length > 0;
  } else if (stats.best > 9999) {
    value = "--";
    bad = true;
  } else {
    value = `${stats.best}ms`;
  }

  return (
    <span
      className={cn(
        "flex w-[4.75rem] items-center justify-between rounded-md border px-1.5 py-0.5 font-mono text-[0.625rem] font-semibold tabular-nums transition-colors",
        hidden && "invisible",
        bad
          ? "border-destructive/20 bg-destructive/10 text-destructive"
          : "border-primary/20 bg-primary/10 text-primary",
      )}
    >
      <span className="opacity-75">{family === "v4" ? "IPv4" : "IPv6"}</span>
      <span>{value}</span>
    </span>
  );
}

function ConnectionInfo({ info, trace }: { info: ClientInfo; trace: ClientTraceInfo | null }) {
  const locationText = [info.city, trace?.loc || info.country].filter(Boolean).join(", ") || "Unknown";
  const colo = trace?.colo || info.colo;
  const protocol = [trace?.http || info.httpProtocol, trace?.visitScheme || info.tlsVersion].filter(Boolean).join(" · ");

  return (
    <div className="rounded-lg border border-border/50 bg-card/50 p-2 text-xs space-y-1">
      <div className="flex items-center justify-between gap-1 text-[0.625rem] font-bold uppercase tracking-wider text-muted-foreground px-0.5">
        <span className="flex items-center gap-1.5">
          <span className="size-1.5 rounded-full bg-success" />
          Connection
        </span>
        {info.asn && (
          <span className="rounded border border-primary/25 bg-primary/10 px-1 py-px font-mono text-[0.625rem] font-bold text-primary">
            {info.asn}
          </span>
        )}
      </div>
      <div className="space-y-0.5 font-mono text-[0.6875rem]">
        <div className="flex items-center justify-between gap-2 px-0.5 text-muted-foreground">
          <span className="flex items-center gap-1.5 text-muted-foreground shrink-0">
            <Globe className="size-3 text-muted-foreground" />
            <span className="font-sans text-xs text-muted-foreground">Location</span>
          </span>
          <span className="truncate text-foreground font-medium" title={locationText}>
            {locationText}
          </span>
        </div>
        {colo ? (
          <div className="flex items-center justify-between gap-2 px-0.5 text-muted-foreground">
            <span className="flex items-center gap-1.5 text-muted-foreground shrink-0">
              <Radio className="size-3 text-muted-foreground" />
              <span className="font-sans text-xs text-muted-foreground">Edge PoP</span>
            </span>
            <span className="rounded border border-info/25 bg-info/10 px-1.5 py-px text-[0.625rem] font-bold text-info">
              {colo}
            </span>
          </div>
        ) : null}
        {protocol ? (
          <div className="flex items-center justify-between gap-2 px-0.5 text-muted-foreground">
            <span className="flex items-center gap-1.5 text-muted-foreground shrink-0">
              <ShieldCheck className="size-3 text-muted-foreground" />
              <span className="font-sans text-xs text-muted-foreground">Protocol</span>
            </span>
            <span className="truncate text-foreground font-medium">
              {protocol}
            </span>
          </div>
        ) : null}
      </div>
    </div>
  );
}
