import { memo, useEffect, useRef, type ReactNode } from "react";
import { Info } from "lucide-react";
import { type PublicNode, type ClientInfo } from "@/lib/api";
import { type NodeRttMap } from "@/lib/rtt";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Skeleton } from "@/components/ui/skeleton";
import { NodeRttDetail } from "@/components/public/NodeRttDetail";
import { cn } from "@/lib/utils";

interface Props {
  nodes: PublicNode[];
  selected?: PublicNode;
  onSelect: (node: PublicNode) => void;
  clientInfo: ClientInfo | null;
  nodeRtt: NodeRttMap;
  rttControl?: ReactNode;
  loading?: boolean;
}

export const NodePillBar = memo(function NodePillBar({ nodes, selected, onSelect, clientInfo: _clientInfo, nodeRtt, rttControl, loading }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!selected?.id || !containerRef.current) return;
    const activeEl = containerRef.current.querySelector<HTMLElement>(`[data-node-id="${selected.id}"]`);
    if (activeEl) {
      activeEl.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
    }
  }, [selected?.id]);

  return (
    <div ref={containerRef} className="sticky top-[var(--nav-height)] z-30 flex items-center gap-2 overflow-x-auto border-b border-border/70 bg-background/90 px-3 py-2 backdrop-blur-md supports-[backdrop-filter]:bg-background/70 lg:hidden">
      {rttControl && <div className="flex flex-shrink-0 items-center">{rttControl}</div>}
      {loading && nodes.length === 0 ? (
        <div className="flex items-center gap-2">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-8 w-24 rounded-lg" />
          ))}
        </div>
      ) : (
        nodes.map((node) => {
        const rtt = nodeRtt[node.id];
        const isActive = selected?.id === node.id;
        return (
          <div
            key={node.id}
            data-node-id={node.id}
            className={cn(
              "flex flex-shrink-0 items-stretch overflow-hidden rounded-lg border transition-all duration-150",
              isActive ? "border-primary/40 bg-primary/10 shadow-xs ring-1 ring-primary/25" : "border-border/60 bg-muted/30 hover:border-border hover:bg-muted/60",
            )}
          >
            <button type="button" onClick={() => onSelect(node)} className="flex items-center gap-2 px-3 py-1.5">
              <span className="relative flex size-2 flex-shrink-0 items-center justify-center">
                {isActive && (
                  <span
                    className={cn(
                      "absolute inline-flex h-full w-full animate-ping rounded-full opacity-60",
                      node.maintenance ? "bg-amber-400" : "bg-emerald-400",
                    )}
                  />
                )}
                <span
                  className={cn(
                    "relative inline-flex size-2 rounded-full ring-2 ring-background",
                    node.maintenance ? "bg-amber-400" : "bg-emerald-400",
                  )}
                />
              </span>
              <span className={cn("truncate text-xs font-bold", isActive ? "text-foreground" : "text-muted-foreground")}>
                {node.display_name || node.id}
              </span>
            </button>
            <Popover>
              <PopoverTrigger asChild>
                <button
                  type="button"
                  aria-label={`${node.id} RTT details`}
                  className="flex items-center border-l border-border/50 px-2 text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground"
                >
                  <Info className="size-3.5" />
                </button>
              </PopoverTrigger>
              <PopoverContent align="end" sideOffset={8} className="w-auto bg-card p-3 text-card-foreground shadow-xl ring-1 ring-border">
                <NodeRttDetail rtt={rtt} />
              </PopoverContent>
            </Popover>
          </div>
        );
      }))}
    </div>
  );
});

