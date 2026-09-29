import { nodeRttStats, type NodeProbeState } from "@/lib/rtt";

export function NodeRttDetail({ rtt }: { rtt?: { v4: NodeProbeState; v6: NodeProbeState } }) {
  return (
    <div className="flex min-w-[12rem] flex-col gap-1.5">
      <span className="text-xs font-semibold text-muted-foreground">RTT from your browser</span>
      <NodeRttDetailRow label="IPv4" state={rtt?.v4} />
      <NodeRttDetailRow label="IPv6" state={rtt?.v6} />
    </div>
  );
}

function NodeRttDetailRow({ label, state }: { label: string; state?: NodeProbeState }) {
  const usable = state?.usable ?? false;
  const samples = state?.samples ?? [];
  const stats = nodeRttStats(samples);
  return (
    <div className="flex items-baseline justify-between gap-3 font-mono text-xs">
      <span className="font-bold text-foreground">{label}</span>
      {!usable ? (
        <span className="text-destructive">not available</span>
      ) : stats ? (
        <span className="tabular-nums text-muted-foreground">
          best <span className="text-foreground">{stats.best}</span> · avg <span className="text-foreground">{stats.avg}</span> · worst{" "}
          <span className="text-foreground">{stats.worst}</span>ms
        </span>
      ) : samples.length === 0 ? (
        <span className="text-muted-foreground">probing…</span>
      ) : (
        <span className="text-destructive">no response</span>
      )}
    </div>
  );
}
