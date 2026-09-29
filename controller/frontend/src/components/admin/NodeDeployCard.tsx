import { Copy, Clock, KeyRound, ShieldCheck, Terminal } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import type { AdminNodeInit } from "@/lib/api";

interface Props {
  nodeInit: AdminNodeInit | null;
  nodeID?: string;
  busy?: boolean;
  onIssueInit?: () => void;
  onSaved: (msg: string) => void;
  onError: (msg: string) => void;
}

export function NodeDeployCard({ nodeInit, nodeID, busy = false, onIssueInit, onSaved, onError }: Props) {
  const [arch, setArch] = useState<"amd64" | "arm64">("amd64");

  async function copy(text: string, label: string) {
    if (!navigator.clipboard) return onError("clipboard unavailable");
    try {
      await navigator.clipboard.writeText(text);
      onSaved(`copied ${label}`);
    } catch { onError("clipboard write failed"); }
  }

  if (!nodeInit) {
    return (
      <div className="rounded-xl border border-dashed bg-muted/20 p-4 text-sm text-muted-foreground">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="flex items-center gap-1.5 font-semibold text-foreground">
              <Terminal className="size-4" /> Deploy
            </p>
            <p className="mt-1">
              {nodeID
                ? "Issue a one-time init key when an existing agent needs to bootstrap or refresh its controller identity. This invalidates older unused keys for this node."
                : <>Save a <span className="font-semibold">new</span> node to generate a one-time init key and its install command.</>}
            </p>
          </div>
          {nodeID && onIssueInit ? (
            <Button size="sm" variant="outline" className="h-7 shrink-0 gap-1 text-xs" onClick={onIssueInit} disabled={busy}>
              <KeyRound className="size-3" /> Issue init key
            </Button>
          ) : null}
        </div>
      </div>
    );
  }

  const installDir = nodeInit.installDir || "/opt/looking-glass";
  const binaryName = nodeInit.binaryName || "hlg-agent";
  const serviceName = nodeInit.serviceName || "hlg-agent";
  const manual = nodeInit.manual ?? [];
  const manualArch = manual.find((m) => m.arch === arch) ?? manual[0];

  return (
    <div className="space-y-3 rounded-xl border bg-card p-4">
      <div className="flex items-center justify-between">
        <p className="flex items-center gap-1.5 text-sm font-bold text-foreground">
          <Terminal className="size-4" /> Deploy agent
        </p>
        <Badge variant="outline" className="gap-1 text-xs">
          <Clock className="size-3" /> valid until {new Date(nodeInit.expires_at * 1000).toLocaleString()}
        </Badge>
      </div>

      <Tabs defaultValue="script">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="script" className="text-xs">One-line install</TabsTrigger>
          <TabsTrigger value="manual" className="text-xs">Download &amp; init (checksum)</TabsTrigger>
        </TabsList>

        <TabsContent value="script" className="space-y-1.5 pt-2">
          <pre className="overflow-auto rounded-lg bg-background p-2.5 font-mono text-xs opacity-70 whitespace-pre-wrap break-all">
            {nodeInit.pull_command}
          </pre>
          <Button size="sm" variant="outline" className="h-7 gap-1 text-xs" onClick={() => void copy(nodeInit.pull_command, "install command")}>
            <Copy className="size-3" /> Copy install command
          </Button>
          <p className="text-xs text-muted-foreground">
            Downloads the installer, installs required packages, asks for the agent listen port during init (default 443), writes runtime/bootstrap config under <span className="font-mono text-[11px]">{installDir}</span>, installs <span className="font-mono text-[11px]">{binaryName}</span> as <span className="font-mono text-[11px]">{serviceName}</span>, and runs agent self-checks.
          </p>
        </TabsContent>

        <TabsContent value="manual" className="space-y-2 pt-2">
          {manual.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No signed release artifacts are available from this controller, so the manual install is unavailable.
              Use the one-line install.
            </p>
          ) : (
            <>
              <div className="flex items-center gap-2">
                <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Architecture</p>
                <div className="flex gap-1">
                  {manual.map((m) => (
                    <Button
                      key={m.arch}
                      size="sm"
                      variant={arch === m.arch ? "default" : "outline"}
                      className="h-6 px-2 text-[11px]"
                      onClick={() => setArch(m.arch)}
                    >
                      {m.arch}
                    </Button>
                  ))}
                </div>
              </div>

              <p className="text-xs text-muted-foreground">
                Download the agent binary, <span className="font-semibold text-foreground">verify its SHA-256</span>, then
                install with <span className="font-mono text-[11px]">init</span>, which asks for the agent listen port (default 443).
                The init key is one-time and is consumed
                on first bootstrap.
              </p>

              {manualArch ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                    <ShieldCheck className="size-3 text-emerald-400" />
                    <span className="font-mono break-all">SHA-256 {manualArch.sha256}</span>
                    <span className="shrink-0">({manualArch.size} bytes)</span>
                  </div>
                  {manualArch.steps.map((step, i) => {
                    const isChecksum = step.includes("sha256sum -c");
                    return (
                      <div key={i} className={`rounded-lg border p-2 ${isChecksum ? "border-emerald-500/40 bg-emerald-500/5" : "bg-background"}`}>
                        <div className="mb-1 flex items-center justify-between">
                          <span className="flex items-center gap-1.5 text-[11px] font-semibold text-muted-foreground">
                            {i + 1}.
                            {isChecksum ? " Verify checksum (required)" : ""}
                          </span>
                          <Button size="sm" variant="ghost" className="h-6 gap-1 px-2 text-[11px]" onClick={() => void copy(step, `step ${i + 1}`)}>
                            <Copy className="size-3" /> Copy
                          </Button>
                        </div>
                        <pre className="overflow-auto font-mono text-xs whitespace-pre-wrap break-all">{step}</pre>
                      </div>
                    );
                  })}
                </div>
              ) : null}
            </>
          )}
        </TabsContent>
      </Tabs>

      <section className="space-y-1.5 border-t pt-3">
        <p className="flex items-center gap-1 text-xs font-bold uppercase tracking-wider text-muted-foreground">
          <KeyRound className="size-3" /> Init key
        </p>
        <pre className="max-h-40 overflow-auto rounded-lg bg-background p-2.5 font-mono text-xs whitespace-pre-wrap break-all">
          {nodeInit.token}
        </pre>
        <Button size="sm" variant="outline" className="h-7 gap-1 text-xs" onClick={() => void copy(nodeInit.token, "init key")}>
          <Copy className="size-3" /> Copy init key
        </Button>
        <p className="text-xs text-muted-foreground">
          One-time bootstrap token. The installer download validates it, and the agent consumes it on first successful bootstrap.
        </p>
      </section>

      {nodeInit.init_string ? (
        <section className="space-y-1.5 border-t pt-3">
          <p className="flex items-center gap-1 text-xs font-bold uppercase tracking-wider text-muted-foreground">
            <Terminal className="size-3" /> Init string
          </p>
          <pre className="max-h-40 overflow-auto rounded-lg bg-background p-2.5 font-mono text-xs whitespace-pre-wrap break-all">
            {nodeInit.init_string}
          </pre>
          <Button size="sm" variant="outline" className="h-7 gap-1 text-xs" onClick={() => void copy(nodeInit.init_string ?? "", "init string")}>
            <Copy className="size-3" /> Copy init string
          </Button>
          <p className="text-xs text-muted-foreground">
            Controller origin plus the one-time key in one value, for containers: <span className="font-mono text-[11px]">hlg-agent run --init-string</span> or <span className="font-mono text-[11px]">-e LG_INIT_STRING</span>.
          </p>
        </section>
      ) : null}
    </div>
  );
}
