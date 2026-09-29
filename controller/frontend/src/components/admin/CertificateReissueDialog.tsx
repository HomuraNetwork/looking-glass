import { useEffect, useRef, useState } from "react";
import { Check, Loader2, AlertTriangle, ShieldCheck, Globe2, Clock } from "lucide-react";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { beginAdminCertificateOrder, finalizeAdminCertificateOrder, cancelAdminCertificateOrder, listAdminCertificates } from "@/lib/api";

type Phase = "confirm" | "generating" | "waiting" | "finalizing" | "issued" | "error";

const STEPS = [
  { key: "generating", label: "Create order & add DNS records", icon: Globe2 },
  { key: "waiting", label: "Wait for DNS propagation", icon: Clock },
  { key: "finalizing", label: "Issue & store certificate", icon: ShieldCheck },
] as const;

interface Props {
  open: boolean;
  domains: string[];
  onOpenChange: (open: boolean) => void;
  onDone: (msg: string) => void;
}

export function CertificateReissueDialog({ open, domains, onOpenChange, onDone }: Props) {
  const [phase, setPhase] = useState<Phase>("confirm");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [countdown, setCountdown] = useState(0);
  const [dnsNames, setDnsNames] = useState<string[]>([]);
  const busyRef = useRef(false);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setPhase("confirm"); setError(""); setNote(""); setCountdown(0); setDnsNames([]); busyRef.current = false;
    void listAdminCertificates().then(({ pending_order: pending }) => {
      if (!active || !pending?.pending) return;
      setDnsNames((pending.dns_records ?? []).map((record) => record.name));
      setNote("Resuming the pending certificate order. The current certificate stays active until the new one is issued.");
      setPhase("waiting");
    }).catch((e) => {
      if (!active) return;
      setError(e instanceof Error ? e.message : "Unable to check pending certificate order");
      setPhase("error");
    });
    return () => { active = false; };
  }, [open]);

  useEffect(() => {
    if (phase !== "waiting" || countdown <= 0) return;
    const t = window.setTimeout(() => setCountdown((c) => c - 1), 1000);
    return () => window.clearTimeout(t);
  }, [phase, countdown]);

  async function runBegin() {
    if (busyRef.current) return;
    busyRef.current = true;
    setPhase("generating"); setError(""); setNote("");
    try {
      const res = await beginAdminCertificateOrder();
      busyRef.current = false;
      if (res.status === "dns_added") {
        setDnsNames((res.dns_records ?? []).map((r) => r.name));
        const wait = Math.max(0, res.wait_seconds ?? 0);
        setCountdown(wait);
        setNote(
          wait > 0
            ? "DNS records added. Check again once they have propagated."
            : "DNS records added. Check validation when you are ready.",
        );
        setPhase("waiting");
      } else {
        setError(res.reason || res.status); setPhase("error");
      }
    } catch (e) {
      busyRef.current = false;
      setError(e instanceof Error ? e.message : "begin failed"); setPhase("error");
    }
  }

  async function runFinalize() {
    if (busyRef.current) return;
    busyRef.current = true;
    setPhase("finalizing"); setError("");
    try {
      const res = await finalizeAdminCertificateOrder();
      busyRef.current = false;
      if (res.status === "issued") {
        setPhase("issued");
        onDone(`Issued certificate for ${res.nodes ?? 0} node(s)`);
      } else if (res.status === "waiting") {
        setNote("DNS validation is not ready yet. Wait for propagation, then check again.");
        setCountdown(30);
        setPhase("waiting");
      } else {
        setError(res.reason || res.status); setPhase("error");
      }
    } catch (e) {
      busyRef.current = false;
      setError(e instanceof Error ? e.message : "finalize failed"); setPhase("error");
    }
  }

  async function handleCancel() {
    try {
      const result = await cancelAdminCertificateOrder();
      if (result.status === "locked") {
        setError("Certificate processing is in progress. Try cancelling again shortly.");
        setPhase("error");
        return;
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to cancel certificate order");
      setPhase("error");
      return;
    }
    onOpenChange(false);
  }

  const activeIndex = phase === "generating" ? 0 : phase === "waiting" ? 1 : phase === "finalizing" ? 2 : phase === "issued" ? 3 : -1;
  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onOpenChange(false); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reissue managed certificate</DialogTitle>
          <DialogDescription>
            ACME DNS-01 for {domains.length} wildcard domain{domains.length === 1 ? "" : "s"}. Runs as short steps — the
            propagation wait happens here, not in one long server request.
          </DialogDescription>
        </DialogHeader>

        {phase === "confirm" ? (
          <div className="space-y-2 py-1 text-sm">
            <p className="text-muted-foreground">This requests a fresh wildcard certificate and publishes encrypted bundles to your nodes.</p>
            <ul className="rounded-lg border bg-muted/30 p-2 font-mono text-xs">
              {domains.map((d) => <li key={d} className="truncate">{d}</li>)}
            </ul>
          </div>
        ) : (
          <div className="space-y-1.5 py-1">
            {STEPS.map((step, i) => {
              const done = phase === "issued" || activeIndex > i;
              const active = activeIndex === i;
              const Icon = step.icon;
              return (
                <div key={step.key} className={cn(
                  "flex items-center gap-2.5 rounded-lg border px-3 py-2 text-sm",
                  active ? "border-primary/40 bg-primary/5" : "bg-background/40",
                )}>
                  <span className={cn("flex size-5 flex-shrink-0 items-center justify-center rounded-full",
                    done ? "bg-emerald-500/15 text-emerald-500" : active ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground")}>
                    {done ? <Check className="size-3.5" /> : active ? <Loader2 className="size-3.5 animate-spin" /> : <Icon className="size-3.5" />}
                  </span>
                  <span className={cn("min-w-0 flex-1", done || active ? "text-foreground" : "text-muted-foreground")}>{step.label}</span>
                  {active && step.key === "waiting" && countdown > 0 && (
                    <span className="font-mono text-xs tabular-nums text-primary">{countdown}s</span>
                  )}
                </div>
              );
            })}

            {phase === "waiting" && dnsNames.length > 0 && (
              <p className="px-1 pt-1 text-xs text-muted-foreground">
                Added {dnsNames.length} TXT record{dnsNames.length === 1 ? "" : "s"} (<span className="font-mono">_acme-challenge…</span>).
              </p>
            )}
            {note && <p className="px-1 text-xs text-amber-600 dark:text-amber-400">{note}</p>}
            {phase === "issued" && (
              <p className="flex items-center gap-1.5 px-1 pt-1 text-sm font-medium text-emerald-600 dark:text-emerald-400">
                <Check className="size-4" /> Certificate issued and stored.
              </p>
            )}
            {phase === "error" && (
              <p className="flex items-start gap-1.5 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                <AlertTriangle className="mt-0.5 size-3.5 flex-shrink-0" />
                <span className="break-all">{error}</span>
              </p>
            )}
          </div>
        )}

        <DialogFooter>
          {phase === "confirm" && (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
              <Button onClick={() => void runBegin()}>Start reissue</Button>
            </>
          )}
          {phase === "waiting" && (
            <>
              <Button variant="outline" onClick={() => void handleCancel()}>Cancel order</Button>
              <Button onClick={() => void runFinalize()}>Check now</Button>
            </>
          )}
          {(phase === "generating" || phase === "finalizing") && (
            <Button disabled className="gap-1.5"><Loader2 className="size-4 animate-spin" /> Working…</Button>
          )}
          {phase === "error" && (
            <>
              <Button variant="outline" onClick={() => void handleCancel()}>Cancel order</Button>
              <Button onClick={() => void runFinalize()}>Retry</Button>
            </>
          )}
          {phase === "issued" && (
            <Button onClick={() => onOpenChange(false)}>Done</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
