import { useId, useMemo, useState } from "react";
import {
  Plus, Activity, CheckCircle2, XCircle, Eye, EyeOff,
  Trash2, Power, PowerOff, RefreshCw, Settings, AlertTriangle,
  Search, Server, ServerOff, ShieldAlert, LayoutGrid, List,
  ChevronRight, Copy, ArrowUp, ArrowDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import {
  Popover, PopoverContent, PopoverTrigger,
} from "@/components/ui/popover";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription, SheetFooter,
} from "@/components/ui/sheet";
import {
  Tabs, TabsContent, TabsList, TabsTrigger,
} from "@/components/ui/tabs";
import type {
  AdminNode, AdminNodeFormInput, AdminNodeCheck, AdminNodeFeature,
  AdminNodeInit, AdminDNSRecord,
} from "@/lib/api";
import {
  adminNodeFeatures, isAdminNodeFeature, upsertAdminNode,
  upsertAdminNodeDNS, checkAdminNode, issueAdminNodeInit, deleteAdminNode,
  reorderAdminNodes,
} from "@/lib/api";
import { ConfirmDialog } from "./ConfirmDialog";
import { NodeDeployCard } from "./NodeDeployCard";
import { cn } from "@/lib/utils";

const FEATURE_LABELS: Record<AdminNodeFeature, string> = {
  generate204: "204", download: "Download", ping: "Ping",
  mtr: "MTR", traceroute: "Traceroute", nexttrace: "NextTrace", iperf3: "iPerf3",
};

export type DNSMode = "id" | "prefix" | "full";

export interface DNSConfig {
  base: string;
  v4Base: string;
  v6Base: string;
  singleBase: boolean;
  mode: DNSMode;
  prefix: string;
  autoDNS: boolean;
}

function emptyForm(): AdminNodeFormInput {
  return {
    internal_id: undefined, id: "", domain: "", port: 443, domain_v4: "", domain_v6: "", display_name: "", display_label: "",
    public_ipv4: "", public_ipv6: "", description: "", buy_url: "", buy_label: "", bgp_url: "", dynamic_ip: false, profile_id: "default", enabled: true,
    hidden: false, maintenance: false, features: [...adminNodeFeatures],
  };
}

interface Props {
  nodes: AdminNode[];
  dnsConfig: DNSConfig;
  onDNSConfig: (d: DNSConfig) => void;
  onSaved: (msg: string) => void;
  onError: (msg: string) => void;
  onRefresh: () => void;
  busy: string;
  setBusy: (s: string) => void;
}

export function AdminNodes({ nodes, dnsConfig, onDNSConfig, onSaved, onError, onRefresh, busy, setBusy }: Props) {
  const [form, setForm] = useState<AdminNodeFormInput>(emptyForm);
  const [checks, setChecks] = useState<Record<string, AdminNodeCheck>>({});
  const [nodeInit, setNodeInit] = useState<AdminNodeInit | null>(null);
  const [dnsRecords, setDnsRecords] = useState<AdminDNSRecord[]>([]);
  const [deleteTarget, setDeleteTarget] = useState<AdminNode | null>(null);
  const [reinitTarget, setReinitTarget] = useState<AdminNode | null>(null);
  const [search, setSearch] = useState("");
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [editTab, setEditTab] = useState("basic");

  function setField<K extends keyof AdminNodeFormInput>(key: K, value: AdminNodeFormInput[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  function openNodeEditor(node: AdminNode, tab = "basic") {
    setForm(nodeToForm(node));
    setNodeInit(node.active_init
      ? {
          node_id: node.active_init.node_id,
          token: node.active_init.token,
          expires_at: node.active_init.expires_at,
          pull_command: node.active_init.pull_command,
          init_string: node.active_init.init_string,
          manual: node.active_init.manual,
          installDir: node.active_init.installDir,
          dataDir: node.active_init.dataDir,
          binaryName: node.active_init.binaryName,
          serviceName: node.active_init.serviceName,
          runUser: node.active_init.runUser,
        }
      : null);
    setDnsRecords([]);
    setSelectedNode(node.id);
    setSheetOpen(true);
    setEditTab(tab);
  }

  function computedDomains(): { domain: string; domain_v4: string; domain_v6: string } {
    if (dnsConfig.mode === "full") {
      return { domain: form.domain, domain_v4: form.domain_v4, domain_v6: form.domain_v6 };
    }
    const label = dnsConfig.mode === "prefix" ? dnsConfig.prefix.trim() : form.id.trim();
    const base = dnsConfig.base.trim().replace(/^\.+/, "");
    if (!base || !label) return { domain: "", domain_v4: "", domain_v6: "" };
    if (dnsConfig.singleBase) {
      return {
        domain: `${label}.${base}`,
        domain_v4: `${label}-v4.${base}`,
        domain_v6: `${label}-v6.${base}`,
      };
    }
    const v4Base = (dnsConfig.v4Base || dnsConfig.base).trim().replace(/^\.+/, "");
    const v6Base = (dnsConfig.v6Base || dnsConfig.base).trim().replace(/^\.+/, "");
    return {
      domain: `${label}.${base}`,
      domain_v4: `${label}.${v4Base}`,
      domain_v6: `${label}.${v6Base}`,
    };
  }

  const displayedDomains = computedDomains();
  const domainsEditable = dnsConfig.mode === "full";
  const dnsComplete = Boolean(
    dnsConfig.base.trim() &&
    (dnsConfig.singleBase || (dnsConfig.v4Base.trim() && dnsConfig.v6Base.trim()))
  );

  async function saveNode() {
    setBusy("save");
    try {
      const dns = dnsConfig.autoDNS && dnsConfig.mode !== "full" && dnsComplete
        ? { enabled: true as const, mode: dnsConfig.mode, prefix: dnsConfig.mode === "prefix" ? dnsConfig.prefix : undefined }
        : { enabled: false as const, mode: dnsConfig.mode };
      const formForSave = dnsConfig.mode !== "full" && dnsComplete
        ? { ...form, ...displayedDomains }
        : form;
      const result = await upsertAdminNode(formForSave, dns);
      setForm(nodeToForm(result.node));
      setNodeInit(result.init ?? null);
      setSelectedNode(result.node.id);
      setSheetOpen(true);
      setEditTab(result.init ? "deploy" : "basic");
      onRefresh();
      onSaved(`saved ${result.node.id}${dns.enabled ? " and synced DNS" : ""}`);
    } catch (e) { onError(e instanceof Error ? e.message : "save failed"); }
    finally { setBusy(""); }
  }

  async function handleMove(node: AdminNode, direction: -1 | 1) {
    const ids = nodes.map((item) => item.internal_id ?? item.id);
    const index = ids.indexOf(node.internal_id ?? node.id);
    const target = index + direction;
    if (index < 0 || target < 0 || target >= ids.length) return;
    [ids[index], ids[target]] = [ids[target], ids[index]];
    setBusy(`move:${node.id}`);
    try {
      await reorderAdminNodes(ids);
      onRefresh();
    } catch (e) { onError(e instanceof Error ? e.message : "reorder failed"); }
    finally { setBusy(""); }
  }

  async function handleCheck(node: AdminNode) {    setBusy(`check:${node.id}`);
    try {
      const result = await checkAdminNode(node.id);
      setChecks((c) => ({ ...c, [node.id]: result }));
      onRefresh();
      onSaved(`${node.id} ${result.healthy ? "healthy" : "needs attention"}`);
    } catch (e) { onError(e instanceof Error ? e.message : "check failed"); }
    finally { setBusy(""); }
  }

  async function handleDelete(node: AdminNode) {
    setBusy(`delete:${node.id}`);
    try {
      await deleteAdminNode(node.id);
      setDeleteTarget(null);
      onRefresh();
      onSaved(`deleted ${node.id}`);
    } catch (e) { onError(e instanceof Error ? e.message : "delete failed"); }
    finally { setBusy(""); }
  }

  async function handleToggleEnabled(node: AdminNode) {
    setBusy(`toggle:${node.id}`);
    try {
      const next = nodeToForm(node);
      next.enabled = !node.enabled;
      await upsertAdminNode(next);
      onRefresh();
      onSaved(`${node.id} ${next.enabled ? "enabled" : "disabled"}`);
    } catch (e) { onError(e instanceof Error ? e.message : "toggle failed"); }
    finally { setBusy(""); }
  }

  async function handleReInit(node: AdminNode) {
    setBusy(`init:${node.id}`);
    try {
      const init = await issueAdminNodeInit(node.id);
      openNodeEditor({ ...node, active_init: { node_id: node.internal_id ?? node.id, ...init } }, "deploy");
      setNodeInit(init);
      onRefresh();
      onSaved(`issued re-init key for ${node.id}`);
    } catch (e) { onError(e instanceof Error ? e.message : "re-init key failed"); }
    finally { setBusy(""); }
  }

  async function createDNS() {
    setBusy("dns");
    try {
      const result = await upsertAdminNodeDNS({
        node_id: form.id,
        prefix: dnsConfig.mode === "prefix" ? dnsConfig.prefix : undefined,
        domain: dnsConfig.mode === "full" ? form.domain : undefined,
        domain_v4: dnsConfig.mode === "full" ? form.domain_v4 : undefined,
        domain_v6: dnsConfig.mode === "full" ? form.domain_v6 : undefined,
        ipv4: form.public_ipv4,
        ipv6: form.public_ipv6,
      });
      setForm((f) => ({ ...f, ...result.domains }));
      setDnsRecords(result.records);
      onSaved(`DNS: ${result.records.length} record(s) updated`);
    } catch (e) { onError(e instanceof Error ? e.message : "DNS failed"); }
    finally { setBusy(""); }
  }

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return nodes;
    return nodes.filter((n) =>
      n.id.toLowerCase().includes(q) ||
      n.domain.toLowerCase().includes(q) ||
      (n.display_label ?? "").toLowerCase().includes(q) ||
      (n.public_ipv4 ?? "").includes(q) ||
      (n.public_ipv6 ?? "").includes(q) ||
      (n.display_name ?? "").toLowerCase().includes(q)
    );
  }, [nodes, search]);

  const stats = useMemo(() => ({
    total: nodes.length,
    online: nodes.filter((n) => n.availability?.available === true).length,
    offline: nodes.filter((n) => n.availability?.available === false).length,
    maintenance: nodes.filter((n) => n.maintenance).length,
  }), [nodes]);

  return (
    <div className="space-y-6">
      <section className="min-w-0 space-y-4" aria-busy={busy.startsWith("check:")}>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-bold text-foreground">Nodes</h2>
            <p className="text-xs text-muted-foreground">Manage probes, deploy agents and monitor health</p>
          </div>
          <Button size="sm" className="h-8 gap-1.5 text-xs"
            onClick={() => { setForm(emptyForm()); setNodeInit(null); setDnsRecords([]); setSelectedNode(null); setSheetOpen(true); setEditTab("basic"); }}>
            <Plus className="size-3.5" /> Add Node
          </Button>
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <StatCard icon={Server} label="Total" value={stats.total} color="text-primary" />
          <StatCard icon={CheckCircle2} label="Online" value={stats.online} color="text-success" />
          <StatCard icon={ServerOff} label="Offline" value={stats.offline} color="text-destructive" />
          <StatCard icon={ShieldAlert} label="Maintenance" value={stats.maintenance} color="text-warning" />
        </div>

        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search by ID, domain, location, IP…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 pl-8 text-sm"
            />
          </div>
          <div className="flex items-center rounded-md border bg-card">
            <Button
              size="sm" variant="ghost"
              className={cn("h-7 w-7 rounded-none rounded-l-md p-0", viewMode === "cards" && "bg-muted")}
              onClick={() => setViewMode("cards")}
            >
              <LayoutGrid className="size-3.5" />
            </Button>
            <Separator orientation="vertical" className="h-5" />
            <Button
              size="sm" variant="ghost"
              className={cn("h-7 w-7 rounded-none rounded-r-md p-0", viewMode === "table" && "bg-muted")}
              onClick={() => setViewMode("table")}
            >
              <List className="size-3.5" />
            </Button>
          </div>
        </div>

        {viewMode === "cards" ? (
          <div className="grid gap-3 sm:grid-cols-2">
            {filtered.map((node) => {
              // Ordering is against the full list, not the search-filtered
              // view, so the move bounds come from the full list too.
              const fullIndex = nodes.findIndex((item) => item.id === node.id);
              return (
                <NodeCard
                  key={node.id}
                  node={node}
                  check={checks[node.id]}
                  isSelected={selectedNode === node.id}
                  busy={busy}
                  canMoveUp={fullIndex > 0}
                  canMoveDown={fullIndex >= 0 && fullIndex < nodes.length - 1}
                  onSelect={() => openNodeEditor(node)}
                  onCheck={() => handleCheck(node)}
                  onToggle={() => handleToggleEnabled(node)}
                  onReInit={() => setReinitTarget(node)}
                  onDelete={() => setDeleteTarget(node)}
                  onMove={(direction) => handleMove(node, direction)}
                  onSaved={onSaved}
                  onError={onError}
                />
              );
            })}
            {filtered.length === 0 && (
              <div className="col-span-full rounded-xl border border-dashed bg-card py-12 text-center">
                <Server className="mx-auto size-8 text-muted-foreground/50" />
                <p className="mt-2 text-sm text-muted-foreground">No nodes found</p>
                {search && <p className="text-xs text-muted-foreground">Try a different search term</p>}
              </div>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border bg-card">
            <table className="w-full min-w-[700px] text-sm">
              <thead className="border-b bg-muted/40">
                <tr>
                  {["Node", "Domain", "Location", "IP", "State", "Actions"].map((h) => (
                    <th key={h} scope="col" className="px-3 py-2.5 text-left text-xs font-bold uppercase tracking-wider text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((node) => {
                  const fullIndex = nodes.findIndex((item) => item.id === node.id);
                  return (
                  <tr key={node.id} className={cn(
                    "border-b last:border-0 hover:bg-muted/20 cursor-pointer",
                    selectedNode === node.id && "bg-primary/5"
                  )}
                    onClick={() => openNodeEditor(node)}
                  >
                    <td className="px-3 py-2.5 align-top">
                      <div className="flex items-center gap-0.5">
                        <span className="flex flex-col" onClick={(e) => e.stopPropagation()}>
                          <button className="text-muted-foreground hover:text-foreground disabled:opacity-30"
                            title="Move up" disabled={fullIndex <= 0 || busy === `move:${node.id}`}
                            onClick={() => handleMove(node, -1)}>
                            <ArrowUp className="size-3" />
                          </button>
                          <button className="text-muted-foreground hover:text-foreground disabled:opacity-30"
                            title="Move down" disabled={fullIndex >= nodes.length - 1 || busy === `move:${node.id}`}
                            onClick={() => handleMove(node, 1)}>
                            <ArrowDown className="size-3" />
                          </button>
                        </span>
                        <div>
                          <div className="font-mono text-sm font-bold text-primary">{node.id}</div>
                          <div className="text-xs text-muted-foreground">{nodeVersionLabel(node)}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-2.5 align-top">
                      <div className="font-mono text-xs">{node.domain}{(node.port ?? 443) === 443 ? "" : `:${node.port}`}</div>
                      <div className="text-xs text-muted-foreground">{node.display_name}</div>
                    </td>
                    <td className="px-3 py-2.5 align-top">{node.display_label || "—"}</td>
                    <td className="px-3 py-2.5 align-top font-mono text-xs">
                      <div>{node.public_ipv4 || "—"}</div>
                      <div className="text-muted-foreground">{node.public_ipv6 || ""}</div>
                    </td>
                    <td className="px-3 py-2.5 align-top">
                      <NodeStateBadges node={node} check={checks[node.id]} />
                    </td>
                    <td className="px-3 py-2.5 text-right align-top">
                      <div className="flex items-center gap-1 justify-end" onClick={(e) => e.stopPropagation()}>
                        <Button size="sm" variant="outline" className="h-6 w-6 p-0"
                          onClick={() => handleCheck(node)} disabled={busy === `check:${node.id}`}
                          title="Check">
                          <Activity className="size-3" />
                        </Button>
                        <Button size="sm" variant="ghost" className="h-6 w-6 p-0"
                          onClick={() => handleToggleEnabled(node)} disabled={busy === `toggle:${node.id}`}
                          title={node.enabled ? "Disable" : "Enable"}>
                          {node.enabled ? <PowerOff className="size-3" /> : <Power className="size-3" />}
                        </Button>
                        <Popover>
                          <PopoverTrigger asChild>
                            <Button size="sm" variant="ghost" className="h-6 w-6 p-0">
                              <Settings className="size-3" />
                            </Button>
                          </PopoverTrigger>
                          <PopoverContent align="end" className="w-40 p-1">
                            <button
                              className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-muted disabled:opacity-50"
                              onClick={() => setReinitTarget(node)} disabled={busy === `init:${node.id}`}
                            >
                              <RefreshCw className="size-3.5" /> Re-init Key
                            </button>
                            <button
                              className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-50"
                              onClick={() => setDeleteTarget(node)} disabled={busy === `delete:${node.id}`}
                            >
                              <Trash2 className="size-3.5" /> Delete
                            </button>
                          </PopoverContent>
                        </Popover>
                      </div>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent className="w-full sm:max-w-lg overflow-y-auto" aria-busy={busy === "save" || busy === "dns"}>
          <SheetHeader className="space-y-1 pb-4">
            <SheetTitle className="flex items-center gap-2">
              {form.id ? (
                <>
                  <Server className="size-5 text-primary" />
                  Edit Node
                </>
              ) : (
                <>
                  <Plus className="size-5 text-primary" />
                  Add New Node
                </>
              )}
            </SheetTitle>
            <SheetDescription>
              {form.id ? `Node ID: ${form.id}` : "Register a new probe node"}
            </SheetDescription>
          </SheetHeader>

          <Tabs value={editTab} onValueChange={setEditTab} className="space-y-4">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="basic">Basic</TabsTrigger>
              <TabsTrigger value="network">Network</TabsTrigger>
              <TabsTrigger value="advanced">Advanced</TabsTrigger>
              <TabsTrigger value="deploy" disabled={!form.id.trim()}>Deploy</TabsTrigger>
            </TabsList>

            <TabsContent value="basic" className="space-y-3">
              <Field label="ID" value={form.id} onChange={(v) => setField("id", v)} />
              <div className="grid grid-cols-2 gap-2">
                <Field label="Display Name" value={form.display_name} onChange={(v) => setField("display_name", v)} />
                <Field label="Location" value={form.display_label} onChange={(v) => setField("display_label", v)} />
              </div>
              <Field label="Description" value={form.description} onChange={(v) => setField("description", v)} />

              <div className="space-y-2 pt-2">
                <Label className="text-xs font-semibold">Node State</Label>
                <div className="flex gap-3">
                  <Toggle label="Enabled" checked={form.enabled} onChange={(v) => setField("enabled", v)} />
                  <Toggle label="Hidden" checked={form.hidden} onChange={(v) => setField("hidden", v)} />
                  <Toggle label="Maintenance" checked={form.maintenance} onChange={(v) => setField("maintenance", v)} />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="network" className="space-y-3">
              <div className="space-y-2">
                <Label className="text-xs font-semibold">DNS Naming</Label>
                <div className="flex gap-1.5">
                  {(["id", "prefix", "full"] as DNSMode[]).map((m) => (
                    <Button key={m} type="button" size="sm" variant="outline"
                      onClick={() => onDNSConfig({ ...dnsConfig, mode: m, autoDNS: m === "full" ? false : dnsConfig.autoDNS })}
                      className={cn(
                        "h-7 flex-1 rounded-md border py-1 text-xs font-semibold transition-colors",
                        dnsConfig.mode === m ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground"
                      )}>
                      {m === "id" ? "ID" : m === "prefix" ? "Prefix" : "Full"}
                    </Button>
                  ))}
                </div>
                {dnsConfig.mode === "prefix" && (
                  <Field label="Prefix" value={dnsConfig.prefix}
                    onChange={(v) => onDNSConfig({ ...dnsConfig, prefix: v })} />
                )}
              </div>

              <Field label="Domain"
                value={domainsEditable ? form.domain : displayedDomains.domain}
                onChange={(v) => setField("domain", v)} disabled={!domainsEditable} />
              <Field label="IPv4 Domain"
                value={domainsEditable ? form.domain_v4 : displayedDomains.domain_v4}
                onChange={(v) => setField("domain_v4", v)} disabled={!domainsEditable} />
              <Field label="IPv6 Domain"
                value={domainsEditable ? form.domain_v6 : displayedDomains.domain_v6}
                onChange={(v) => setField("domain_v6", v)} disabled={!domainsEditable} />

              <div className="space-y-1">
                <Label htmlFor="node-worker-port" className="text-xs">Node HTTPS Port</Label>
                <Input id="node-worker-port" type="number" min={1} max={65535} value={form.port}
                  onChange={(e) => setField("port", Number(e.target.value) || 443)} className="h-8 text-sm" />
                <p className="text-[11px] text-muted-foreground">Port the Worker uses to reach the node or reverse proxy over HTTPS. Default: 443.</p>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <Field label="IPv4" value={form.public_ipv4} onChange={(v) => setField("public_ipv4", v)} />
                <Field label="IPv6" value={form.public_ipv6} onChange={(v) => setField("public_ipv6", v)} />
              </div>

              <div className="flex flex-wrap gap-3">
                <Toggle label="Dynamic IP" checked={form.dynamic_ip} onChange={(v) => setField("dynamic_ip", v)} />
              </div>

              {dnsConfig.mode !== "full" && (
                <Toggle label="Auto DNS" checked={dnsConfig.autoDNS}
                  onChange={(v) => onDNSConfig({ ...dnsConfig, autoDNS: v })} />
              )}

              {dnsRecords.length > 0 && (
                <div className="rounded-lg border bg-muted/30 p-3 space-y-1.5">
                  <p className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Cloudflare DNS</p>
                  {dnsRecords.map((r) => (
                    <div key={`${r.type}:${r.name}`} className="flex items-baseline gap-2 font-mono text-xs">
                      <Badge variant="outline" className="text-xs">{r.type}</Badge>
                      <span className="truncate">{r.name}</span>
                      <span className="text-muted-foreground">{r.action}</span>
                    </div>
                  ))}
                </div>
              )}

              <Button size="sm" variant="outline" className="w-full text-xs"
                onClick={createDNS} disabled={busy === "dns"}>
                Create DNS
              </Button>
            </TabsContent>

            <TabsContent value="advanced" className="space-y-3">
              <div className="space-y-2">
                <Label className="text-xs font-semibold">Features</Label>
                <div className="flex flex-wrap gap-1.5">
                  {adminNodeFeatures.map((f) => {
                    const on = form.features.includes(f);
                    return (
                      <Button key={f} type="button" size="sm" variant="outline"
                        onClick={() => setField("features", on
                          ? form.features.filter((x) => x !== f)
                          : [...form.features, f]
                        )}
                        className={cn(
                          "h-6 rounded border px-2 py-0.5 font-mono text-xs font-bold transition-colors",
                          on ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground"
                        )}>
                        {FEATURE_LABELS[f]}
                      </Button>
                    );
                  })}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <Field label="Action label" value={form.buy_label} onChange={(v) => setField("buy_label", v)} />
                <Field label="Action URL" value={form.buy_url} onChange={(v) => setField("buy_url", v)} />
              </div>

              <div className="grid grid-cols-1 gap-2">
                <Field label="BGP URL override" value={form.bgp_url} onChange={(v) => setField("bgp_url", v)} />
              </div>

            </TabsContent>

            <TabsContent value="deploy" className="space-y-3">
              <NodeDeployCard
                nodeInit={nodeInit}
                nodeID={form.id.trim() || undefined}
                busy={busy === "init"}
                onIssueInit={form.id.trim() ? () => setReinitTarget({
                  ...formToNode(form, selectedNode, nodes),
                  active_init: nodeInit ? { node_id: form.id.trim(), ...nodeInit } : undefined,
                }) : undefined}
                onSaved={onSaved}
                onError={onError}
              />
            </TabsContent>
          </Tabs>

          <SheetFooter className="pt-4 border-t mt-4">
            <Button variant="outline" onClick={() => setSheetOpen(false)}>Cancel</Button>
            <Button onClick={saveNode} disabled={busy === "save"}>
              {form.id ? "Save Changes" : "Create Node"}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
      <Dialog open={!!deleteTarget} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="size-5 text-destructive" />
              Delete Node
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete <strong>{deleteTarget?.id}</strong>? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => deleteTarget && handleDelete(deleteTarget)} disabled={busy.startsWith("delete:")}>
              <Trash2 className="size-3 mr-1" /> Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={!!reinitTarget}
        onOpenChange={(open) => { if (!open) setReinitTarget(null); }}
        title="Reissue init key"
        description={`Issue a new one-time init key for ${reinitTarget?.id}. Any older unused key for this node will stop working. The new token stays visible until consumed or expired.`}
        confirmPhrase={reinitTarget?.id ?? ""}
        confirmLabel="Issue key"
        onConfirm={() => { if (reinitTarget) void handleReInit(reinitTarget); }}
      />
    </div>
  );
}

/** Prefer the reported build identity; older agents report only a version. */
function nodeVersionLabel(node: AdminNode): string {
  if (node.build_id) return `agent build ${node.build_id}`;
  return node.version ? `agent v${node.version}` : "agent version unknown";
}

export function formatNodeTime(seconds?: number): string {
  if (!seconds) return "never";
  const delta = Date.now() / 1000 - seconds;
  if (delta < 0) {
    const ahead = -delta;
    if (ahead < 60) return "in <1m";
    if (ahead < 3600) return `in ${Math.floor(ahead / 60)}m`;
    if (ahead < 86400) return `in ${Math.floor(ahead / 3600)}h`;
    if (ahead < 7 * 86400) return `in ${Math.floor(ahead / 86400)}d`;
    return new Date(seconds * 1000).toLocaleDateString();
  }
  if (delta < 60) return "just now";
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  if (delta < 7 * 86400) return `${Math.floor(delta / 86400)}d ago`;
  return new Date(seconds * 1000).toLocaleDateString();
}

function NodeStateBadges({ node, check }: { node: AdminNode; check?: AdminNodeCheck }) {
  // The node is out of sync when the config it confirmed serving trails the
  // current revision the controller has (e.g. a change it has not pulled yet).
  const configPending = (node.config_applied_version ?? 0) < node.config_version;
  return (
    <div className="flex flex-wrap gap-1">
      {node.update_available && (
        <Badge variant="outline" className="text-xs border-warning/50 text-warning" title="This node runs an older agent build than the one the controller distributes; re-run its install command to upgrade">
          update available
        </Badge>
      )}
      <AvailabilityBadge availability={node.availability} />
      <Badge variant="outline" className="text-xs" title={node.enabled ? "Enabled in configuration" : "Disabled in configuration"}>
        {node.enabled ? "enabled" : "disabled"}
      </Badge>
      {node.dynamic_ip && (
        <Badge variant="outline" className="text-xs">
          dyn
        </Badge>
      )}
      <Badge variant="outline" className="text-xs">
        {node.hidden ? <EyeOff className="size-2.5" /> : <Eye className="size-2.5" />}
      </Badge>
      {node.maintenance && <Badge variant="destructive" className="text-xs">maint</Badge>}
      <CertificateBadge certificate={node.certificate} />
      {configPending && (
        <Badge variant="outline" className="text-xs border-warning/50 text-warning" title="The node has not confirmed the latest config yet">
          config pending
        </Badge>
      )}
      {check && (
        <Badge variant={check.healthy ? "secondary" : "destructive"} className="text-xs gap-0.5" title={checkTitle(check)}>
          {check.healthy ? <CheckCircle2 className="size-2.5" /> : <XCircle className="size-2.5" />}
          {/* Only show a latency when it actually succeeded; a failure is the
              two 5s timeouts summed, which reads as a meaningless big number. */}
          {check.healthy
            ? `${check.checks.generate_204.duration_ms + check.checks.info.duration_ms}ms`
            : "needs attention"}
        </Badge>
      )}
    </div>
  );
}

function AvailabilityBadge({ availability }: { availability?: { available: boolean; reason: string; at: number } | null }) {
  if (!availability) {
    return (
      <Badge variant="outline" className="text-xs" title="No availability result yet (checked on the background pass)">
        unknown
      </Badge>
    );
  }
  const label = availability.available ? "online" : offlineLabel(availability.reason);
  return (
    <Badge
      variant={availability.available ? "secondary" : "destructive"}
      className="text-xs"
      title={`${availability.available ? "Reachable" : availability.reason || "unreachable"} · ${new Date(availability.at * 1000).toLocaleString()}`}
    >
      {label}
    </Badge>
  );
}

function offlineLabel(reason: string): string {
  switch (reason) {
    case "cert_invalid":
      return "no valid cert";
    case "agent_offline":
      return "offline";
    default:
      return reason ? `down (${reason})` : "offline";
  }
}

function CertificateBadge({ certificate }: { certificate?: { status: string; synced_at: number | null } | null }) {
  if (!certificate) {
    return (
      <Badge variant="outline" className="text-xs border-warning/50 text-warning" title="No managed certificate published yet; the node serves its self-signed fallback">
        self-signed
      </Badge>
    );
  }
  if (certificate.status === "synced") {
    return (
      <Badge variant="secondary" className="text-xs" title={`Certificate applied${certificate.synced_at ? ` at ${new Date(certificate.synced_at * 1000).toLocaleString()}` : ""}`}>
        TLS ok
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="text-xs border-warning/50 text-warning" title="Published to the node but not yet confirmed applied (the agent has not pulled and acknowledged it)">
      TLS not applied
    </Badge>
  );
}

function checkTitle(check: AdminNodeCheck): string {
  if (check.healthy) return `generate_204 ${check.checks.generate_204.duration_ms}ms · info ${check.checks.info.duration_ms}ms`;
  const parts = [check.checks.generate_204, check.checks.info]
    .map((endpoint) => endpoint.error ?? (endpoint.status ? `HTTP ${endpoint.status}` : "failed"))
    .filter(Boolean);
  return `Unhealthy: ${parts.join(" · ")}`;
}

function Field({ label, value, onChange, disabled = false }: {
  label: string; value: string; onChange: (v: string) => void; disabled?: boolean;
}) {
  const inputId = useId();
  return (
    <div className="space-y-1">
      <Label htmlFor={inputId} className="text-xs">{label}</Label>
      <Input id={inputId} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}
        className="h-8 text-sm" />
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center gap-1.5 text-xs text-muted-foreground">
      <Checkbox checked={checked} onCheckedChange={(value) => onChange(value === true)} />
      {label}
    </label>
  );
}

function nodeToForm(node: AdminNode): AdminNodeFormInput {
  return {
    internal_id: node.internal_id,
    id: node.id,
    domain: node.domain,
    port: node.port ?? 443,
    domain_v4: node.domain_v4 ?? "",
    domain_v6: node.domain_v6 ?? "",
    display_name: node.display_name ?? node.id,
    display_label: node.display_label ?? "",
    public_ipv4: node.public_ipv4 ?? "",
    public_ipv6: node.public_ipv6 ?? "",
    description: node.description ?? "",
    buy_url: node.buy_url ?? "",
    buy_label: node.buy_label ?? "",
    bgp_url: node.bgp_url ?? "",
    dynamic_ip: Boolean(node.dynamic_ip),
    profile_id: node.profile_id ?? "default",
    enabled: node.enabled,
    hidden: node.hidden,
    maintenance: Boolean(node.maintenance),
    features: (node.features ?? [...adminNodeFeatures]).filter(isAdminNodeFeature),
  };
}

function formToNode(form: AdminNodeFormInput, selectedNode: string | null, nodes: AdminNode[]): AdminNode {
  const existing = nodes.find((node) => node.id === (selectedNode || form.id.trim()));
  return existing ?? {
    id: form.id.trim(),
    internal_id: form.internal_id,
    domain: form.domain.trim(),
    port: form.port,
    domain_v4: form.domain_v4.trim() || undefined,
    domain_v6: form.domain_v6.trim() || undefined,
    display_name: form.display_name.trim(),
    display_label: form.display_label.trim() || undefined,
    features: form.features,
    has_ipv4: Boolean(form.public_ipv4.trim()),
    has_ipv6: Boolean(form.public_ipv6.trim()),
    maintenance: form.maintenance,
    dynamic_ip: form.dynamic_ip,
    public_ipv4: form.public_ipv4.trim() || undefined,
    public_ipv6: form.public_ipv6.trim() || undefined,
    description: form.description.trim() || undefined,
    action_url: form.buy_url.trim() || undefined,
    action_label: form.buy_label.trim() || undefined,
    buy_url: form.buy_url.trim() || undefined,
    buy_label: form.buy_label.trim() || undefined,
    bgp_url: form.bgp_url.trim() || undefined,
    profile_id: form.profile_id.trim() || "default",
    enabled: form.enabled,
    hidden: form.hidden,
    config_version: 1,
    created_at: 0,
    updated_at: 0,
  };
}

function StatCard({ icon: Icon, label, value, color }: {
  icon: typeof Server; label: string; value: number; color: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-xl border bg-card p-3">
      <div className={cn("flex h-8 w-8 items-center justify-center rounded-lg bg-muted", color)}>
        <Icon className="size-4" />
      </div>
      <div>
        <div className="text-lg font-bold leading-none">{value}</div>
        <div className="text-xs text-muted-foreground">{label}</div>
      </div>
    </div>
  );
}

async function copyText(text: string, label: string, onSaved: (msg: string) => void, onError: (msg: string) => void) {
  if (!navigator.clipboard) return onError("clipboard unavailable");
  try {
    await navigator.clipboard.writeText(text);
    onSaved(`copied ${label}`);
  } catch { onError("clipboard write failed"); }
}

function NodeCard({
  node, check, isSelected, busy,
  canMoveUp, canMoveDown, onSelect, onCheck, onToggle, onReInit, onDelete, onMove, onSaved, onError,
}: {
  node: AdminNode; check?: AdminNodeCheck; isSelected: boolean; busy: string;
  canMoveUp: boolean; canMoveDown: boolean;
  onSelect: () => void; onCheck: () => void; onToggle: () => void;
  onReInit: () => void; onDelete: () => void; onMove: (direction: -1 | 1) => void;
  onSaved: (msg: string) => void; onError: (msg: string) => void;
}) {
  const isBusy = busy.startsWith("check:") || busy.startsWith("toggle:") || busy.startsWith("init:") || busy.startsWith("delete:");
  return (
    <div
      className={cn(
        "group relative rounded-xl border bg-card p-4 transition-all hover:shadow-sm cursor-pointer",
        isSelected && "ring-2 ring-primary/30 border-primary/40"
      )}
      onClick={onSelect}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="font-mono text-sm font-bold text-primary truncate">{node.id}</h3>
            <NodeStateBadges node={node} check={check} />
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground truncate">{node.display_name || node.domain}</p>
        </div>
        <div className="flex flex-shrink-0 items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
          <Button size="sm" variant="ghost" className="h-6 w-6 p-0" title="Move up"
            disabled={!canMoveUp || busy === `move:${node.id}`} onClick={() => onMove(-1)}>
            <ArrowUp className="size-3.5" />
          </Button>
          <Button size="sm" variant="ghost" className="h-6 w-6 p-0" title="Move down"
            disabled={!canMoveDown || busy === `move:${node.id}`} onClick={() => onMove(1)}>
            <ArrowDown className="size-3.5" />
          </Button>
          <ChevronRight className={cn("size-4 text-muted-foreground transition-transform", isSelected && "rotate-90 text-primary")} />
        </div>
      </div>

      <div className="mt-3 space-y-1.5">
        {node.domain && (
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-muted-foreground">Domain</span>
            <span className="font-mono truncate">{node.domain}</span>
          </div>
        )}
        {node.display_label && (
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-muted-foreground">Location</span>
            <span>{node.display_label}</span>
          </div>
        )}
        <div className="flex items-center gap-1.5 text-xs">
          <span className="text-muted-foreground">IP</span>
          <span className="font-mono">{node.public_ipv4 || "—"}</span>
          {node.public_ipv6 && <span className="font-mono text-muted-foreground">/ {node.public_ipv6}</span>}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          <span>{nodeVersionLabel(node)}</span>
          <span>·</span>
          <span>updated {formatNodeTime(node.updated_at)}</span>
          {node.last_seen_at ? (
            <>
              <span>·</span>
              <span>seen {formatNodeTime(node.last_seen_at)}</span>
            </>
          ) : null}
          {node.certificate ? (
            <>
              <span>·</span>
              <span>cert expires {formatNodeTime(node.certificate.cert_expires_at)}</span>
            </>
          ) : null}
          {check && (
            <>
              <span>·</span>
              <span className={check.healthy ? "text-success" : "text-destructive"}>
                {check.healthy
                  ? `${check.checks.generate_204.duration_ms + check.checks.info.duration_ms}ms`
                  : "check failed"}
              </span>
            </>
          )}
        </div>
      </div>

      <div className="mt-4 flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
        <Button size="sm" variant="outline" className="h-7 gap-1 text-xs flex-1"
          onClick={onCheck} disabled={busy === `check:${node.id}`}>
          <Activity className="size-3" /> Check
        </Button>
        <Button size="sm" variant={node.enabled ? "outline" : "default"}
          className={cn("h-7 gap-1 text-xs flex-1", node.enabled && "border-warning/40 text-warning hover:bg-warning/10")}
          onClick={onToggle} disabled={busy === `toggle:${node.id}`}>
          {node.enabled ? <><PowerOff className="size-3" /> Disable</> : <><Power className="size-3" /> Enable</>}
        </Button>
        <Popover>
          <PopoverTrigger asChild>
            <Button size="sm" variant="ghost" className="h-7 w-7 p-0">
              <Settings className="size-3.5" />
            </Button>
          </PopoverTrigger>
          <PopoverContent align="end" className="w-44 p-1">
            <button
              className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-muted disabled:opacity-50"
              onClick={onReInit} disabled={isBusy}
            >
              <RefreshCw className="size-3.5" /> Re-init Key
            </button>
            <button
              className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-muted disabled:opacity-50"
              onClick={() => void copyText(node.domain, "domain", onSaved, onError)}
            >
              <Copy className="size-3.5" /> Copy Domain
            </button>
            <div className="my-1 h-px bg-border" />
            <button
              className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-50"
              onClick={onDelete} disabled={isBusy}
            >
              <Trash2 className="size-3.5" /> Delete
            </button>
          </PopoverContent>
        </Popover>
      </div>
    </div>
  );
}
