import { CheckCircle2, AlertCircle, ArrowRight, Server, Eye, Wrench } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { AdminNode, AdminRuntimeSecret, AdminProjectSetting } from "@/lib/api";
import type { AdminSection } from "./AdminShell";
import type { AdminSystemTab } from "./AdminSystem";

interface Props {
  nodes: AdminNode[];
  secrets: AdminRuntimeSecret[];
  settings: AdminProjectSetting[];
  dnsConfigured: boolean;
  onSection: (target: AdminSectionTarget) => void;
}

interface ChecklistItem {
  label: string;
  description: string;
  done: boolean;
  section: AdminSection;
  systemTab?: AdminSystemTab;
}

export interface AdminSectionTarget {
  section: AdminSection;
  systemTab?: AdminSystemTab;
}

export function AdminOverview({ nodes, secrets, settings, dnsConfigured, onSection }: Props) {
  const secretOk = (key: string) => secrets.find((s) => s.key === key)?.configured === true;
  const settingOk = (key: string) => settings.find((s) => s.key === key)?.configured === true;

  const enabled = nodes.filter((n) => n.enabled).length;
  const hidden = nodes.filter((n) => n.hidden).length;
  const maintenance = nodes.filter((n) => n.maintenance).length;

  const checklist: ChecklistItem[] = [
    {
      label: "Signing keys",
      description: "Token, config & admin Ed25519 keys",
      done: secretOk("LG_TOKEN_SIGN_JWK") && secretOk("LG_CONFIG_SIGN_JWK") && secretOk("LG_ADMIN_SIGN_JWK"),
      section: "system",
      systemTab: "keys",
    },
    {
      label: "Cloudflare DNS",
      description: "Zone ID, API token & base domains",
      done: settingOk("CLOUDFLARE_ZONE_ID") && secretOk("CLOUDFLARE_DNSUPDATE_API_KEY") && dnsConfigured,
      section: "system",
      systemTab: "dns",
    },
    {
      label: "Turnstile",
      description: "Site key & secret for challenges",
      done: settingOk("TURNSTILE_SITE_KEY") && secretOk("TURNSTILE_SECRET_KEY"),
      section: "system",
      systemTab: "challenge",
    },
    {
      label: "Branding",
      description: "Site name, logo & navigation",
      done: settingOk("PUBLIC_SITE_NAME") || settingOk("PUBLIC_LOGO_IMAGE_URL"),
      section: "branding",
    },
    {
      label: "First node",
      description: "Enroll at least one agent",
      done: nodes.length > 0,
      section: "nodes",
    },
  ];
  const remaining = checklist.filter((c) => !c.done).length;

  return (
    <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard icon={Server} label="Nodes" value={nodes.length} hint={`${enabled} enabled`} />
        <StatCard icon={CheckCircle2} label="Enabled" value={enabled} hint={`${nodes.length - enabled} off`} tone="ok" />
        <StatCard icon={Eye} label="Hidden" value={hidden} hint="not in public list" />
        <StatCard icon={Wrench} label="Maintenance" value={maintenance} hint="degraded" tone={maintenance > 0 ? "warn" : undefined} />
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle className="text-base">Setup checklist</CardTitle>
              <CardDescription>
                {remaining === 0 ? "All set — everything is configured." : `${remaining} item${remaining > 1 ? "s" : ""} left to configure.`}
              </CardDescription>
            </div>
            <Badge variant={remaining === 0 ? "secondary" : "outline"} className="text-xs">
              {checklist.length - remaining}/{checklist.length}
            </Badge>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {checklist.map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={() => onSection({ section: item.section, systemTab: item.systemTab })}
                className="group flex w-full items-center gap-3 rounded-lg border bg-background/60 px-3 py-2.5 text-left transition-colors hover:border-primary/40 hover:bg-muted/40"
              >
                {item.done
                  ? <CheckCircle2 className="size-4 flex-shrink-0 text-success" />
                  : <AlertCircle className="size-4 flex-shrink-0 text-warning" />}
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-semibold leading-tight">{item.label}</span>
                  <span className="block truncate text-xs text-muted-foreground">{item.description}</span>
                </span>
                <ArrowRight className="size-3.5 flex-shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
              </button>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-base">Nodes</CardTitle>
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => onSection({ section: "nodes" })}>
              Manage <ArrowRight className="size-3" />
            </Button>
          </CardHeader>
          <CardContent>
            {nodes.length === 0 ? (
              <p className="rounded-lg border border-dashed px-3 py-6 text-center text-sm text-muted-foreground">
                No nodes yet. Add one in the Nodes section to generate an install command.
              </p>
            ) : (
              <ul className="space-y-1.5">
                {nodes.slice(0, 6).map((node) => (
                  <li key={node.id} className="flex items-center gap-2 rounded-lg border bg-background/60 px-3 py-2">
                    <span className={cn("size-2 flex-shrink-0 rounded-full", node.enabled ? "bg-success" : "bg-muted-foreground/40")} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-sm font-semibold">{node.id}</span>
                      <span className="block truncate text-xs text-muted-foreground">{node.domain}</span>
                    </span>
                    {node.maintenance && <Badge variant="destructive" className="text-xs">maint</Badge>}
                    {node.hidden && <Badge variant="outline" className="text-xs">hidden</Badge>}
                  </li>
                ))}
                {nodes.length > 6 && (
                  <li className="px-3 pt-1 text-xs text-muted-foreground">+{nodes.length - 6} more…</li>
                )}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, hint, tone }: {
  icon: typeof Server; label: string; value: number; hint: string; tone?: "ok" | "warn";
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <div className={cn(
          "flex size-10 flex-shrink-0 items-center justify-center rounded-lg",
          tone === "ok" ? "bg-success/10 text-success"
            : tone === "warn" ? "bg-warning/10 text-warning"
            : "bg-primary/10 text-primary",
        )}>
          <Icon className="size-5" />
        </div>
        <div className="min-w-0">
          <p className="text-2xl font-bold leading-none">{value}</p>
          <p className="text-xs font-semibold text-foreground">{label}</p>
          <p className="truncate text-xs text-muted-foreground">{hint}</p>
        </div>
      </CardContent>
    </Card>
  );
}
