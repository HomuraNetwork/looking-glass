import { useMemo, useState } from "react";
import { Search, Pencil } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import type { AdminProjectSetting, AdminRuntimeSecret, PublicNavItem } from "@/lib/api";
import { saveAdminProjectSetting, saveAdminRuntimeSecret } from "@/lib/api";

interface Props {
  settings: AdminProjectSetting[];
  secrets: AdminRuntimeSecret[];
  onUpdateSetting: (s: AdminProjectSetting) => void;
  onUpdateSecret: (s: AdminRuntimeSecret) => void;
  onError: (msg: string) => void;
  onSaved: (msg: string) => void;
  busy: string;
  setBusy: (s: string) => void;
}

type Kind = "secret" | "string" | "boolean" | "json";

interface Row {
  key: string;
  label: string;
  kind: Kind;
  configured: boolean;
  source: string;
  display: string;
  /** initial draft value for the editor */
  draft: string;
}

function rowsFrom(settings: AdminProjectSetting[], secrets: AdminRuntimeSecret[]): Row[] {
  const settingRows: Row[] = settings.map((s) => {
    const kind: Kind = s.type;
    let display: string;
    let draft: string;
    if (s.type === "boolean") {
      display = s.value === true ? "true" : "false";
      draft = display;
    } else if (s.type === "json") {
      const len = Array.isArray(s.value) ? s.value.length : 0;
      display = `${len} item${len === 1 ? "" : "s"}`;
      draft = JSON.stringify(Array.isArray(s.value) ? s.value : [], null, 2);
    } else {
      display = typeof s.value === "string" && s.value ? s.value : "—";
      draft = typeof s.value === "string" ? s.value : "";
    }
    return { key: s.key, label: s.label, kind, configured: s.configured, source: s.source, display, draft };
  });
  const secretRows: Row[] = secrets.map((s) => ({
    key: s.key, label: s.label, kind: "secret", configured: s.configured, source: s.source,
    display: s.configured ? "•••••• stored" : "—", draft: "",
  }));
  return [...settingRows, ...secretRows].sort((a, b) => a.key.localeCompare(b.key));
}

const KIND_LABEL: Record<Kind, string> = { secret: "secret", string: "string", boolean: "boolean", json: "json" };

export function AdminRawConfig({ settings, secrets, onUpdateSetting, onUpdateSecret, onError, onSaved, busy, setBusy }: Props) {
  const [query, setQuery] = useState("");
  const [editing, setEditing] = useState<Row | null>(null);
  const [draft, setDraft] = useState("");
  const [pending, setPending] = useState<{ row: Row; value: string } | null>(null);

  const rows = useMemo(() => rowsFrom(settings, secrets), [settings, secrets]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => r.key.toLowerCase().includes(q) || r.label.toLowerCase().includes(q));
  }, [rows, query]);

  function openEditor(row: Row) {
    setDraft(row.draft);
    setEditing(row);
  }

  function requestSave() {
    if (!editing) return;
    setPending({ row: editing, value: draft });
    setEditing(null);
  }

  async function applyPending() {
    if (!pending) return;
    const { row, value } = pending;
    setPending(null);
    setBusy(`raw:${row.key}`);
    try {
      if (row.kind === "secret") {
        const trimmed = value.trim();
        if (!trimmed) throw new Error("secret value required");
        // override when already configured — raw editing implies intent to replace
        onUpdateSecret(await saveAdminRuntimeSecret(row.key, trimmed, row.configured));
      } else if (row.kind === "boolean") {
        onUpdateSetting(await saveAdminProjectSetting(row.key, value === "true"));
      } else if (row.kind === "json") {
        onUpdateSetting(await saveAdminProjectSetting(row.key, JSON.parse(value) as PublicNavItem[]));
      } else {
        onUpdateSetting(await saveAdminProjectSetting(row.key, value.trim()));
      }
      onSaved(`Saved ${row.key}`);
    } catch (e) { onError(e instanceof Error ? e.message : "save failed"); }
    finally { setBusy(""); }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Raw configuration</CardTitle>
        <CardDescription>
          Every project setting and runtime secret in one place. Editing here writes the live value — prefer the dedicated sections above for day-to-day changes.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="relative max-w-sm">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search keys…" className="h-9 pl-8" />
        </div>

        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead className="hidden sm:table-cell">Kind</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="hidden md:table-cell">Source</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((row) => (
                <TableRow key={row.key}>
                  <TableCell className="align-top">
                    <div className="font-semibold leading-tight">{row.label}</div>
                    <div className="font-mono text-xs text-muted-foreground">{row.key}</div>
                  </TableCell>
                  <TableCell className="hidden align-top sm:table-cell">
                    <Badge variant={row.kind === "secret" ? "outline" : "secondary"} className="text-xs">
                      {KIND_LABEL[row.kind]}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[16rem] align-top">
                    <span className="block truncate font-mono text-xs">{row.display}</span>
                    <Badge variant={row.configured ? "secondary" : "outline"} className="mt-1 text-[0.65rem]">
                      {row.configured ? "set" : "unset"}
                    </Badge>
                  </TableCell>
                  <TableCell className="hidden align-top md:table-cell">
                    <Badge variant="outline" className="text-xs">{row.source}</Badge>
                  </TableCell>
                  <TableCell className="align-top text-right">
                    <Button size="icon" variant="ghost" className="size-8" aria-label={`Edit ${row.key}`}
                      disabled={busy === `raw:${row.key}`} onClick={() => openEditor(row)}>
                      <Pencil className="size-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                    No keys match “{query}”.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>

      <Dialog open={!!editing} onOpenChange={(v) => { if (!v) setEditing(null); }}>
        <DialogContent>
          {editing && (
            <>
              <DialogHeader>
                <DialogTitle className="font-mono text-sm">{editing.key}</DialogTitle>
                <DialogDescription>{editing.label} · {KIND_LABEL[editing.kind]}</DialogDescription>
              </DialogHeader>
              <div className="py-2">
                {editing.kind === "boolean" ? (
                  <label className="flex items-center justify-between rounded-lg border bg-background/60 px-3 py-2.5">
                    <span className="text-sm font-medium">Enabled</span>
                    <Switch checked={draft === "true"} onCheckedChange={(v) => setDraft(v ? "true" : "false")} />
                  </label>
                ) : editing.kind === "json" ? (
                  <textarea value={draft} onChange={(e) => setDraft(e.target.value)}
                    className="min-h-40 w-full rounded-md border bg-background p-2 font-mono text-xs" />
                ) : editing.kind === "secret" ? (
                  <div className="space-y-1.5">
                    <Input type="password" value={draft} onChange={(e) => setDraft(e.target.value)}
                      placeholder={editing.configured ? "enter a new value to replace" : "paste value"}
                      className="h-9 font-mono text-xs" />
                    <p className="text-xs text-muted-foreground">
                      {editing.configured ? "Saving replaces the stored secret." : "The value is saved by the controller and never shown again."}
                    </p>
                  </div>
                ) : (
                  <Input value={draft} onChange={(e) => setDraft(e.target.value)} className="h-9 font-mono text-xs" autoFocus />
                )}
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setEditing(null)}>Cancel</Button>
                <Button onClick={requestSave}>Save</Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!pending} onOpenChange={(v) => { if (!v) setPending(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Apply change?</AlertDialogTitle>
            <AlertDialogDescription>
              This updates <span className="font-mono text-foreground">{pending?.row.key}</span> in the live configuration.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setPending(null)}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => void applyPending()}>Save change</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}
