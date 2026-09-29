import { useState } from "react";
import { UserPlus, KeyRound, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "./ConfirmDialog";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { AdminUser, AdminTotpSetup } from "@/lib/api";
import {
  createAdminUser, deleteAdminUser, resetAdminUserPassword,
  setupAdminUserTotp, resetAdminUserTotp,
} from "@/lib/api";

interface Props {
  users: AdminUser[];
  currentUsername: string;
  totpReveal: AdminTotpSetup | null;
  onRefresh: () => void;
  onError: (msg: string) => void;
  onSaved: (msg: string) => void;
  onTotpReveal: (t: AdminTotpSetup | null) => void;
  busy: string;
  setBusy: (s: string) => void;
}

export function AdminUsers({
  users, currentUsername, totpReveal, onRefresh, onError, onSaved, onTotpReveal, busy, setBusy,
}: Props) {
  const [newAdmin, setNewAdmin] = useState({ username: "", password: "" });
  const [resetPasswords, setResetPasswords] = useState<Record<string, string>>({});
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [totpAction, setTotpAction] = useState<{ type: "setup" | "reset"; username: string } | null>(null);
  const [reauth, setReauth] = useState({ password: "", totp: "" });

  async function addUser() {
    if (!newAdmin.username.trim() || newAdmin.password.length < 8)
      return onError("username and password (min 8 chars) required");
    setBusy("create");
    try {
      await createAdminUser(newAdmin.username, newAdmin.password);
      setNewAdmin({ username: "", password: "" });
      onRefresh();
      onSaved("user added");
    } catch (e) { onError(e instanceof Error ? e.message : "create failed"); }
    finally { setBusy(""); }
  }

  async function resetPassword(username: string) {
    const pw = resetPasswords[username] ?? "";
    if (pw.length < 8) return onError("password must be at least 8 characters");
    setBusy(`reset:${username}`);
    try {
      await resetAdminUserPassword(username, pw);
      setResetPasswords((p) => ({ ...p, [username]: "" }));
      onRefresh();
      onSaved(`password reset for ${username}`);
    } catch (e) { onError(e instanceof Error ? e.message : "reset failed"); }
    finally { setBusy(""); }
  }

  async function setupTotp(username: string) {
    setBusy(`totp:${username}`);
    try {
      onTotpReveal(await setupAdminUserTotp(username, reauth.password, reauth.totp || undefined));
      onRefresh();
      onSaved(`TOTP set up for ${username}`);
    } catch (e) { onError(e instanceof Error ? e.message : "TOTP setup failed"); }
    finally { setBusy(""); closeTotpAction(); }
  }

  async function clearTotp(username: string) {
    setBusy(`totp-reset:${username}`);
    try {
      await resetAdminUserTotp(username, reauth.password, reauth.totp || undefined);
      if (totpReveal?.user.username === username) onTotpReveal(null);
      onRefresh();
      onSaved(`TOTP reset for ${username}`);
    } catch (e) { onError(e instanceof Error ? e.message : "TOTP reset failed"); }
    finally { setBusy(""); closeTotpAction(); }
  }

  function closeTotpAction() {
    setTotpAction(null);
    setReauth({ password: "", totp: "" });
  }

  async function confirmTotpAction() {
    if (!totpAction || !reauth.password) return onError("current password is required");
    if (users.find((user) => user.username === currentUsername)?.has_totp && !reauth.totp) {
      return onError("current authenticator code is required");
    }
    if (totpAction.type === "setup") await setupTotp(totpAction.username);
    else await clearTotp(totpAction.username);
  }

  async function doDelete(username: string) {
    setBusy(`delete:${username}`);
    try {
      await deleteAdminUser(username);
      onRefresh();
      onSaved(`deleted ${username}`);
    } catch (e) { onError(e instanceof Error ? e.message : "delete failed"); }
    finally { setBusy(""); }
  }

  return (
    <div className="max-w-xl space-y-5">
      <h2 className="text-base font-bold">Admin Users</h2>

      <div className="rounded-xl border bg-card p-3.5 space-y-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <UserPlus className="size-3.5" /> Add Admin
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <Label className="text-xs">Username</Label>
            <Input value={newAdmin.username}
              onChange={(e) => setNewAdmin((n) => ({ ...n, username: e.target.value }))}
              className="h-8 text-sm" />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Password</Label>
            <Input type="password" value={newAdmin.password}
              onChange={(e) => setNewAdmin((n) => ({ ...n, password: e.target.value }))}
              className="h-8 text-sm" />
          </div>
        </div>
        <Button size="sm" className="text-xs" onClick={addUser} disabled={busy === "create"}>
          Add
        </Button>
      </div>

      {totpReveal && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-50 dark:bg-amber-950/30 p-3.5 space-y-2">
          <p className="text-xs font-bold uppercase tracking-wider text-amber-700 dark:text-amber-400">
            TOTP Secret — {totpReveal.user.username}
          </p>
          <pre className="rounded bg-background p-2 font-mono text-xs break-all whitespace-pre-wrap">
            {totpReveal.secret}
          </pre>
          <pre className="rounded bg-background p-2 font-mono text-xs break-all whitespace-pre-wrap">
            {totpReveal.otpauth_url}
          </pre>
          <Button size="sm" variant="outline" className="text-xs" onClick={() => onTotpReveal(null)}>
            Dismiss
          </Button>
        </div>
      )}

      {users.map((user) => (
        <div key={user.id} className="rounded-xl border bg-card p-3.5 space-y-3">
          <div className="flex items-start justify-between gap-2">
            <div>
              <p className="text-sm font-semibold">
                {user.username}
                {user.username === currentUsername && (
                  <span className="ml-2 text-xs text-muted-foreground">(you)</span>
                )}
              </p>
              <p className="text-xs text-muted-foreground">
                {new Date(user.updated_at * 1000).toLocaleString()}
              </p>
            </div>
            <div className="flex gap-1.5 flex-shrink-0">
              <Badge variant="outline" className="text-xs">{user.role}</Badge>
              <Badge variant={user.has_totp ? "secondary" : "outline"} className="text-xs">
                {user.has_totp ? "totp" : "no totp"}
              </Badge>
            </div>
          </div>

          <div className="flex gap-2">
            <Input type="password" placeholder="New password…"
              value={resetPasswords[user.username] ?? ""}
              onChange={(e) => setResetPasswords((p) => ({ ...p, [user.username]: e.target.value }))}
              className="h-8 flex-1 text-sm" />
            <Button size="sm" variant="outline" className="h-8 text-xs"
              onClick={() => resetPassword(user.username)}
              disabled={busy === `reset:${user.username}`}>
              <KeyRound className="size-3" /> Reset pw
            </Button>
          </div>

          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="flex-1 text-xs"
              onClick={() => { setReauth({ password: "", totp: "" }); setTotpAction({ type: "setup", username: user.username }); }}
              disabled={busy === `totp:${user.username}`}>
              Setup TOTP
            </Button>
            <Button size="sm" variant="outline" className="flex-1 text-xs"
              onClick={() => { setReauth({ password: "", totp: "" }); setTotpAction({ type: "reset", username: user.username }); }}
              disabled={busy === `totp-reset:${user.username}`}>
              Reset TOTP
            </Button>
            <Button size="sm" variant="outline" className="h-8 gap-1 text-xs text-destructive hover:bg-destructive/10"
              onClick={() => setDeleteTarget(user.username)}>
              <Trash2 className="size-3" />
            </Button>
          </div>
        </div>
      ))}

      <Dialog open={!!totpAction} onOpenChange={(open) => { if (!open) closeTotpAction(); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{totpAction?.type === "setup" ? "Confirm TOTP setup" : "Confirm TOTP reset"}</DialogTitle>
            <DialogDescription>
              Re-enter your admin credentials to change two-factor authentication for {totpAction?.username}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="totp-reauth-password">Current password</Label>
              <Input id="totp-reauth-password" type="password" autoComplete="current-password" value={reauth.password}
                onChange={(event) => setReauth((value) => ({ ...value, password: event.target.value }))} />
            </div>
            {users.find((user) => user.username === currentUsername)?.has_totp && (
              <div className="space-y-1">
                <Label htmlFor="totp-reauth-code">Current authenticator code</Label>
                <Input id="totp-reauth-code" inputMode="numeric" autoComplete="one-time-code" value={reauth.totp}
                  onChange={(event) => setReauth((value) => ({ ...value, totp: event.target.value }))} />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={closeTotpAction}>Cancel</Button>
            <Button onClick={() => void confirmTotpAction()} disabled={!!busy}>
              {totpAction?.type === "setup" ? "Continue" : "Reset TOTP"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {deleteTarget && (
        <ConfirmDialog
          open={true}
          onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
          title={`Delete ${deleteTarget}`}
          description={`This will permanently delete the admin account "${deleteTarget}". This cannot be undone.`}
          confirmPhrase={deleteTarget}
          confirmLabel="Delete"
          variant="destructive"
          onConfirm={() => doDelete(deleteTarget)}
        />
      )}
    </div>
  );
}
