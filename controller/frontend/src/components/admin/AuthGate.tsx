import { type FormEvent, type SetStateAction, useId, useState } from "react";
import { AlertTriangle, Database, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ConfirmDialog } from "./ConfirmDialog";
import type { DatabaseStatus } from "@/lib/api";

interface Props {
  onboarding: boolean;
  dbInitRequired: boolean;
  dbStatus?: DatabaseStatus;
  unavailable: boolean;
  form: { username: string; password: string; totpCode: string };
  busy: string;
  message: string;
  onChange: (v: SetStateAction<{ username: string; password: string; totpCode: string }>) => void;
  onSubmit: (mode: "setup" | "login") => void;
  onInitDatabase: (confirm?: string) => void;
}

export function AuthGate({ onboarding, dbInitRequired, dbStatus, unavailable, form, busy, message, onChange, onSubmit, onInitDatabase }: Props) {
  const mode = onboarding ? "setup" : "login";
  const usernameId = useId();
  const passwordId = useId();
  const totpId = useId();
  const errorId = useId();
  const [resetOpen, setResetOpen] = useState(false);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(mode);
  }

  if (unavailable) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex max-w-sm flex-col gap-2 rounded-xl border bg-card p-6 text-center">
          <p className="text-sm font-semibold text-foreground">Service Unconfigured</p>
          <p className="text-sm text-muted-foreground">{message || "Configure database or service credentials before using admin."}</p>
        </div>
      </div>
    );
  }

  if (dbInitRequired) {
    const resetRequired = dbStatus?.status === "incompatible";
    const missingTables = dbStatus?.missing_tables ?? [];
    const existingCount = dbStatus?.table_count ?? 0;
    const missingPreview = missingTables.slice(0, 6).join(", ");
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-4">
        <div className="flex w-full max-w-md flex-col gap-4 rounded-xl border bg-card p-6">
          <div className="flex items-center gap-2">
            {resetRequired ? <AlertTriangle className="size-4 text-destructive" /> : <Database className="size-4 text-primary" />}
            <h1 className="text-lg font-bold">
              {resetRequired ? "Database Reset Required" : "Initialize Database"}
            </h1>
          </div>
          <p className="text-sm text-muted-foreground">
            {resetRequired
              ? "The bound DB is not empty and does not match this project's schema. Resetting will drop existing tables before creating the Looking Glass schema."
              : "The DB binding is present but empty. Initialize the schema before creating the first administrator."}
          </p>
          {dbStatus && (
            <div className="rounded-lg border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
              <p><span className="font-medium text-foreground">Tables:</span> {existingCount}</p>
              {missingPreview && (
                <p className="mt-1">
                  <span className="font-medium text-foreground">Missing:</span> {missingPreview}
                  {missingTables.length > 6 ? `, +${missingTables.length - 6} more` : ""}
                </p>
              )}
            </div>
          )}
          {message && (
            <p id={errorId} role="alert" className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {message}
            </p>
          )}
          <Button
            type="button"
            className="w-full"
            variant={resetRequired ? "destructive" : "default"}
            disabled={busy === "db-init"}
            onClick={() => resetRequired ? setResetOpen(true) : onInitDatabase()}
          >
            {resetRequired ? "Reset and Initialize" : "Initialize Database"}
          </Button>
          <ConfirmDialog
            open={resetOpen}
            onOpenChange={setResetOpen}
            title="Reset database"
            description="This will drop existing tables in the bound database and recreate the Looking Glass schema. This cannot be undone from the app."
            confirmPhrase="RESET DATABASE"
            confirmLabel="Reset Database"
            variant="destructive"
            onConfirm={() => onInitDatabase("RESET DATABASE")}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <form
        className="flex w-full max-w-sm flex-col gap-4 rounded-xl border bg-card p-6"
        onSubmit={submit}
        aria-busy={busy === mode}
        aria-describedby={message ? errorId : undefined}
      >
        <div className="flex items-center gap-2">
          <Shield className="size-4 text-primary" />
          <h1 className="text-lg font-bold">
            {onboarding ? "Create First Admin" : "Admin Login"}
          </h1>
        </div>
        <p className="text-sm text-muted-foreground">
          {onboarding ? "Initialize this Worker with the first administrator." : "Sign in to manage this Looking Glass instance."}
        </p>
        {message && (
          <p id={errorId} role="alert" className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {message}
          </p>
        )}
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor={usernameId} className="text-sm">Username</Label>
            <Input
              id={usernameId}
              value={form.username}
              autoComplete="username"
              aria-describedby={message ? errorId : undefined}
              onChange={(e) => onChange((c) => ({ ...c, username: e.target.value }))}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor={passwordId} className="text-sm">Password</Label>
            <Input
              id={passwordId}
              type="password"
              value={form.password}
              autoComplete={onboarding ? "new-password" : "current-password"}
              aria-describedby={message ? errorId : undefined}
              onChange={(e) => onChange((c) => ({ ...c, password: e.target.value }))}
            />
          </div>
          {!onboarding && (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor={totpId} className="text-sm">TOTP Code <span className="text-muted-foreground">(optional)</span></Label>
              <Input
                id={totpId}
                value={form.totpCode}
                autoComplete="one-time-code"
                inputMode="numeric"
                aria-describedby={message ? errorId : undefined}
                onChange={(e) => onChange((c) => ({ ...c, totpCode: e.target.value }))}
              />
            </div>
          )}
          <Button type="submit" className="w-full" disabled={busy === mode}>
            {onboarding ? "Create Admin" : "Sign In"}
          </Button>
        </div>
      </form>
    </div>
  );
}
