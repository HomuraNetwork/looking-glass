import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { AdminShell, type AdminSection } from "./admin/AdminShell";
import { AuthGate } from "./admin/AuthGate";
import { AdminNodes, type DNSConfig } from "./admin/AdminNodes";
import { AdminOverview, type AdminSectionTarget } from "./admin/AdminOverview";
import { AdminBranding } from "./admin/AdminBranding";
import { AdminSystem, type AdminSystemTab } from "./admin/AdminSystem";
import { AdminRawConfig } from "./admin/AdminRawConfig";
import { AdminUsers } from "./admin/AdminUsers";
import type {
  AdminManagedCertificate,
  AdminNode,
  AdminProjectSetting,
  AdminRuntimeSecret,
  AdminSession,
  AdminTotpSetup,
  AdminUser,
  DatabaseStatus,
} from "@/lib/api";
import {
  adminSession,
  getAdminDNSSettings,
  initAdminDatabase,
  isUnauthorizedError,
  listAdminCertificates,
  listAdminNodes,
  listAdminProjectSettings,
  listAdminRuntimeSecrets,
  listAdminUsers,
  loginAdmin,
  logoutAdmin,
  saveAdminDNSSettings,
  setupAdmin,
} from "@/lib/api";

const emptySession: AdminSession = { authenticated: false, onboarding_required: false, user: null };

const defaultDNSConfig: DNSConfig = {
  base: "",
  v4Base: "",
  v6Base: "",
  singleBase: false,
  mode: "id",
  prefix: "",
  autoDNS: true,
};

const validSections: AdminSection[] = ["overview", "nodes", "branding", "system", "users", "advanced"];
const validSystemTabs: AdminSystemTab[] = ["dns", "certificates", "challenge", "keys", "behavior"];

function parseAdminHash(): { section: AdminSection; systemTab?: AdminSystemTab } {
  if (typeof window === "undefined") return { section: "overview" };
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [sec, tab] = raw.split(":");
  const section = validSections.includes(sec as AdminSection) ? (sec as AdminSection) : "overview";
  const systemTab = validSystemTabs.includes(tab as AdminSystemTab) ? (tab as AdminSystemTab) : undefined;
  return { section, systemTab };
}

export function AdminPanel() {
  const initialHash = parseAdminHash();
  const [session, setSession] = useState<AdminSession>(emptySession);
  const [authForm, setAuthForm] = useState({ username: "admin", password: "", totpCode: "" });
  const [section, setSectionState] = useState<AdminSection>(initialHash.section);
  const [systemTab, setSystemTabState] = useState<AdminSystemTab>(initialHash.systemTab ?? "dns");

  function setSection(next: AdminSection) {
    setSectionState(next);
    if (typeof window !== "undefined") {
      const hash = next === "system" ? `#${next}:${systemTab}` : `#${next}`;
      if (window.location.hash !== hash) {
        window.history.replaceState(null, "", hash);
      }
    }
  }

  function setSystemTab(next: AdminSystemTab) {
    setSystemTabState(next);
    if (typeof window !== "undefined") {
      const hash = `#system:${next}`;
      if (window.location.hash !== hash) {
        window.history.replaceState(null, "", hash);
      }
    }
  }

  useEffect(() => {
    function handleHashChange() {
      const parsed = parseAdminHash();
      setSectionState(parsed.section);
      if (parsed.systemTab) {
        setSystemTabState(parsed.systemTab);
      }
    }
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, [systemTab]);
  const [nodes, setNodes] = useState<AdminNode[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [secrets, setSecrets] = useState<AdminRuntimeSecret[]>([]);
  const [settings, setSettings] = useState<AdminProjectSetting[]>([]);
  const [certificates, setCertificates] = useState<AdminManagedCertificate[]>([]);
  const [dnsConfig, setDNSConfig] = useState<DNSConfig>(defaultDNSConfig);
  const [totpReveal, setTotpReveal] = useState<AdminTotpSetup | null>(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [unavailable, setUnavailable] = useState(false);
  const [dbStatus, setDbStatus] = useState<DatabaseStatus | undefined>();

  useEffect(() => {
    void bootstrap();
  }, []);

  function isDbBindingMissing(detail: string): boolean {
    return detail === "db_binding_missing" || /D1 database binding is missing/i.test(detail);
  }

  async function bootstrap() {
    setBusy("session");
    try {
      const next = await adminSession();
      setSession(next);
      setDbStatus(next.db_status);
      setUnavailable(false);
      if (next.authenticated) await loadAdmin();
    } catch (error) {
      const detail = error instanceof Error ? error.message : "session error";
      setUnavailable(isDbBindingMissing(detail) || detail === "service_unconfigured");
      setMessage(detail);
    } finally {
      setBusy("");
    }
  }

  /** Resolves true when every endpoint fulfilled; false on any failure (including 401). */
  async function loadAdmin(): Promise<boolean> {
    const results = await Promise.allSettled([
      listAdminNodes(),
      listAdminUsers(),
      listAdminRuntimeSecrets(),
      listAdminProjectSettings(),
      getAdminDNSSettings(),
      listAdminCertificates(),
    ]);
    const allFulfilled = results.every((result) => result.status === "fulfilled");
    const [loadedNodes, loadedUsers, loadedSecrets, loadedSettings, dns, certs] = results;
    if (loadedNodes.status === "fulfilled") setNodes(loadedNodes.value);
    if (loadedUsers.status === "fulfilled") setUsers(loadedUsers.value);
    if (loadedSecrets.status === "fulfilled") setSecrets(loadedSecrets.value);
    if (loadedSettings.status === "fulfilled") setSettings(loadedSettings.value);
    if (dns.status === "fulfilled" && dns.value) {
      const settings = dns.value;
      setDNSConfig((current) => ({
        ...current,
        base: settings.base,
        v4Base: settings.v4_base,
        v6Base: settings.v6_base,
        singleBase: settings.single_base,
      }));
    }
    if (certs.status === "fulfilled") setCertificates(certs.value.certificates);
    for (const result of results) {
      if (result.status !== "rejected") continue;
      const error = result.reason;
      if (isUnauthorizedError(error)) {
        // Session expired or revoked: drop back to the logged-out state.
        setSession(emptySession);
        toast.error("Session expired");
        return false;
      }
      handleError(error instanceof Error ? error.message : "Failed to load admin data");
    }
    return allFulfilled;
  }

  async function submitAuth(mode: "setup" | "login") {
    if (!authForm.username.trim() || authForm.password.length < 8) {
      setMessage("username and password (min 8 chars) required");
      return;
    }
    setBusy(mode);
    try {
      const next = mode === "setup"
        ? await setupAdmin({ username: authForm.username, password: authForm.password })
        : await loginAdmin({
            username: authForm.username,
            password: authForm.password,
            totp_code: authForm.totpCode || undefined,
          });
      setSession(next);
      setAuthForm((current) => ({ ...current, password: "", totpCode: "" }));
      setUnavailable(false);
      setMessage("");
      await loadAdmin();
      toast.success(mode === "setup" ? "Admin created" : "Signed in");
    } catch (error) {
      handleError(error instanceof Error ? error.message : "auth failed");
    } finally {
      setBusy("");
    }
  }

  async function initializeDatabase(confirm?: string) {
    setBusy("db-init");
    setMessage("");
    try {
      const result = await initAdminDatabase(confirm);
      setDbStatus(result.db_status);
      setSession({ authenticated: false, onboarding_required: true, db_init_required: false, db_status: result.db_status, user: null });
      toast.success("Database initialized");
      await bootstrap();
    } catch (error) {
      handleError(error instanceof Error ? error.message : "database initialization failed");
    } finally {
      setBusy("");
    }
  }

  /** Apply pending schema migrations without leaving the authenticated admin session. */
  async function applyDatabaseMigrations() {
    setBusy("db-migrate");
    try {
      const result = await initAdminDatabase();
      setDbStatus(result.db_status);
      const applied = result.applied ?? [];
      toast.success(applied.length > 0 ? `Applied ${applied.length} migration(s)` : "Schema already up to date");
    } catch (error) {
      handleError(error instanceof Error ? error.message : "database upgrade failed");
    } finally {
      setBusy("");
    }
  }

  async function signOut() {
    setBusy("logout");
    try {
      await logoutAdmin();
      setSession(emptySession);
      setNodes([]);
      setUsers([]);
      setSecrets([]);
      setSettings([]);
      setCertificates([]);
      setDNSConfig(defaultDNSConfig);
      setTotpReveal(null);
      setDbStatus(undefined);
      toast.success("Signed out");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "signout failed");
    } finally {
      setBusy("");
    }
  }

  async function saveDNS() {
    setBusy("dns");
    try {
      const result = await saveAdminDNSSettings({
        base: dnsConfig.base,
        v4_base: dnsConfig.v4Base,
        v6_base: dnsConfig.v6Base,
        single_base: dnsConfig.singleBase,
      });
      setDNSConfig((current) => ({
        ...current,
        base: result.base,
        v4Base: result.v4_base,
        v6Base: result.v6_base,
        singleBase: result.single_base,
      }));
      toast.success("DNS settings saved");
    } catch (error) {
      handleError(error instanceof Error ? error.message : "save failed");
    } finally {
      setBusy("");
    }
  }

  function handleError(messageText: string) {
    if (messageText === "unauthorized") setSession(emptySession);
    if (messageText === "onboarding_required") {
      setSession({ authenticated: false, onboarding_required: true, user: null });
    }
    if (messageText === "db_init_required" || messageText === "db_init_confirmation_required") {
      setSession({ authenticated: false, onboarding_required: false, db_init_required: true, db_status: dbStatus, user: null });
    }
    setUnavailable(isDbBindingMissing(messageText) || messageText === "service_unconfigured");
    if (!session.authenticated) setMessage(messageText);
    else toast.error(messageText);
  }

  /** Clear the admin session when any section refresh reports 401. */
  function handleRefreshError(error: unknown) {
    if (isUnauthorizedError(error)) {
      setSession(emptySession);
      toast.error("Session expired");
      return;
    }
    handleError(error instanceof Error ? error.message : "Failed to refresh admin data");
  }

  function updateSetting(next: AdminProjectSetting) {
    setSettings((previous) => previous.map((item) => (item.key === next.key ? next : item)));
  }

  function handleOverviewSection(target: AdminSectionTarget) {
    setSection(target.section);
    if (target.section === "system" && target.systemTab) {
      setSystemTab(target.systemTab);
    }
  }

  if (!session.authenticated || !session.user) {
    return (
      <AuthGate
        onboarding={session.onboarding_required}
        dbInitRequired={session.db_init_required === true}
        dbStatus={session.db_status ?? dbStatus}
        unavailable={unavailable}
        form={authForm}
        busy={busy}
        message={message}
        onChange={setAuthForm}
        onSubmit={submitAuth}
        onInitDatabase={initializeDatabase}
      />
    );
  }

  const updateSecret = (secret: AdminRuntimeSecret) =>
    setSecrets((previous) => previous.map((item) => (item.key === secret.key ? secret : item)));

  const pendingMigrations = session.db_status?.pending_migrations ?? dbStatus?.pending_migrations ?? [];

  return (
    <AdminShell
      section={section}
      onSection={setSection}
      username={session.user.username}
      siteName={(() => {
        const value = settings.find((item) => item.key === "PUBLIC_SITE_NAME")?.value;
        return typeof value === "string" && value ? value : "Looking Glass";
      })()}
      busy={!!busy}
      onRefresh={() => {
        setMessage("");
        void loadAdmin()
          .then((ok) => {
            if (ok) toast.success("Admin data refreshed");
          })
          .catch(() => {});
      }}
      onSignOut={signOut}
    >
      {pendingMigrations.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-warning/40 bg-warning/10 px-3.5 py-2.5">
          <div className="text-xs text-foreground">
            <span className="font-semibold">Schema update available.</span>{" "}
            {pendingMigrations.length} migration(s) pending: {pendingMigrations.join(", ")}
          </div>
          <Button size="sm" className="text-xs" disabled={busy === "db-migrate"} onClick={applyDatabaseMigrations}>
            {busy === "db-migrate" ? "Applying…" : "Apply update"}
          </Button>
        </div>
      )}
      {section === "overview" && (
        <AdminOverview
          nodes={nodes}
          secrets={secrets}
          settings={settings}
          dnsConfigured={Boolean(dnsConfig.base.trim())}
          onSection={handleOverviewSection}
        />
      )}
      {section === "nodes" && (
        <AdminNodes
          nodes={nodes}
          dnsConfig={dnsConfig}
          onDNSConfig={setDNSConfig}
          onSaved={(next) => toast.success(next)}
          onError={handleError}
          onRefresh={async () => {
            try {
              setNodes(await listAdminNodes());
            } catch (error) {
              handleRefreshError(error);
            }
          }}
          busy={busy}
          setBusy={setBusy}
        />
      )}
      {section === "branding" && (
        <AdminBranding
          settings={settings}
          onUpdate={updateSetting}
          onError={handleError}
          onSaved={(next) => toast.success(next)}
          busy={busy}
          setBusy={setBusy}
        />
      )}
      {section === "system" && (
        <AdminSystem
          settings={settings}
          secrets={secrets}
          certificates={certificates}
          tab={systemTab}
          onTabChange={setSystemTab}
          onUpdateSetting={updateSetting}
          onUpdateSecret={updateSecret}
          dnsConfig={{
            base: dnsConfig.base,
            v4Base: dnsConfig.v4Base,
            v6Base: dnsConfig.v6Base,
            singleBase: dnsConfig.singleBase,
          }}
          onDNSChange={(dns) => setDNSConfig((previous) => ({ ...previous, ...dns }))}
          onSaveDNS={saveDNS}
          onRefreshCertificates={async () => {
            try {
              setCertificates((await listAdminCertificates()).certificates);
            } catch (error) {
              handleRefreshError(error);
            }
          }}
          dnsBusy={busy === "dns"}
          onError={handleError}
          onSaved={(next) => toast.success(next)}
          busy={busy}
          setBusy={setBusy}
        />
      )}
      {section === "users" && (
        <AdminUsers
          users={users}
          currentUsername={session.user.username}
          totpReveal={totpReveal}
          onRefresh={() => {
            void listAdminUsers()
              .then(setUsers)
              .catch(handleRefreshError);
          }}
          onError={handleError}
          onSaved={(next) => toast.success(next)}
          onTotpReveal={setTotpReveal}
          busy={busy}
          setBusy={setBusy}
        />
      )}
      {section === "advanced" && (
        <AdminRawConfig
          settings={settings}
          secrets={secrets}
          onUpdateSetting={updateSetting}
          onUpdateSecret={updateSecret}
          onError={handleError}
          onSaved={(next) => toast.success(next)}
          busy={busy}
          setBusy={setBusy}
        />
      )}
    </AdminShell>
  );
}
