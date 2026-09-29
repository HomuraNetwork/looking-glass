import { useEffect, useState } from "react";
import {
  BadgeCheck,
  Check,
  ExternalLink,
  Globe2,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AdminDNS } from "./AdminDNS";
import { ConfirmDialog } from "./ConfirmDialog";
import { CertificateReissueDialog } from "./CertificateReissueDialog";
import type { AdminCertificateDebug, AdminManagedCertificate, AdminProjectSetting, AdminRuntimeSecret } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  AdminCertificateActionError,
  importAdminCertificate,
  saveAdminProjectSetting,
  saveAdminRuntimeSecret,
  generateAdminRuntimeSecret,
  resetAdminProjectSetting,
  registerZeroSSLEAB,
  syncAdminCertificates,
} from "@/lib/api";

interface DNSFormConfig {
  base: string;
  v4Base: string;
  v6Base: string;
  singleBase: boolean;
}

interface Props {
  settings: AdminProjectSetting[];
  secrets: AdminRuntimeSecret[];
  certificates: AdminManagedCertificate[];
  tab: AdminSystemTab;
  onTabChange: (tab: AdminSystemTab) => void;
  onUpdateSetting: (s: AdminProjectSetting) => void;
  onUpdateSecret: (s: AdminRuntimeSecret) => void;
  dnsConfig: DNSFormConfig;
  onDNSChange: (d: DNSFormConfig) => void;
  onSaveDNS: () => void;
  onRefreshCertificates: () => void;
  dnsBusy: boolean;
  onError: (msg: string) => void;
  onSaved: (msg: string) => void;
  busy: string;
  setBusy: (s: string) => void;
}

export type AdminSystemTab = "dns" | "certificates" | "challenge" | "keys" | "behavior";

const ACME_PROVIDER_PRESETS = [
  {
    value: "letsencrypt",
    label: "Let's Encrypt",
    directoryURL: "https://acme-v02.api.letsencrypt.org/directory",
    eab: false,
  },
  {
    value: "letsencrypt-staging",
    label: "Let's Encrypt Staging",
    directoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
    eab: false,
  },
  {
    value: "zerossl",
    label: "ZeroSSL",
    directoryURL: "https://acme.zerossl.com/v2/DV90",
    eab: true,
  },
  {
    value: "google",
    label: "Google Trust Services",
    directoryURL: "https://dv.acme-v02.api.pki.goog/directory",
    eab: true,
  },
  {
    value: "google-staging",
    label: "Google Trust Services Staging",
    directoryURL: "https://dv.acme-v02.test-api.pki.goog/directory",
    eab: true,
  },
  {
    value: "custom",
    label: "Custom URL",
    directoryURL: "",
    eab: false,
  },
  {
    value: "custom-eab",
    label: "Custom URL + EAB",
    directoryURL: "",
    eab: true,
  },
] as const;

export function AdminSystem(props: Props) {
  const { settings, secrets, certificates } = props;
  const [certificateAction, setCertificateAction] = useState<"reissue" | "sync" | null>(null);
  const [manualCertificate, setManualCertificate] = useState({
    domains: "",
    certPEM: "",
    keyPEM: "",
    caPEM: "",
    expiresAt: "",
  });
  const [certificateDebug, setCertificateDebug] = useState<AdminCertificateDebug | null>(null);
  const setting = (key: string) => settings.find((item) => item.key === key);
  const secret = (key: string) => secrets.find((item) => item.key === key);
  const acmeSetting = setting("ACME_ENABLED");
  const acmeEnabled = acmeSetting?.value === true;
  const acmeProvider = selectedACMEProvider(setting("ACME_PROVIDER")?.value);
  const acmeUsesCustomDirectory = acmeProvider.value === "custom" || acmeProvider.value === "custom-eab";
  const managedDomains = managedDomainsFromDNS(props.dnsConfig);
  const certificateDebugEnabled = setting("LG_WORKER_DEBUG_LOGS")?.value === true || setting("LG_DEBUG_STREAMS")?.value === true;
  const certificateDebugValue = {
    current: {
      source: acmeEnabled ? "acme" : "manual",
      provider: acmeProvider.value,
      provider_label: acmeProvider.label,
      directory_url: acmeUsesCustomDirectory ? stringSettingValue(setting("ACME_DIRECTORY_URL")?.value) : acmeProvider.directoryURL,
      eab_required: acmeProvider.eab,
      eab_key_id_configured: Boolean(stringSettingValue(setting("ACME_EAB_KEY_ID")?.value)),
      eab_hmac_key_configured: secret("ACME_EAB_HMAC_KEY")?.configured === true,
      acme_account_jwk_configured: secret("ACME_ACCOUNT_JWK")?.configured === true,
      cloudflare_dns_token_configured: secret("CLOUDFLARE_DNSUPDATE_API_KEY")?.configured === true,
      cloudflare_zone_id_configured: Boolean(stringSettingValue(setting("CLOUDFLARE_ZONE_ID")?.value)),
      managed_domains: managedDomains,
      active_bundle_count: certificates.length,
      worker_debug_logs: setting("LG_WORKER_DEBUG_LOGS")?.value === true,
      debug_streams: setting("LG_DEBUG_STREAMS")?.value === true,
    },
    last_action: certificateDebug,
  };

  async function runCertificateAction(action: "sync") {
    props.setBusy(`cert:${action}`);
    try {
      const result = await syncAdminCertificates();
      setCertificateDebug(result.debug ?? certificateActionDebug("sync", result));
      props.onRefreshCertificates();
      props.onSaved(`Synced ${result.synced} node certificate bundle(s)${result.skipped ? `, skipped ${result.skipped}` : ""}`);
    } catch (error) {
      setCertificateDebug(certificateActionErrorDebug(action, error));
      props.onError(error instanceof Error ? error.message : "certificate action failed");
    } finally {
      props.setBusy("");
      setCertificateAction(null);
    }
  }

  async function importManualCertificate() {
    const certExpiresAt = Math.floor(Date.parse(manualCertificate.expiresAt) / 1000);
    if (!manualCertificate.certPEM.trim() || !manualCertificate.keyPEM.trim()) return props.onError("certificate and private key are required");
    if (!Number.isFinite(certExpiresAt)) return props.onError("certificate expiry is required");
    props.setBusy("cert:import");
    try {
      const result = await importAdminCertificate({
        cert_pem: manualCertificate.certPEM,
        key_pem: manualCertificate.keyPEM,
        ca_pem: manualCertificate.caPEM || undefined,
        cert_expires_at: certExpiresAt,
        domains: splitCertificateDomains(manualCertificate.domains),
      });
      await props.onRefreshCertificates();
      setCertificateDebug(result.debug ?? certificateActionDebug("import", result));
      setManualCertificate((current) => ({ ...current, certPEM: "", keyPEM: "", caPEM: "" }));
      props.onSaved(result.status === "imported"
        ? `Imported certificate for ${result.nodes ?? 0} node(s)${result.skipped ? `, skipped ${result.skipped}` : ""}`
        : `Certificate import: ${result.reason ?? result.status}`);
    } catch (error) {
      setCertificateDebug(certificateActionErrorDebug("import", error));
      props.onError(error instanceof Error ? error.message : "certificate import failed");
    } finally {
      props.setBusy("");
    }
  }

  return (
    <>
      <Tabs value={props.tab} onValueChange={(value) => props.onTabChange(value as AdminSystemTab)} className="space-y-4">
        <TabsList className="grid h-auto w-full grid-cols-2 gap-1 sm:flex sm:w-auto">
          <TabsTrigger value="dns" className="gap-1.5"><Globe2 data-icon="inline-start" />DNS</TabsTrigger>
          <TabsTrigger value="certificates" className="gap-1.5"><BadgeCheck data-icon="inline-start" />Certificates</TabsTrigger>
          <TabsTrigger value="challenge" className="gap-1.5"><ShieldCheck data-icon="inline-start" />Challenge</TabsTrigger>
          <TabsTrigger value="keys" className="gap-1.5"><KeyRound data-icon="inline-start" />Signing keys</TabsTrigger>
          <TabsTrigger value="behavior" className="gap-1.5"><SlidersHorizontal data-icon="inline-start" />Behavior</TabsTrigger>
        </TabsList>

        <TabsContent value="dns" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">DNS provider</CardTitle>
              <CardDescription>Creates per-node DNS records automatically.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <ProviderSelect
                label="Provider"
                value="cloudflare"
                options={[
                  { value: "cloudflare", label: "Cloudflare" },
                  { value: "hetzner", label: "Hetzner DNS", soon: true },
                  { value: "custom", label: "Custom API", soon: true },
                ]}
              />
              <StringSettingField setting={setting("CLOUDFLARE_ZONE_ID")} label="Zone ID" placeholder="zone id" {...props} />
              <SecretField secret={secret("CLOUDFLARE_DNSUPDATE_API_KEY")} label="DNS edit API token" {...props} />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Base domains</CardTitle>
              <CardDescription>Roots used when generating per-node DNS names.</CardDescription>
            </CardHeader>
            <CardContent>
              <AdminDNS config={props.dnsConfig} onChange={props.onDNSChange} onSave={props.onSaveDNS} busy={props.dnsBusy} embedded />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="certificates" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <CardTitle className="text-base">Managed certificates</CardTitle>
                <CardDescription>{acmeEnabled ? "Renew wildcard certificates with ACME DNS-01 and republish them to nodes." : "Use externally issued certificates and publish encrypted bundles to nodes."}</CardDescription>
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setCertificateAction("sync")}
                  disabled={props.busy === "cert:sync"}
                >
                  <RefreshCw data-icon="inline-start" />
                  Sync to nodes
                </Button>
                {acmeEnabled ? (
                  <Button
                    size="sm"
                    onClick={() => setCertificateAction("reissue")}
                    disabled={props.busy === "cert:reissue"}
                  >
                    <BadgeCheck data-icon="inline-start" />
                    Reissue
                  </Button>
                ) : null}
              </div>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <CertificateSourceField setting={acmeSetting} {...props} />
              {acmeEnabled ? (
                <>
                  <ACMEProviderField
                    provider={setting("ACME_PROVIDER")}
                    directory={setting("ACME_DIRECTORY_URL")}
                    onUpdateSetting={props.onUpdateSetting}
                    onError={props.onError}
                    onSaved={props.onSaved}
                    busy={props.busy}
                    setBusy={props.setBusy}
                  />
                  <ACMEAccountEmailField
                    setting={setting("ACME_ACCOUNT_EMAIL")}
                    enableZeroSSLRegistration={acmeProvider.value === "zerossl"}
                    {...props}
                  />
                  {acmeUsesCustomDirectory ? (
                    <StringSettingField setting={setting("ACME_DIRECTORY_URL")} label="Directory URL" placeholder="https://acme-v02.api.letsencrypt.org/directory" {...props} />
                  ) : null}
                  <StringSettingField setting={setting("ACME_RENEW_BEFORE_DAYS")} label="Renew before days" placeholder="30" {...props} />
                  {acmeProvider.eab ? (
                    <>
                      <StringSettingField setting={setting("ACME_EAB_KEY_ID")} label="EAB key ID" placeholder="key identifier from the CA" {...props} />
                      <ACMEAlgorithmField setting={setting("ACME_EAB_ALG")} {...props} />
                      <SecretField secret={secret("ACME_EAB_HMAC_KEY")} label="ACME EAB HMAC Key" {...props} />
                    </>
                  ) : null}
                  <SecretField secret={secret("ACME_ACCOUNT_JWK")} label={secret("ACME_ACCOUNT_JWK")?.label ?? "ACME Account JWK"} {...props} />
                </>
              ) : null}
            </CardContent>
          </Card>

          {!acmeEnabled ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Import existing certificate</CardTitle>
                <CardDescription>Use a certificate issued outside this control plane and publish encrypted bundles to matching nodes.</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="cert-import-domains" className="text-sm font-medium">Covered domains</Label>
                  <Textarea
                    id="cert-import-domains"
                    name="cert-import-domains"
                    value={manualCertificate.domains}
                    onChange={(event) => setManualCertificate((current) => ({ ...current, domains: event.target.value }))}
                    placeholder={managedDomains.length ? managedDomains.join("\n") : "*.example.net"}
                    className="min-h-20 font-mono text-xs"
                  />
                  <p className="text-xs text-muted-foreground">Leave empty to use the managed domains from DNS settings.</p>
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="cert-import-expires-at" className="text-sm font-medium">Expires at</Label>
                  <Input
                    id="cert-import-expires-at"
                    name="cert-import-expires-at"
                    type="datetime-local"
                    value={manualCertificate.expiresAt}
                    onChange={(event) => setManualCertificate((current) => ({ ...current, expiresAt: event.target.value }))}
                    className="h-9"
                  />
                </div>
                <div className="grid gap-4 lg:grid-cols-2">
                  <PEMField
                    id="cert-import-cert-pem"
                    label="Certificate PEM"
                    value={manualCertificate.certPEM}
                    placeholder="-----BEGIN CERTIFICATE-----"
                    onChange={(value) => setManualCertificate((current) => ({ ...current, certPEM: value }))}
                  />
                  <PEMField
                    id="cert-import-key-pem"
                    label="Private key PEM"
                    value={manualCertificate.keyPEM}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                    onChange={(value) => setManualCertificate((current) => ({ ...current, keyPEM: value }))}
                  />
                  <PEMField
                    id="cert-import-ca-pem"
                    label="CA chain PEM"
                    value={manualCertificate.caPEM}
                    placeholder="optional intermediate certificates"
                    onChange={(value) => setManualCertificate((current) => ({ ...current, caPEM: value }))}
                    className="lg:col-span-2"
                  />
                </div>
                <div className="flex justify-end">
                  <Button size="sm" onClick={() => void importManualCertificate()} disabled={props.busy === "cert:import"}>
                    <BadgeCheck data-icon="inline-start" />
                    Import and sync
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : null}

          {certificateDebugEnabled ? <CertificateDebugPanel value={certificateDebugValue} /> : null}

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Active bundles</CardTitle>
              <CardDescription>Current active certificates stored for the project.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {certificates.length === 0 ? (
                <div className="rounded-lg border border-dashed px-4 py-8 text-sm text-muted-foreground">
                  No active certificate bundles yet.
                </div>
              ) : certificates.map((certificate) => (
                <div key={certificate.bundle_id} className="rounded-lg border bg-background/50 p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      <p className="font-mono text-sm font-semibold text-foreground">{certificate.domain}</p>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        <Badge variant="secondary">v{certificate.version}</Badge>
                        <Badge variant="outline">{certificate.sync_status}</Badge>
                        <Badge variant="outline">{certificate.nodes.length} node(s)</Badge>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <div>Issued {formatTimestamp(certificate.created_at)}</div>
                      <div>Expires {formatTimestamp(certificate.cert_expires_at)}</div>
                      <div>Last sync {certificate.synced_at ? formatTimestamp(certificate.synced_at) : "pending"}</div>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-3 lg:grid-cols-2">
                    <CertificateField label="Domains" value={certificate.domains.join("\n")} />
                    <CertificateField label="SHA-256 fingerprint" value={certificate.fingerprint_sha256} />
                    <CertificateField label="Certificate PEM" value={certificate.cert_pem} code className="lg:col-span-2" />
                    {certificate.ca_pem ? <CertificateField label="CA PEM" value={certificate.ca_pem} code className="lg:col-span-2" /> : null}
                  </div>
                  {certificate.nodes.length > 0 ? (
                    <div className="mt-4 rounded-md border bg-muted/20 p-3">
                      <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Node delivery</div>
                      <div className="flex flex-wrap gap-2">
                        {certificate.nodes.map((node) => (
                          <Badge key={node.node_id} variant={node.status === "synced" ? "default" : "outline"}>
                            {node.node_id}:{node.status}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="challenge">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Challenge provider</CardTitle>
              <CardDescription>Bot challenge for iperf3 and download sessions. Both keys are required to enable it.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <ProviderSelect
                label="Provider"
                value="turnstile"
                options={[
                  { value: "turnstile", label: "Cloudflare Turnstile" },
                  { value: "recaptcha", label: "Google reCAPTCHA", soon: true },
                  { value: "hcaptcha", label: "hCaptcha", soon: true },
                ]}
              />
              <StringSettingField setting={setting("TURNSTILE_SITE_KEY")} label="Site key (public)" placeholder="0x…" {...props} />
              <SecretField secret={secret("TURNSTILE_SECRET_KEY")} label="Secret key" {...props} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="keys">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Ed25519 signing keys</CardTitle>
              <CardDescription>Sign tokens, node config bundles, and admin operations. Generate once; rotating invalidates issued material.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {["LG_TOKEN_SIGN_JWK", "LG_CONFIG_SIGN_JWK", "LG_ADMIN_SIGN_JWK"].map((key) => (
                <SecretField key={key} secret={secret(key)} label={secret(key)?.label ?? key} {...props} />
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="behavior">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Runtime behavior</CardTitle>
              <CardDescription>Operational toggles applied across the worker.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <BooleanSettingField setting={setting("LG_BLOCK_PRIVATE_IPS")} label="Block private IP targets" hint="Reject diagnostics aimed at RFC1918 / loopback ranges." {...props} />
              <BooleanSettingField setting={setting("LG_DEBUG_STREAMS")} label="Debug live streams" hint="Expose verbose live job/iperf output to the public console." {...props} />
              <BooleanSettingField setting={setting("LG_WORKER_DEBUG_LOGS")} label="Worker debug logs" hint="Emit verbose worker-side request logs." {...props} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <CertificateReissueDialog
        open={certificateAction === "reissue"}
        domains={managedDomains}
        onOpenChange={(open) => { if (!open) setCertificateAction(null); }}
        onDone={(msg) => { props.onSaved(msg); props.onRefreshCertificates(); }}
      />
      <ConfirmDialog
        open={certificateAction === "sync"}
        onOpenChange={(open) => { if (!open) setCertificateAction(null); }}
        title="Sync active bundles to nodes"
        description="Republish the current active certificate bundle to every matching node."
        confirmPhrase="sync"
        confirmLabel="Sync"
        onConfirm={() => void runCertificateAction("sync")}
      />
    </>
  );
}

function CertificateDebugPanel({ value }: { value: Record<string, unknown> }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Certificate debug</CardTitle>
        <CardDescription>Visible while Worker debug logs or Debug live streams is enabled.</CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="max-h-80 overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-all">
          {JSON.stringify(value, null, 2)}
        </pre>
      </CardContent>
    </Card>
  );
}

function certificateActionDebug(action: "reissue" | "sync" | "import", response: unknown): AdminCertificateDebug {
  return {
    action,
    at: new Date().toISOString(),
    response,
  };
}

function certificateActionErrorDebug(action: "reissue" | "sync" | "import", error: unknown): AdminCertificateDebug {
  if (error instanceof AdminCertificateActionError) {
    return error.debug ?? {
      action,
      at: new Date().toISOString(),
      error: error.message,
      response: error.payload,
    };
  }
  return {
    action,
    at: new Date().toISOString(),
    error: error instanceof Error ? error.message : "certificate action failed",
  };
}

function ACMEProviderField({ provider, directory, onUpdateSetting, onError, onSaved, busy, setBusy }: {
  provider?: AdminProjectSetting;
  directory?: AdminProjectSetting;
} & Pick<Props, "onUpdateSetting" | "onError" | "onSaved" | "busy" | "setBusy">) {
  if (!provider) return null;
  const selected = selectedACMEProvider(provider.value);
  const id = "set:ACME_PROVIDER";

  async function selectProvider(nextValue: string) {
    const preset = ACME_PROVIDER_PRESETS.find((item) => item.value === nextValue) ?? ACME_PROVIDER_PRESETS[0];
    setBusy(id);
    try {
      onUpdateSetting(await saveAdminProjectSetting("ACME_PROVIDER", preset.value));
      if (directory && preset.directoryURL) {
        onUpdateSetting(await saveAdminProjectSetting("ACME_DIRECTORY_URL", preset.directoryURL));
      }
      onSaved(`Saved ACME provider: ${preset.label}`);
    } catch (error) {
      onError(error instanceof Error ? error.message : "save failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <Label className="text-sm font-medium">Provider preset</Label>
        <SourceBadges configured={provider.configured} source={provider.source} />
      </div>
      <Select value={selected.value} onValueChange={(value) => void selectProvider(value)} disabled={busy === id}>
        <SelectTrigger className="h-9" aria-label="Provider preset">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {ACME_PROVIDER_PRESETS.map((preset) => (
              <SelectItem key={preset.value} value={preset.value}>
                {preset.label}{preset.eab && !preset.label.includes("EAB") ? " · EAB" : ""}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
      <p className="text-xs text-muted-foreground">
        {selected.directoryURL ? `Directory URL is managed by this preset: ${selected.directoryURL}` : "Use your own ACME directory URL below."}
        {selected.eab ? " External Account Binding is required for this provider." : ""}
      </p>
    </div>
  );
}

function CertificateSourceField({ setting, onUpdateSetting, onError, onSaved, busy, setBusy }: {
  setting?: AdminProjectSetting;
} & Pick<Props, "onUpdateSetting" | "onError" | "onSaved" | "busy" | "setBusy">) {
  if (!setting) return null;
  const id = "set:ACME_ENABLED";
  const value = setting.value === true ? "acme" : "manual";

  async function save(nextValue: string) {
    if (nextValue !== "acme" && nextValue !== "manual") return;
    setBusy(id);
    try {
      onUpdateSetting(await saveAdminProjectSetting("ACME_ENABLED", nextValue === "acme"));
      onSaved(nextValue === "acme" ? "Using ACME renewal" : "Using manual certificate import");
    } catch (error) {
      onError(error instanceof Error ? error.message : "save failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <Label className="text-sm font-medium">Certificate source</Label>
        <SourceBadges configured={setting.configured} source={setting.source} />
      </div>
      <ToggleGroup
        type="single"
        value={value}
        onValueChange={(nextValue) => void save(nextValue)}
        disabled={busy === id}
        className="grid grid-cols-1 gap-2 sm:grid-cols-2"
        aria-label="Certificate source"
      >
        <ToggleGroupItem value="acme" variant="outline" className="h-auto justify-start px-3 py-2 text-left">
          <span className="flex flex-col gap-0.5">
            <span>ACME renewal</span>
            <span className="text-xs font-normal text-muted-foreground">Scheduled DNS-01 renewal</span>
          </span>
        </ToggleGroupItem>
        <ToggleGroupItem value="manual" variant="outline" className="h-auto justify-start px-3 py-2 text-left">
          <span className="flex flex-col gap-0.5">
            <span>Manual import</span>
            <span className="text-xs font-normal text-muted-foreground">Externally issued certificate</span>
          </span>
        </ToggleGroupItem>
      </ToggleGroup>
      <p className="text-xs text-muted-foreground">
        These modes are mutually exclusive. Manual import disables scheduled ACME renewal.
      </p>
    </div>
  );
}

function selectedACMEProvider(value: unknown): (typeof ACME_PROVIDER_PRESETS)[number] {
  const currentProvider = typeof value === "string" && value ? value : "letsencrypt";
  return ACME_PROVIDER_PRESETS.find((preset) => preset.value === currentProvider) ?? ACME_PROVIDER_PRESETS.find((preset) => preset.value === "custom")!;
}

function ACMEAlgorithmField({ setting, onUpdateSetting, onError, onSaved, busy, setBusy }: {
  setting?: AdminProjectSetting;
} & Pick<Props, "onUpdateSetting" | "onError" | "onSaved" | "busy" | "setBusy">) {
  if (!setting) return null;
  const currentSetting = setting;
  const currentValue = typeof currentSetting.value === "string" && currentSetting.value ? currentSetting.value : "HS256";
  const id = `set:${currentSetting.key}`;

  async function save(nextValue: string) {
    setBusy(id);
    try {
      onUpdateSetting(await saveAdminProjectSetting(currentSetting.key, nextValue));
      onSaved("Saved EAB algorithm");
    } catch (error) {
      onError(error instanceof Error ? error.message : "save failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <Label className="text-sm font-medium">EAB algorithm</Label>
        <SourceBadges configured={currentSetting.configured} source={currentSetting.source} />
      </div>
      <Select value={currentValue} onValueChange={(value) => void save(value)} disabled={busy === id}>
        <SelectTrigger className="h-9" aria-label="EAB algorithm">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value="HS256">HS256</SelectItem>
            <SelectItem value="HS384">HS384</SelectItem>
            <SelectItem value="HS512">HS512</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  );
}

function ACMEAccountEmailField({
  setting,
  enableZeroSSLRegistration,
  onUpdateSetting,
  onUpdateSecret,
  onError,
  onSaved,
  busy,
  setBusy,
}: {
  setting?: AdminProjectSetting;
  enableZeroSSLRegistration: boolean;
} & Pick<Props, "onUpdateSetting" | "onUpdateSecret" | "onError" | "onSaved" | "busy" | "setBusy">) {
  const [value, setValue] = useState(() => (typeof setting?.value === "string" ? setting.value : ""));
  const [termsOpen, setTermsOpen] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  useEffect(() => {
    setValue(typeof setting?.value === "string" ? setting.value : "");
  }, [setting?.value]);
  if (!setting) return null;
  const currentSetting = setting;
  const saveID = `set:${currentSetting.key}`;
  const registerID = "cert:zerossl-register";
  const inputID = domID("setting", currentSetting.key);

  async function save() {
    setBusy(saveID);
    try {
      const trimmed = value.trim();
      onUpdateSetting(trimmed
        ? await saveAdminProjectSetting(currentSetting.key, trimmed)
        : await resetAdminProjectSetting(currentSetting.key, currentSetting.key));
      onSaved("Saved account email");
    } catch (error) {
      onError(error instanceof Error ? error.message : "save failed");
    } finally {
      setBusy("");
    }
  }

  async function register() {
    const email = value.trim();
    if (!email) {
      onError("account email is required");
      return;
    }
    setBusy(registerID);
    try {
      const result = await registerZeroSSLEAB(email);
      onUpdateSetting(result.account_email_setting);
      onUpdateSetting(result.eab_key_id_setting);
      onUpdateSetting(result.eab_alg_setting);
      onUpdateSecret(result.eab_hmac_secret);
      setValue(result.email);
      onSaved("Registered ZeroSSL account email and generated EAB credentials");
      setTermsAccepted(false);
      setTermsOpen(false);
    } catch (error) {
      onError(error instanceof Error ? error.message : "ZeroSSL registration failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <>
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between gap-2">
          <Label htmlFor={inputID} className="text-sm font-medium">Account email</Label>
          <SourceBadges configured={currentSetting.configured} source={currentSetting.source} />
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            id={inputID}
            name={inputID}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder="admin@example.net"
            className="h-9 font-mono text-xs"
          />
          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="h-9 flex-1 sm:flex-none" onClick={() => void save()} disabled={busy === saveID}>
              Save
            </Button>
            {enableZeroSSLRegistration ? (
              <Button
                size="sm"
                className="h-9 flex-1 sm:flex-none"
                onClick={() => setTermsOpen(true)}
                disabled={busy === registerID || !value.trim()}
              >
                Register + generate EAB
              </Button>
            ) : null}
          </div>
        </div>
        {enableZeroSSLRegistration ? (
          <p className="text-xs text-muted-foreground">
            Save this email first if you want it stored without rotating credentials. Register + generate EAB also saves the email, then replaces the current ZeroSSL EAB values after the Terms confirmation.
          </p>
        ) : null}
      </div>

      <AlertDialog open={termsOpen} onOpenChange={(open) => { setTermsOpen(open); if (!open) setTermsAccepted(false); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Register with ZeroSSL?</AlertDialogTitle>
            <AlertDialogDescription>
              This sends the account email to ZeroSSL and stores the returned EAB key ID and HMAC key in this control plane.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="flex flex-col gap-3 py-1">
            <div className="rounded-lg border bg-muted/30 p-3 text-sm">
              <div className="font-medium text-foreground">{value.trim() || "No email entered"}</div>
              <div className="mt-1 text-muted-foreground">Provider preset: ZeroSSL</div>
            </div>
            <div className="flex items-start gap-3 rounded-lg border p-3">
              <Checkbox
                id="zerossl-terms"
                checked={termsAccepted}
                onCheckedChange={(checked) => setTermsAccepted(checked === true)}
              />
              <Label htmlFor="zerossl-terms" className="space-y-1 text-sm leading-5">
                <span className="block">I understand this registers the email with ZeroSSL and requests new ACME EAB credentials for it.</span>
                <span className="block text-xs text-muted-foreground">
                  By continuing you agree to ZeroSSL&apos;s applicable terms and certificate service rules.
                  {" "}
                  <a
                    href="https://zerossl.com/terms/"
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-foreground underline underline-offset-2"
                  >
                    Terms
                    <ExternalLink className="size-3.5" />
                  </a>
                </span>
              </Label>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => { setTermsOpen(false); setTermsAccepted(false); }}>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => void register()} disabled={!termsAccepted || busy === registerID}>
              Register and generate EAB
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function ProviderSelect({ label, value, options }: {
  label: string;
  value: string;
  options: { value: string; label: string; soon?: boolean }[];
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label className="text-sm font-medium">{label}</Label>
      <Select value={value} onValueChange={() => {}}>
        <SelectTrigger className="h-9" aria-label={label}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {options.map((option) => (
              <SelectItem key={option.value} value={option.value} disabled={option.soon}>
                {option.label}{option.soon ? " · soon" : ""}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  );
}

function SourceBadges({ configured, source }: { configured: boolean; source: string }) {
  return (
    <span className="flex gap-1.5">
      <Badge variant={configured ? "secondary" : "outline"} className="text-xs">{configured ? "set" : "unset"}</Badge>
      <Badge variant="outline" className="text-xs">{source}</Badge>
    </span>
  );
}

function StringSettingField({ setting, label, placeholder, onUpdateSetting, onError, onSaved, busy, setBusy }: {
  setting?: AdminProjectSetting;
  label: string;
  placeholder?: string;
} & Pick<Props, "onUpdateSetting" | "onError" | "onSaved" | "busy" | "setBusy">) {
  const [value, setValue] = useState(() => (typeof setting?.value === "string" ? setting.value : ""));
  useEffect(() => {
    setValue(typeof setting?.value === "string" ? setting.value : "");
  }, [setting?.value]);
  if (!setting) return null;
  const currentSetting = setting;
  const id = `set:${currentSetting.key}`;
  const inputID = domID("setting", currentSetting.key);

  async function save() {
    setBusy(id);
    try {
      const trimmed = value.trim();
      onUpdateSetting(trimmed
        ? await saveAdminProjectSetting(currentSetting.key, trimmed)
        : await resetAdminProjectSetting(currentSetting.key, currentSetting.key));
      onSaved(`Saved ${label}`);
    } catch (error) {
      onError(error instanceof Error ? error.message : "save failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={inputID} className="text-sm font-medium">{label}</Label>
        <SourceBadges configured={currentSetting.configured} source={currentSetting.source} />
      </div>
      <div className="flex gap-2">
        <Input id={inputID} name={inputID} value={value} onChange={(event) => setValue(event.target.value)} placeholder={placeholder} className="h-9 font-mono text-xs" />
        <Button size="sm" className="h-9" onClick={save} disabled={busy === id}>Save</Button>
      </div>
    </div>
  );
}

function BooleanSettingField({ setting, label, hint, onUpdateSetting, onError, onSaved, busy, setBusy }: {
  setting?: AdminProjectSetting;
  label: string;
  hint?: string;
} & Pick<Props, "onUpdateSetting" | "onError" | "onSaved" | "busy" | "setBusy">) {
  if (!setting) return null;
  const currentSetting = setting;
  const id = `set:${currentSetting.key}`;
  const checked = currentSetting.value === true;

  async function toggle(next: boolean) {
    setBusy(id);
    try {
      onUpdateSetting(await saveAdminProjectSetting(currentSetting.key, next));
      onSaved(`Saved ${label}`);
    } catch (error) {
      onError(error instanceof Error ? error.message : "save failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <label className="flex items-center justify-between gap-3 rounded-lg border bg-background/60 px-3 py-2.5">
      <span className="min-w-0">
        <span className="block text-sm font-medium">{label}</span>
        {hint ? <span className="block text-xs text-muted-foreground">{hint}</span> : null}
      </span>
      <Switch aria-label={label} checked={checked} disabled={busy === id} onCheckedChange={toggle} />
    </label>
  );
}

function SecretField({ secret, label, onUpdateSecret, onError, onSaved, busy, setBusy }: {
  secret?: AdminRuntimeSecret;
  label: string;
} & Pick<Props, "onUpdateSecret" | "onError" | "onSaved" | "busy" | "setBusy">) {
  const [value, setValue] = useState("");
  const [override, setOverride] = useState(false);
  if (!secret) return null;
  const currentSecret = secret;
  const storeId = `secret:${currentSecret.key}`;
  const generateId = `gen:${currentSecret.key}`;
  const inputID = domID("secret", currentSecret.key);
  const locked = currentSecret.configured && !override;

  async function store() {
    const trimmed = value.trim();
    if (!trimmed) return onError("secret value required");
    if (locked) return onError("enable override to replace a configured secret");
    setBusy(storeId);
    try {
      onUpdateSecret(await saveAdminRuntimeSecret(currentSecret.key, trimmed, override));
      setValue("");
      setOverride(false);
      onSaved(`Stored ${label}`);
    } catch (error) {
      onError(error instanceof Error ? error.message : "store failed");
    } finally {
      setBusy("");
    }
  }

  async function generate() {
    if (locked) return onError("enable override to regenerate a configured secret");
    setBusy(generateId);
    try {
      onUpdateSecret(await generateAdminRuntimeSecret(currentSecret.key, currentSecret.key, override));
      setOverride(false);
      onSaved(`Generated ${label}`);
    } catch (error) {
      onError(error instanceof Error ? error.message : "generate failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="flex flex-col gap-1.5 rounded-lg border bg-background/40 p-3">
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={inputID} className="flex items-center gap-1.5 text-sm font-medium">
          {currentSecret.configured ? <Check className="text-success" /> : null}
          {label}
        </Label>
        <SourceBadges configured={currentSecret.configured} source={currentSecret.source} />
      </div>
      <div className="flex gap-2">
        <Input
          type="password"
          id={inputID}
          name={inputID}
          value={value}
          disabled={locked}
          onChange={(event) => setValue(event.target.value)}
          placeholder={currentSecret.configured ? "•••••• stored" : "paste value"}
          className="h-9 font-mono text-xs"
        />
        <Button size="sm" className="h-9" onClick={store} disabled={busy === storeId || locked}>Save</Button>
        {currentSecret.can_generate ? (
          <Button size="sm" variant="outline" className="h-9 gap-1" onClick={generate} disabled={busy === generateId || locked}>
            <RefreshCw data-icon="inline-start" />
            Generate
          </Button>
        ) : null}
      </div>
      {currentSecret.configured ? (
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Switch aria-label={`Allow replacing ${label}`} checked={override} onCheckedChange={setOverride} />
          Allow replacing the stored value
        </label>
      ) : null}
    </div>
  );
}

function PEMField({ id, label, value, placeholder, className, onChange }: {
  id: string;
  label: string;
  value: string;
  placeholder: string;
  className?: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={id} className="text-sm font-medium">{label}</Label>
      <Textarea
        id={id}
        name={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="min-h-40 font-mono text-xs"
        spellCheck={false}
      />
    </div>
  );
}

function CertificateField({ label, value, className, code = false }: {
  label: string;
  value: string;
  className?: string;
  code?: boolean;
}) {
  return (
    <div className={className}>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</p>
      <pre className={code
        ? "max-h-48 overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-all"
        : "rounded-md border bg-muted/20 px-3 py-2 font-mono text-xs whitespace-pre-wrap break-all"}>
        {value}
      </pre>
    </div>
  );
}

function formatTimestamp(value: number) {
  return new Date(value * 1000).toLocaleString();
}

function managedDomainsFromDNS(config: DNSFormConfig): string[] {
  const bases = new Set<string>();
  const add = (value: string) => {
    const normalized = value.trim().replace(/^\.+|\.+$/g, "");
    if (normalized) bases.add(normalized);
  };
  add(config.base);
  if (!config.singleBase) {
    add(config.v4Base || config.base);
    add(config.v6Base || config.base);
  }
  return Array.from(bases).sort().map((domain) => `*.${domain}`);
}

function splitCertificateDomains(value: string): string[] | undefined {
  const domains = value
    .split(/[\s,]+/)
    .map((domain) => domain.trim().replace(/^\.+|\.+$/g, ""))
    .filter((domain, index, array) => domain.length > 0 && array.indexOf(domain) === index);
  return domains.length > 0 ? domains : undefined;
}

function stringSettingValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function domID(prefix: string, key: string): string {
  return `${prefix}-${key.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
}
