import { useEffect, useState } from "react";
import { Sun, Moon, Check } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import { NavItemsEditor } from "./NavItemsEditor";
import { THEME_PRESETS, PRESET_PALETTES, PALETTE_ROLES, resolvePalette, modeVars, paletteToTheme, presetIdOf, type Palette, type ThemeMode } from "@/lib/theme-presets";
import type { AdminProjectSetting, PublicNavItem } from "@/lib/api";
import { saveAdminProjectSetting, resetAdminProjectSetting } from "@/lib/api";



interface Props {
  settings: AdminProjectSetting[];
  onUpdate: (s: AdminProjectSetting) => void;
  onError: (msg: string) => void;
  onSaved: (msg: string) => void;
  busy: string;
  setBusy: (s: string) => void;
}

const SITE_NAME = "PUBLIC_SITE_NAME";
const BRAND_NAME = "PUBLIC_BRAND_NAME";
const SHOW_BRAND = "PUBLIC_SHOW_BRAND_NAME";
const LOGO_TEXT = "PUBLIC_LOGO_TEXT";
const LOGO_IMAGE = "PUBLIC_LOGO_IMAGE_URL";
const NAV_ITEMS = "PUBLIC_NAV_ITEMS";
const THEME = "PUBLIC_THEME";
const PAGE_TITLE = "PUBLIC_PAGE_TITLE";
const FAVICON_URL = "PUBLIC_FAVICON_URL";
const PAGE_TITLE_MODE = "PUBLIC_PAGE_TITLE_MODE";
const META_DESCRIPTION = "PUBLIC_META_DESCRIPTION";
const META_KEYWORDS = "PUBLIC_META_KEYWORDS";
const OG_IMAGE_URL = "PUBLIC_OG_IMAGE_URL";
const TWITTER_IMAGE_URL = "PUBLIC_TWITTER_IMAGE_URL";
const AGENT_INSTALL_DIR = "AGENT_INSTALL_DIR";
const AGENT_BINARY_NAME = "AGENT_BINARY_NAME";
const AGENT_SERVICE_NAME = "AGENT_SERVICE_NAME";
const AGENT_RUN_USER = "AGENT_RUN_USER";

export function AdminBranding({ settings, onUpdate, onError, onSaved, busy, setBusy }: Props) {
  const str = (key: string) => {
    const v = settings.find((s) => s.key === key)?.value;
    return typeof v === "string" ? v : "";
  };
  const bool = (key: string) => settings.find((s) => s.key === key)?.value === true;
  const navJson = () => {
    const v = settings.find((s) => s.key === NAV_ITEMS)?.value;
    return Array.isArray(v) ? JSON.stringify(v, null, 2) : "[]";
  };

  const [siteName, setSiteName] = useState(() => str(SITE_NAME));
  const [brandName, setBrandName] = useState(() => str(BRAND_NAME));
  const [showBrand, setShowBrand] = useState(() => bool(SHOW_BRAND));
  const [logoText, setLogoText] = useState(() => str(LOGO_TEXT));
  const [logoImage, setLogoImage] = useState(() => str(LOGO_IMAGE));
  const [nav, setNav] = useState(() => navJson());
  const [previewDark, setPreviewDark] = useState(true);
  const [theme, setTheme] = useState(() => str(THEME) || "homura");
  const [pageTitle, setPageTitle] = useState(() => str(PAGE_TITLE));
  const [faviconUrl, setFaviconUrl] = useState(() => str(FAVICON_URL));
  const [pageTitleMode, setPageTitleMode] = useState(() => str(PAGE_TITLE_MODE) || "site_only");
  const [metaDescription, setMetaDescription] = useState(() => str(META_DESCRIPTION));
  const [metaKeywords, setMetaKeywords] = useState(() => str(META_KEYWORDS));
  const [ogImageUrl, setOgImageUrl] = useState(() => str(OG_IMAGE_URL));
  const [twitterImageUrl, setTwitterImageUrl] = useState(() => str(TWITTER_IMAGE_URL));
  const [agentInstallDir, setAgentInstallDir] = useState(() => str(AGENT_INSTALL_DIR) || "/opt/looking-glass");
  const [agentBinaryName, setAgentBinaryName] = useState(() => str(AGENT_BINARY_NAME) || "hlg-agent");
  const [agentServiceName, setAgentServiceName] = useState(() => str(AGENT_SERVICE_NAME) || "hlg-agent");
  const [agentRunUser, setAgentRunUser] = useState(() => str(AGENT_RUN_USER) || "root");

  async function persistString(key: string, value: string, optional: boolean) {
    const trimmed = value.trim();
    if (!trimmed) {
      if (!optional) throw new Error(`${key} required`);
      onUpdate(await resetAdminProjectSetting(key, key));
      return;
    }
    onUpdate(await saveAdminProjectSetting(key, trimmed));
  }

  async function saveIdentity() {
    setBusy("brand:identity");
    try {
      await persistString(SITE_NAME, siteName, false);
      await persistString(BRAND_NAME, brandName, true);
      onUpdate(await saveAdminProjectSetting(SHOW_BRAND, showBrand));
      await persistString(LOGO_TEXT, logoText, true);
      await persistString(LOGO_IMAGE, logoImage, true);
      onSaved("Saved site identity");
    } catch (e) { onError(e instanceof Error ? e.message : "save failed"); }
    finally { setBusy(""); }
  }

  async function saveNav() {
    setBusy("brand:nav");
    try {
      const parsed = JSON.parse(nav) as PublicNavItem[];
      onUpdate(await saveAdminProjectSetting(NAV_ITEMS, parsed));
      onSaved("Saved navigation");
    } catch (e) { onError(e instanceof Error ? e.message : "invalid navigation JSON"); }
    finally { setBusy(""); }
  }

  async function saveTheme() {
    setBusy("brand:theme");
    try {
      onUpdate(await saveAdminProjectSetting(THEME, theme));
      onSaved("Saved theme — reload the public site to see changes");
    } catch (e) { onError(e instanceof Error ? e.message : "save failed"); }
    finally { setBusy(""); }
  }

  async function saveBrowserSeo() {
    setBusy("brand:seo");
    try {
      onUpdate(await saveAdminProjectSetting(PAGE_TITLE_MODE, pageTitleMode));
      await persistString(PAGE_TITLE, pageTitle, true);
      await persistString(FAVICON_URL, faviconUrl, true);
      await persistString(META_DESCRIPTION, metaDescription, true);
      await persistString(META_KEYWORDS, metaKeywords, true);
      await persistString(OG_IMAGE_URL, ogImageUrl, true);
      await persistString(TWITTER_IMAGE_URL, twitterImageUrl, true);
      onSaved("Saved browser & SEO settings — reload the public site to see changes");
    } catch (e) { onError(e instanceof Error ? e.message : "save failed"); }
    finally { setBusy(""); }
  }

  async function saveAgentInstall() {
    setBusy("brand:agent");
    try {
      await persistString(AGENT_INSTALL_DIR, agentInstallDir, false);
      await persistString(AGENT_BINARY_NAME, agentBinaryName, false);
      await persistString(AGENT_SERVICE_NAME, agentServiceName, false);
      await persistString(AGENT_RUN_USER, agentRunUser, false);
      onSaved("Saved agent install defaults");
    } catch (e) { onError(e instanceof Error ? e.message : "save failed"); }
    finally { setBusy(""); }
  }

  const palette = resolvePalette(theme);
  const basePreset = presetIdOf(theme) ?? "homura";
  const activePreset = theme.trim().startsWith("{") ? null : theme.trim().toLowerCase();
  function setColor(mode: ThemeMode, role: typeof PALETTE_ROLES[number]["role"], hex: string) {
    const next = { ...palette, [mode]: { ...palette[mode], [role]: hex } };
    setTheme(paletteToTheme(next, basePreset));
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Site identity</CardTitle>
          <CardDescription>Names and logo shown in the public navbar and browser tab.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <FormRow label="Site name" hint="The product name, e.g. “Looking Glass”.">
            <Input value={siteName} onChange={(e) => setSiteName(e.target.value)} className="h-9" placeholder="Looking Glass" />
          </FormRow>
          <FormRow label="Brand / company name" hint="Optional prefix shown before the site name.">
            <Input value={brandName} onChange={(e) => setBrandName(e.target.value)} className="h-9" placeholder="(none)" />
          </FormRow>
          <label className="flex items-center justify-between rounded-lg border bg-background/60 px-3 py-2">
            <span className="text-sm font-medium">Show brand name in navbar</span>
            <Switch checked={showBrand} onCheckedChange={setShowBrand} />
          </label>
          <FormRow label="Logo image URL" hint="Takes priority over the text badge. A transparent PNG/SVG is ideal.">
            <Input value={logoImage} onChange={(e) => setLogoImage(e.target.value)} className="h-9 font-mono text-xs" placeholder="https://…/logo.png" />
          </FormRow>
          <FormRow label="Logo text (fallback badge)" hint="Up to 3 characters shown when no image is set.">
            <Input value={logoText} onChange={(e) => setLogoText(e.target.value)} className="h-9" placeholder="LG" maxLength={8} />
          </FormRow>
          <Button size="sm" className="w-full" onClick={saveIdentity} disabled={busy === "brand:identity"}>
            Save site identity
          </Button>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <CardTitle className="text-base">Appearance</CardTitle>
              <CardDescription>Pick a preset then fine-tune primary, accent and background. The preview shows the real public interface.</CardDescription>
            </div>
            <div className="flex shrink-0 items-center gap-2 rounded-lg border bg-background/60 px-2.5 py-1.5">
              <Sun className="size-3.5 text-muted-foreground" />
              <Switch checked={previewDark} onCheckedChange={setPreviewDark} aria-label="Preview dark theme" />
              <Moon className="size-3.5 text-muted-foreground" />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,20rem)]">
            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Preset</Label>
                <div className="flex flex-wrap gap-2">
                  {THEME_PRESETS.map((preset) => {
                    const active = activePreset === preset.id;
                    const p = PRESET_PALETTES[preset.id].light;
                    return (
                      <button
                        key={preset.id}
                        type="button"
                        onClick={() => setTheme(preset.id)}
                        className={cn(
                          "flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm font-medium transition-colors",
                          active ? "border-primary bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:bg-muted/50",
                        )}
                        aria-pressed={active}
                      >
                        <span className="flex h-4 overflow-hidden rounded-full ring-1 ring-black/10">
                          {(["background", "primary", "accent"] as const).map((r) => (
                            <span key={r} className="w-2" style={{ background: p[r] }} />
                          ))}
                        </span>
                        {preset.label}
                        {active && <Check className="size-3.5 text-primary" />}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Fine-tune colors</Label>
                <div className="overflow-hidden rounded-lg border">
                  <div className="grid grid-cols-[1fr_auto_auto] items-center gap-x-4 border-b bg-muted/40 px-3 py-1.5 text-xs font-semibold text-muted-foreground">
                    <span>Role</span>
                    <span className="flex items-center gap-1"><Sun className="size-3" /> Light</span>
                    <span className="flex items-center gap-1"><Moon className="size-3" /> Dark</span>
                  </div>
                  {PALETTE_ROLES.map(({ role, label }) => (
                    <div key={role} className="grid grid-cols-[1fr_auto_auto] items-center gap-x-4 border-b px-3 py-2 last:border-0">
                      <span className="text-sm font-medium">{label}</span>
                      <Swatch value={palette.light[role]} onChange={(hex) => setColor("light", role, hex)} ariaLabel={`${label} light`} />
                      <Swatch value={palette.dark[role]} onChange={(hex) => setColor("dark", role, hex)} ariaLabel={`${label} dark`} />
                    </div>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">Cards, muted surfaces, borders and the terminal are derived from the background automatically. Reload the public site after saving.</p>
              </div>
            </div>

            <ThemePreview
              palette={palette}
              dark={previewDark}
              siteName={siteName}
              brandName={brandName}
              showBrand={showBrand}
              logoText={logoText}
              logoImage={logoImage}
            />
          </div>

          <Button size="sm" onClick={saveTheme} disabled={busy === "brand:theme"}>Save theme</Button>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">Browser &amp; SEO</CardTitle>
          <CardDescription>The browser tab title, favicon, meta tags, and social sharing cards.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-sm font-medium">Page title format</Label>
              <div className="flex flex-wrap gap-2">
                {([
                  { value: "site_only", label: "Site only", example: siteName || "Looking Glass" },
                  { value: "site_brand", label: "Site - Brand", example: `${siteName || "Looking Glass"} - ${brandName || "Brand"}` },
                  { value: "brand_site", label: "Brand Site", example: `${brandName || "Brand"} ${siteName || "Looking Glass"}` },
                  { value: "custom", label: "Custom", example: pageTitle.trim() || "Custom text" },
                ] as const).map((mode) => (
                  <button
                    key={mode.value}
                    type="button"
                    onClick={() => setPageTitleMode(mode.value)}
                    className={cn(
                      "flex flex-col items-start rounded-md border px-2.5 py-1.5 text-left transition-colors",
                      pageTitleMode === mode.value
                        ? "border-primary bg-primary/10 text-foreground"
                        : "border-border text-muted-foreground hover:bg-muted/50",
                    )}
                  >
                    <span className="text-xs font-semibold">{mode.label}</span>
                    <span className="max-w-[12rem] truncate text-[0.65rem] text-muted-foreground">{mode.example}</span>
                  </button>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">How the browser tab title is built.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Custom page title</Label>
              <Input
                value={pageTitle}
                onChange={(e) => setPageTitle(e.target.value)}
                disabled={pageTitleMode !== "custom"}
                className="h-9 font-mono text-xs"
                placeholder={pageTitleMode === "custom" ? "Required for custom mode" : "—"}
              />
              <p className="text-xs text-muted-foreground">{pageTitleMode === "custom" ? "Shown verbatim as the tab title." : "Only used by the Custom format above."}</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Favicon URL</Label>
              <Input value={faviconUrl} onChange={(e) => setFaviconUrl(e.target.value)} className="h-9 font-mono text-xs"
                placeholder="https://example.com/favicon.ico" />
              <p className="text-xs text-muted-foreground">Custom favicon for the browser tab. Leave empty for default.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Meta Description</Label>
              <Input
                value={metaDescription}
                onChange={(e) => setMetaDescription(e.target.value)}
                className="h-9 font-mono text-xs"
                placeholder="Looking Glass network diagnostics tool..."
              />
              <p className="text-xs text-muted-foreground">Shown in search results and social shares.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Meta Keywords</Label>
              <Input
                value={metaKeywords}
                onChange={(e) => setMetaKeywords(e.target.value)}
                className="h-9 font-mono text-xs"
                placeholder="ping, traceroute, mtr, looking glass..."
              />
              <p className="text-xs text-muted-foreground">Comma-separated keywords for search engines.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Open Graph Image URL</Label>
              <Input
                value={ogImageUrl}
                onChange={(e) => setOgImageUrl(e.target.value)}
                className="h-9 font-mono text-xs"
                placeholder="https://example.com/og.png"
              />
              <p className="text-xs text-muted-foreground">Image for Facebook/LinkedIn sharing. 1200×630px ideal.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Twitter Card Image URL</Label>
              <Input
                value={twitterImageUrl}
                onChange={(e) => setTwitterImageUrl(e.target.value)}
                className="h-9 font-mono text-xs"
                placeholder="https://example.com/twitter-card.png"
              />
              <p className="text-xs text-muted-foreground">Twitter/X sharing image. Falls back to OG image if empty.</p>
            </div>
          </div>
          <Button size="sm" onClick={saveBrowserSeo} disabled={busy === "brand:seo"}>Save browser &amp; SEO</Button>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">Navigation links</CardTitle>
          <CardDescription>Links shown in the public navbar. Drag with the arrows to reorder.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <NavItemsEditor value={nav} onChange={setNav} />
          <Button size="sm" className="w-full sm:w-auto" onClick={saveNav} disabled={busy === "brand:nav"}>
            Save navigation
          </Button>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="text-base">Agent install branding</CardTitle>
          <CardDescription>Defaults used when generating node install commands and service files.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1">
              <Label className="text-sm font-medium">Install directory</Label>
              <Input value={agentInstallDir} onChange={(e) => setAgentInstallDir(e.target.value)} className="h-9 font-mono text-xs" placeholder="/opt/looking-glass" />
              <p className="text-xs text-muted-foreground">Agent binary, config, bootstrap input, and data directory live under this path.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Service user</Label>
              <Input value={agentRunUser} onChange={(e) => setAgentRunUser(e.target.value)} className="h-9 font-mono text-xs" placeholder="root" />
              <p className="text-xs text-muted-foreground">Defaults to root. A different user must already exist on the node.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Binary name</Label>
              <Input value={agentBinaryName} onChange={(e) => setAgentBinaryName(e.target.value)} className="h-9 font-mono text-xs" placeholder="hlg-agent" />
              <p className="text-xs text-muted-foreground">Installed as this filename inside the install directory.</p>
            </div>
            <div className="space-y-1">
              <Label className="text-sm font-medium">Service name</Label>
              <Input value={agentServiceName} onChange={(e) => setAgentServiceName(e.target.value)} className="h-9 font-mono text-xs" placeholder="hlg-agent" />
              <p className="text-xs text-muted-foreground">Used for systemd and OpenRC service registration.</p>
            </div>
          </div>
          <Button size="sm" onClick={saveAgentInstall} disabled={busy === "brand:agent"}>Save agent install defaults</Button>
        </CardContent>
      </Card>
    </div>
  );
}

function FormRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <Label className="text-sm font-medium">{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

/** Uses the worker's theme variables so the preview matches the public page. */
function ThemePreview({
  palette,
  dark,
  siteName,
  brandName,
  showBrand,
  logoText,
  logoImage,
}: {
  palette: Palette;
  dark: boolean;
  siteName: string;
  brandName: string;
  showBrand: boolean;
  logoText: string;
  logoImage: string;
}) {
  // Resolve the worker's HSL tokens directly; this preview has no injected CSS variables.
  const vars = modeVars(dark ? palette.dark : palette.light);
  const c = (token: keyof typeof vars | string) => `hsl(${vars[token] ?? "0 0% 50%"})`;
  const name = showBrand && brandName.trim() ? `${brandName.trim()} ${siteName.trim() || "Looking Glass"}` : siteName.trim() || "Looking Glass";

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Preview</Label>
        <span className="text-[0.6875rem] text-muted-foreground">{dark ? "dark" : "light"}</span>
      </div>
      <div className="overflow-hidden rounded-xl border shadow-sm" aria-label="Theme preview">
        <div style={{ background: c("--background"), color: c("--foreground") }}>
          <div
            className="flex items-center gap-2.5 border-b px-3 py-2.5"
            style={{ background: c("--background"), borderColor: c("--border") }}
          >
            {logoImage.trim() ? (
              <img
                src={logoImage}
                alt=""
                className="h-5 w-auto max-w-[6rem] object-contain"
                onError={(e) => { (e.target as HTMLImageElement).style.visibility = "hidden"; }}
              />
            ) : (
              <span
                className="flex size-5 shrink-0 items-center justify-center rounded-md text-[0.6rem] font-black"
                style={{ background: c("--primary"), color: c("--primary-foreground") }}
              >
                {(logoText || "LG").slice(0, 3)}
              </span>
            )}
            <span className="min-w-0 truncate text-xs font-bold">{name}</span>
            <span className="ml-2 flex h-full items-center gap-3 text-[0.6875rem]">
              <span className="border-b-2 pb-0.5 font-semibold" style={{ borderColor: c("--primary") }}>Looking Glass</span>
              <span style={{ color: c("--muted-foreground") }}>Status</span>
            </span>
          </div>

          <div className="space-y-2 p-3">
            <div
              className="rounded-lg border p-2.5"
              style={{ background: c("--card"), borderColor: c("--border"), color: c("--card-foreground") }}
            >
              <div className="mb-2 flex items-center justify-between gap-2">
                <span className="text-[0.6875rem] font-semibold">Node</span>
                <span
                  className="rounded-full px-1.5 py-px text-[0.625rem] font-semibold"
                  style={{ background: c("--accent"), color: c("--accent-foreground") }}
                >
                  Online
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <span
                  className="rounded-md px-2.5 py-1 text-[0.6875rem] font-semibold"
                  style={{ background: c("--primary"), color: c("--primary-foreground") }}
                >
                  Run MTR
                </span>
                <span
                  className="rounded-md border px-2.5 py-1 text-[0.6875rem] font-medium"
                  style={{ background: c("--secondary"), color: c("--secondary-foreground"), borderColor: c("--border") }}
                >
                  Refresh
                </span>
                <span className="rounded-md border px-2 py-1 font-mono text-[0.625rem]" style={{ color: c("--muted-foreground"), borderColor: c("--border") }}>
                  muted
                </span>
              </div>
            </div>
            <div
              className="rounded-lg p-2.5 font-mono text-[0.625rem] leading-relaxed"
              style={{ background: c("--term-bg"), color: "#cbd5e1" }}
            >
              <div style={{ color: "#6ee7b7" }}>$ mtr -n 1.1.1.1</div>
              <div> 1  10.0.0.1      0.5ms</div>
              <div style={{ color: "#7dd3fc" }}> 2  1.1.1.1       8.2ms</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Swatch({ value, onChange, ariaLabel }: { value: string; onChange: (hex: string) => void; ariaLabel: string }) {
  // Keep incomplete text local; only commit valid hex values.
  const [text, setText] = useState(value);
  useEffect(() => { setText(value); }, [value]);

  function commit(raw: string) {
    const hex = (raw.startsWith("#") ? raw : `#${raw}`).toLowerCase();
    if (/^#[0-9a-f]{6}$/.test(hex)) onChange(hex);
    else setText(value);
  }
  return (
    <span className="flex w-[6.25rem] items-center gap-1.5">
      <input
        type="color"
        value={value}
        onChange={(e) => { setText(e.target.value); onChange(e.target.value); }}
        aria-label={ariaLabel}
        className="h-7 w-8 flex-shrink-0 cursor-pointer rounded border bg-background p-0.5"
      />
      <input
        type="text"
        value={text}
        aria-label={`${ariaLabel} hex`}
        onChange={(e) => setText(e.target.value)}
        onBlur={() => commit(text)}
        onKeyDown={(e) => { if (e.key === "Enter") commit(text); }}
        className="w-[4.25rem] rounded border bg-background px-1 py-0.5 font-mono text-[0.65rem] uppercase text-muted-foreground"
      />
    </span>
  );
}
