import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { Navbar } from "@/components/layout/Navbar";
import { Sidebar } from "@/components/layout/Sidebar";
import { SiteFooter } from "@/components/layout/SiteFooter";
import { NodePillBar } from "@/components/layout/NodePillBar";
import { NodeInfoPanel, RttProbePopover } from "@/components/public/NodeInfoPanel";
import { LGTerminal } from "@/components/LGTerminal";
import { DownloadTest } from "@/components/DownloadTest";
import { IperfSession } from "@/components/IperfSession";
import { DevConsole } from "@/components/DevConsole";
import { type ClientInfo, type ClientTraceInfo, type PublicConfig, type PublicNode, fetchClientInfo, fetchClientTraceInfo, listNodes, publicConfig } from "@/lib/api";
import { useNodesRtt } from "@/lib/rtt";
import { applyTheme, getStoredTheme, resolveTheme, subscribeToSystemTheme, toggleTheme, type Theme, type ThemePreference } from "@/lib/theme";
import { resolveSelectedNodeID, writeNodeIDToURL } from "@/lib/node-url";

const AdminPanel = lazy(() => import("@/components/AdminPanel").then((m) => ({ default: m.AdminPanel })));

export default function App() {
  if (globalThis.location?.pathname.startsWith("/admin")) {
    return (
      <Suspense fallback={<AdminLoadingFallback />}>
        <AdminPanel />
      </Suspense>
    );
  }
  return <PublicApp />;
}

function AdminLoadingFallback() {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center bg-background px-4 text-foreground">
      <div className="flex flex-col items-center gap-3">
        <div className="size-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Loading Admin…
        </span>
      </div>
    </div>
  );
}

const fallbackBranding: NonNullable<PublicConfig["branding"]> = {
  site_name: "Looking Glass",
  logo_text: "LG",
  logo_image_url: null,
  brand_name: "",
  show_brand_name: false,
  nav_items: [{ label: "Looking Glass", href: "/", active: true }],
  theme: "homura",
  page_title: null,
  favicon_url: null,
  page_title_mode: "site_only",
  meta_description: null,
  meta_keywords: null,
  og_image_url: null,
  twitter_image_url: null,
};

// The worker injects config for first paint; defaults cover local Vite and missing injection.
const bootConfig = typeof window !== "undefined" ? window.__LG_BOOT__ : undefined;

import { appendDevLog } from "@/lib/dev-log";

function PublicApp() {
  const [theme, setTheme] = useState<ThemePreference>(getStoredTheme);
  const [resolvedTheme, setResolvedTheme] = useState<Theme>(() => resolveTheme(getStoredTheme()));
  const [nodes, setNodes] = useState<PublicNode[]>([]);
  const [loadingNodes, setLoadingNodes] = useState(true);
  const [selectedId, setSelectedId] = useState("");
  const [branding, setBranding] = useState(bootConfig?.branding ?? fallbackBranding);
  const [challengeSiteKey, setChallengeSiteKey] = useState(bootConfig?.challenge?.site_key ?? "");
  const [debugStreams, setDebugStreams] = useState(bootConfig?.debug?.streams ?? true);
  const [clientInfo, setClientInfo] = useState<ClientInfo | null>(null);
  const [clientTrace, setClientTrace] = useState<ClientTraceInfo | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    listNodes()
      .then((loaded) => {
        setNodes(loaded);
        setSelectedId((current) => resolveSelectedNodeID(loaded, current));
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load nodes"))
      .finally(() => setLoadingNodes(false));

    if (!bootConfig) {
      publicConfig()
        .then((cfg) => {
          setBranding(cfg.branding ?? fallbackBranding);
          setChallengeSiteKey(cfg.challenge?.site_key ?? "");
          setDebugStreams(cfg.debug?.streams ?? true);
        })
        .catch(() => {});
    }

    fetchClientInfo()
      .then(setClientInfo)
      .catch(() => {});

    fetchClientTraceInfo()
      .then(setClientTrace)
      .catch(() => {});
  }, []);

  useEffect(() => {
    const sync = () => setResolvedTheme(applyTheme(theme));
    sync();
    if (theme !== "system") return undefined;
    return subscribeToSystemTheme(sync);
  }, [theme]);

  useEffect(() => {
    const syncSelectedNodeFromURL = () => {
      setSelectedId((current) => resolveSelectedNodeID(nodes, current));
    };
    window.addEventListener("popstate", syncSelectedNodeFromURL);
    return () => window.removeEventListener("popstate", syncSelectedNodeFromURL);
  }, [nodes]);

  const selected = useMemo(() => nodes.find((n) => n.id === selectedId), [nodes, selectedId]);
  const { results: nodeRtt } = useNodesRtt(nodes);

  const handleToggleTheme = useCallback(() => {
    const next = toggleTheme();
    setTheme(next);
  }, []);

  const handleSelectNode = useCallback((node: PublicNode) => {
    setSelectedId(node.id);
    writeNodeIDToURL(node.id);
  }, []);

  const onDebugLG = useCallback((line: string) => {
    appendDevLog("lg", line);
  }, []);

  const onDebugIperf = useCallback((line: string) => {
    appendDevLog("iperf", line);
  }, []);

  return (
    <div className="flex min-h-dvh flex-col [--nav-height:3rem] [@media_(min-height:846px)]:lg:h-dvh [@media_(min-height:846px)]:lg:overflow-hidden">
      <Navbar
        theme={theme}
        resolvedTheme={resolvedTheme}
        onToggleTheme={handleToggleTheme}
        siteName={branding.site_name}
        logoText={branding.logo_text}
        logoImageUrl={branding.logo_image_url}
        brandName={branding.brand_name}
        showBrandName={branding.show_brand_name}
        navItems={branding.nav_items}
      />
      <NodePillBar
        nodes={nodes}
        selected={selected}
        onSelect={handleSelectNode}
        clientInfo={clientInfo}
        nodeRtt={nodeRtt}
        rttControl={<RttProbePopover nodes={nodes} selected={selected} />}
        loading={loadingNodes}
      />
      <div className="flex flex-1 [@media_(min-height:846px)]:lg:min-h-0 [@media_(min-height:846px)]:lg:overflow-hidden">
        <Sidebar
          nodes={nodes}
          selected={selected}
          onSelect={handleSelectNode}
          clientInfo={clientInfo}
          clientTrace={clientTrace}
          nodeRtt={nodeRtt}
          rttControl={<RttProbePopover nodes={nodes} selected={selected} />}
          loading={loadingNodes}
        />
        <main className="min-w-0 flex-1 p-3 pb-16 sm:p-4 lg:pb-4 [@media_(min-height:846px)]:lg:h-full [@media_(min-height:846px)]:lg:min-h-0 [@media_(min-height:846px)]:lg:overflow-y-auto">
          {error && (
            <div className="mb-3 rounded-xl border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
              {error}
            </div>
          )}
          <div className="grid min-h-0 gap-3.5 lg:grid-cols-[minmax(21rem,25rem)_minmax(0,1fr)] xl:grid-cols-[minmax(23rem,30rem)_minmax(0,1fr)] [@media_(min-height:846px)]:lg:h-full [@media_(min-height:846px)]:lg:grid-rows-[minmax(28rem,73fr)_minmax(14rem,64fr)]">
            <div className="flex min-h-0 flex-col gap-3">
              <NodeInfoPanel
                className="flex-shrink-0"
                selected={selected}
                clientInfo={clientInfo}
                loading={loadingNodes}
              />
              <DownloadTest className="min-h-0 lg:flex-1" node={selected} challengeSiteKey={challengeSiteKey} />
            </div>
            <LGTerminal
              className="min-h-[20rem] lg:min-h-0 lg:h-[30rem] [@media_(min-height:846px)]:lg:h-auto"
              node={selected}
              debugEnabled={debugStreams}
              challengeSiteKey={challengeSiteKey}
              onDebug={onDebugLG}
            />
            <IperfSession
              className="min-h-[17rem] lg:col-span-2 lg:min-h-0"
              node={selected}
              challengeSiteKey={challengeSiteKey}
              onDebug={onDebugIperf}
            />
          </div>
        </main>
      </div>
      <footer className="flex-shrink-0 border-t bg-card px-4 py-3 lg:hidden">
        <SiteFooter />
      </footer>
      <DevConsole enabled={debugStreams} />
    </div>
  );
}
