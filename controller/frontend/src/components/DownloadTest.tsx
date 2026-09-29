import { ArrowDownToLine, Clock, Copy, Download, Plus } from "lucide-react";
import { memo, useEffect, useRef, useState } from "react";
import { ChallengeGate, type ChallengeGateHandle } from "@/components/ChallengeGate";
import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import type { PublicNode, TokenResponse } from "@/lib/api";
import { buildDownloadURL, extendDownloadToken, requestDownloadToken } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Props {
  className?: string;
  node?: PublicNode;
  challengeSiteKey: string;
}

interface GeneratedDownloadLink {
  token: string;
  linkID: string;
  domain: string;
  sizes: string[];
  expiresAt: number;
  extensionsRemaining: number;
}

export type DownloadLinkState = GeneratedDownloadLink | null;

export interface DownloadHostOption {
  key: "primary" | "ipv4" | "ipv6";
  label: string;
  domain: string;
}

export function formatDownloadTTL(seconds: number): string {
  if (seconds <= 0) return "expired";
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  return `${minutes}m ${remainingSeconds.toString().padStart(2, "0")}s`;
}

export function createDownloadLinkState(
  token: TokenResponse,
): GeneratedDownloadLink {
  return {
    token: token.token,
    linkID: token.link_id || "",
    domain: token.domain || "",
    sizes: token.sizes && token.sizes.length > 0 ? token.sizes : ["10M", "100M", "1G"],
    expiresAt: token.expires_at,
    extensionsRemaining: token.extensions_remaining ?? 0,
  };
}

export function downloadHostOptions(node?: PublicNode): DownloadHostOption[] {
  if (!node) return [];
  const options: DownloadHostOption[] = [{ key: "primary", label: "Primary", domain: node.domain }];
  if (node.has_ipv4 !== false && node.domain_v4) options.push({ key: "ipv4", label: "IPv4", domain: node.domain_v4 });
  if (node.has_ipv6 !== false && node.domain_v6) options.push({ key: "ipv6", label: "IPv6", domain: node.domain_v6 });
  return options;
}

export function downloadLinkURL(host: Pick<PublicNode, "domain"> | string | undefined, link: GeneratedDownloadLink, size: string): string {
  const domain = typeof host === "string" ? host : host?.domain;
  return buildDownloadURL({ domain: domain || link.domain }, link.token, size);
}

export function compactDownloadHostLabel(key: DownloadHostOption["key"]): string {
  if (key === "primary") return "Auto";
  if (key === "ipv4") return "IPv4";
  return "IPv6";
}

export function upsertDownloadLinkState(_current: DownloadLinkState, link: GeneratedDownloadLink): DownloadLinkState {
  return link;
}

export function shouldAutoRunDownloadChallenge(challengeVisible: boolean, challengeToken: string, isGenerating: boolean): boolean {
  return challengeVisible && challengeToken.length > 0 && !isGenerating;
}

export const DownloadTest = memo(function DownloadTest({ className, node, challengeSiteKey }: Props) {
  const [hostKey, setHostKey] = useState<DownloadHostOption["key"]>("primary");
  const [status, setStatus] = useState("Idle");
  const [isGenerating, setIsGenerating] = useState(false);
  const [isExtending, setIsExtending] = useState(false);
  const [generated, setGenerated] = useState<DownloadLinkState>(null);
  const [challengeVisible, setChallengeVisible] = useState(false);
  const [challengeToken, setChallengeToken] = useState("");
  const [nowSeconds, setNowSeconds] = useState(() => Math.floor(Date.now() / 1000));
  const challengeRef = useRef<ChallengeGateHandle | null>(null);
  const submittedChallengeRef = useRef("");
  // Reject responses started for a previously selected node.
  const latestNodeIDRef = useRef<string | undefined>(node?.id);

  useEffect(() => {
    latestNodeIDRef.current = node?.id;
    setGenerated(null);
    setStatus("Idle");
    setChallengeVisible(false);
    setChallengeToken("");
  }, [node?.id]);

  useEffect(() => {
    // Tick only while a link exists — the countdown is meaningless when idle.
    if (!generated) return;
    const id = window.setInterval(() => setNowSeconds(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(id);
  }, [generated?.linkID]);

  function beginGenerate() {
    setChallengeVisible(true);
    setChallengeToken("");
    submittedChallengeRef.current = "";
    setStatus("Complete challenge to generate a link");
  }

  async function generateLink() {
    if (!node || !challengeToken) return;
    const requestedNode = node.id;
    setIsGenerating(true);
    setStatus("Generating link");
    try {
      const token = await requestDownloadToken(node.id, challengeToken);
      if (latestNodeIDRef.current !== requestedNode) return;
      setGenerated((current) => upsertDownloadLinkState(current, createDownloadLinkState(token)));
      setStatus("Link ready");
      setChallengeVisible(false);
    } catch (error) {
      if (latestNodeIDRef.current !== requestedNode) return;
      setStatus(error instanceof Error ? error.message : "Link failed");
    } finally {
      challengeRef.current?.reset();
      setIsGenerating(false);
    }
  }

  useEffect(() => {
    if (!shouldAutoRunDownloadChallenge(challengeVisible, challengeToken, isGenerating)) return;
    if (submittedChallengeRef.current === challengeToken) return;
    submittedChallengeRef.current = challengeToken;
    void generateLink();
  }, [challengeVisible, challengeToken, isGenerating]);

  async function extendLink() {
    if (!node || !generated?.linkID) return;
    const requestedNode = node.id;
    setIsExtending(true);
    setStatus("Extending link");
    try {
      const token = await extendDownloadToken(node.id, generated.linkID, generated.token);
      if (latestNodeIDRef.current !== requestedNode) return;
      const next = createDownloadLinkState(token);
      setGenerated(next);
      setStatus("Idle");
    } catch (error) {
      if (latestNodeIDRef.current !== requestedNode) return;
      setStatus(error instanceof Error ? error.message : "Extend failed");
    } finally {
      setIsExtending(false);
    }
  }

  async function copyLink(url: string) {
    if (!globalThis.navigator?.clipboard?.writeText) {
      setStatus("Copy unavailable");
      return;
    }
    try {
      await globalThis.navigator.clipboard.writeText(url);
      setStatus("Copied");
    } catch {
      setStatus("Copy failed");
    }
  }

  const hostOptions = downloadHostOptions(node);
  const host = hostOptions.find((option) => option.key === hostKey) || hostOptions[0];
  const hostDomain = host?.key === "primary" ? generated?.domain || host?.domain : host?.domain;
  const routeLabel = hostOptions.length > 1 ? `via ${host?.label || "Primary"}` : null;
  const downloadSizes = generated?.sizes || ["10M", "100M", "1G"];
  const secondsLeft = generated ? generated.expiresAt - nowSeconds : 0;
  const expired = Boolean(generated && secondsLeft <= 0);
  const visibleStatus = status !== "Idle" && status !== "Link ready" && status !== "Copied" && status !== "Extending link";

  return (
    <TooltipProvider delayDuration={150}>
      <div className={cn("flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card", className)}>
        <div className="flex h-10 shrink-0 items-center gap-2.5 border-b bg-muted/30 px-3.5">
          <div className="flex size-6 shrink-0 items-center justify-center rounded-md border border-primary/25 bg-primary/10 text-primary">
            <ArrowDownToLine className="size-3.5" />
          </div>
          <span className="text-sm font-semibold tracking-tight text-foreground">Speedtest files</span>
          {generated && !expired && (
            <div className="ml-auto flex shrink-0 items-center gap-1.5 text-xs">
              <div className="flex items-center gap-1 font-mono text-[0.6875rem]">
                <Clock className="size-3 shrink-0 text-muted-foreground" />
                <span className={cn("font-semibold", expired ? "text-destructive" : "text-foreground")}>
                  {formatDownloadTTL(secondsLeft)}
                </span>
              </div>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="inline-flex">
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      className="h-6 px-1.5 text-[0.6875rem] font-semibold text-primary hover:text-primary hover:bg-primary/10 rounded"
                      onClick={extendLink}
                      disabled={isExtending || (generated.extensionsRemaining ?? 0) <= 0}
                    >
                      <Plus className="size-3 mr-0.5" />
                      {isExtending ? "Extending…" : "Extend"}
                    </Button>
                  </span>
                </TooltipTrigger>
                <TooltipContent>
                  {(generated.extensionsRemaining ?? 0) > 0 ? "Extend the link's validity" : "No extensions left"}
                </TooltipContent>
              </Tooltip>
            </div>
          )}
        </div>

        <div className="relative flex min-h-0 flex-1 flex-col gap-2 p-3">
          {hostOptions.length > 1 && (
            <DownloadChoiceGroup
              ariaLabel="Download route"
              value={host?.key || "primary"}
              options={hostOptions.map((h) => ({ value: h.key, label: compactDownloadHostLabel(h.key), title: h.label }))}
              onValueChange={(value) => setHostKey(value as DownloadHostOption["key"])}
            />
          )}

          <dl className="divide-y divide-border/50">
            {downloadSizes.map((size) => {
              const url = generated ? downloadLinkURL(hostDomain, generated, size) : "";
              return (
                <DownloadLinkRow
                  key={size}
                  size={size}
                  url={url}
                  disabled={!generated}
                  expired={expired}
                  routeLabel={routeLabel}
                  onCopy={copyLink}
                />
              );
            })}
          </dl>

          {(!generated || expired || challengeVisible || isGenerating) && (
            <div className="absolute inset-0 flex items-center justify-center overflow-auto rounded-xl bg-card/90 p-3 backdrop-blur-xs">
              <div className="flex w-full max-w-sm flex-col gap-2 text-center">
                {!challengeVisible ? (
                  <Button
                    size="default"
                    disabled={!node || isGenerating}
                    onClick={beginGenerate}
                    className="h-10 w-full gap-2 rounded-xl text-xs font-bold shadow-md transition-all active:scale-[0.98]"
                  >
                    <Download className="size-3.5" />
                    <span>{expired ? "Generate new link" : "Generate Link"}</span>
                  </Button>
                ) : (
                  <>
                    <ChallengeGate ref={challengeRef} siteKey={challengeSiteKey} onToken={setChallengeToken} />
                    <Button size="sm" variant="outline" onClick={() => setChallengeVisible(false)} className="h-8 text-xs">
                      Cancel
                    </Button>
                  </>
                )}
              </div>
            </div>
          )}

          {visibleStatus && (
            <p className="shrink-0 px-0.5 font-mono text-[0.6875rem] text-muted-foreground" aria-live="polite">
              {expired ? "Link expired" : status}
            </p>
          )}
        </div>
      </div>
    </TooltipProvider>
  );
});

function DownloadChoiceGroup({
  ariaLabel,
  value,
  options,
  onValueChange,
}: {
  ariaLabel: string;
  value: string;
  options: Array<{ value: string; label: string; title?: string }>;
  onValueChange: (value: string) => void;
}) {
  return (
    <ToggleGroup
      type="single"
      value={value}
      onValueChange={(next) => {
        if (next) onValueChange(next);
      }}
      aria-label={ariaLabel}
      className="flex w-full items-center gap-1 rounded-lg border border-border/70 bg-muted/40 p-1"
    >
      {options.map((option) => (
        <ToggleGroupItem
          key={option.value}
          value={option.value}
          aria-label={`${ariaLabel}: ${option.label}`}
          title={option.title}
          className="h-7 min-w-0 flex-1 truncate rounded-md px-2 text-xs font-semibold text-muted-foreground transition-colors hover:text-foreground data-[state=on]:bg-card data-[state=on]:text-foreground data-[state=on]:shadow-xs data-[state=on]:ring-1 data-[state=on]:ring-border"
        >
          {option.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}

function DownloadLinkRow({
  size,
  url,
  disabled,
  expired,
  routeLabel,
  onCopy,
}: {
  size: string;
  url: string;
  disabled: boolean;
  expired: boolean;
  routeLabel?: string | null;
  onCopy: (url: string) => void;
}) {
  const linkDisabled = disabled || expired || !url;
  const sizeLabel = formatDownloadSize(size);
  const showPlaceholder = !url;
  const placeholderText = routeLabel ? `Generate a link · ${routeLabel}` : "Generate a link to start";

  return (
    <div className="flex min-h-9 items-center gap-2 py-1.5">
      <dt className="w-12 shrink-0 text-right font-mono text-[0.6875rem] font-bold tabular-nums text-muted-foreground">
        {sizeLabel}
      </dt>
      <dd className="min-w-0 flex-1">
        <input
          aria-label={`${size} download link`}
          readOnly
          value={url}
          onFocus={(e) => {
            if (url) e.currentTarget.select();
          }}
          placeholder={showPlaceholder ? (placeholderText ?? "Generate a link to start") : undefined}
          className="w-full min-w-0 bg-transparent font-mono text-xs text-foreground placeholder:text-muted-foreground/40 outline-none select-all"
        />
      </dd>
      <div className="flex shrink-0 items-center gap-0.5">
        {url && !linkDisabled && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                aria-label={`Copy ${size} download link`}
                className="size-6 rounded p-0 text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground"
                onClick={() => onCopy(url)}
              >
                <Copy className="size-3" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Copy {size} link</TooltipContent>
          </Tooltip>
        )}
        <Tooltip>
          <TooltipTrigger asChild>
            {linkDisabled ? (
              <Button
                size="sm"
                variant="outline"
                disabled
                aria-label={`Download ${size} file`}
                className="h-7 shrink-0 gap-1 rounded-md px-2 text-xs font-semibold opacity-40"
              >
                <Download className="size-3.5" />
              </Button>
            ) : (
              <Button asChild size="sm" variant="default" className="h-7 shrink-0 gap-1 rounded-md px-2 text-xs font-semibold shadow-2xs">
                <a aria-label={`Download ${size} file`} href={url} target="_blank" rel="noreferrer">
                  <Download className="size-3.5" />
                </a>
              </Button>
            )}
          </TooltipTrigger>
          <TooltipContent>Download {size} file</TooltipContent>
        </Tooltip>
      </div>
    </div>
  );
}

function formatDownloadSize(size: string): string {
  if (size === "10M") return "10 MB";
  if (size === "100M") return "100 MB";
  if (size === "1G") return "1 GB";
  return size;
}
