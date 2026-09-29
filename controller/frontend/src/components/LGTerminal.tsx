import { Copy, Eraser, Globe, Info, Loader2, Play, ShieldAlert, Square, Terminal } from "lucide-react";
import { memo, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ChallengeGate, type ChallengeGateHandle } from "@/components/ChallengeGate";
import type { PublicNode } from "@/lib/api";
import { buildLiveWSURL, requestLiveSession } from "@/lib/api";
import { hasAnsi, parseAnsi, stripAnsi } from "@/lib/ansi";
import { isIPAddress, isValidTarget, resolveFrontendDNS } from "@/lib/dns";
import { cn } from "@/lib/utils";

interface Props {
  className?: string;
  node?: PublicNode;
  debugEnabled?: boolean;
  onDebug?: (line: string) => void;
  challengeSiteKey?: string;
}

const LG_OUTPUT_MAX_LINES = 160;
const REMOTE_DNS_HELP =
  "Remote DNS resolves the hostname on the node instead of in your browser, then runs against the node's resolved address.";

export function isJobStopLine(line: string): boolean {
  return /^stopped:/i.test(stripAnsi(line).trim());
}

export function isJobFinishedOutput(line: string): boolean {
  const trimmed = stripAnsi(line).trim();
  if (!trimmed) return false;
  if (trimmed === "command closed" || trimmed === "--- command closed ---" || trimmed.includes("command closed")) {
    return true;
  }
  if (/^(?:error|job rejected|output truncated|command skipped|stopped):/i.test(trimmed)) {
    return true;
  }
  if (/\b(?:packets transmitted|packet loss|rtt min\/avg\/max|round-trip min\/avg\/max)\b/i.test(trimmed)) {
    return true;
  }
  if (/(?:map trace:|trace complete)/i.test(trimmed)) {
    return true;
  }
  return false;
}

export function getMtrLossColor(loss: string): string {
  const percent = parseFloat(loss.replace("%", ""));
  if (!Number.isFinite(percent) || percent <= 0) return "text-emerald-400 font-medium";
  if (percent < 100) return "text-amber-400 font-bold";
  return "text-rose-400 font-bold";
}

export function getMtrLatencyColor(val: string, loss: string): string {
  const lossPercent = parseFloat(loss.replace("%", ""));
  if (val === "-" || val === "?" || val === "???" || (val === "0" && lossPercent >= 100)) {
    return "text-slate-500";
  }
  const num = parseFloat(val);
  if (isNaN(num)) return "text-slate-300";
  if (num < 50) return "text-emerald-400";
  if (num < 150) return "text-sky-300";
  return "text-amber-300 font-semibold";
}

export type LiveJobFrame = {
  stream: "stdout" | "debug" | "control";
  line: string;
  mode?: "append" | "command" | "replace";
  key?: string;
  /** Structural type set by the worker (e.g. mtr/traceroute rows/header). */
  kind?: "mtr" | "mtr-header" | "traceroute";
  /** mtr hop number, for ordering rows that arrive out of sequence. */
  hop?: number;
  /** Structured mtr row fields (present when kind is "mtr"). */
  mtr?: MtrHop;
  /** Structured traceroute hop (present when kind is "traceroute"). */
  trace?: TracerouteHop;
  /** Set on control frames (e.g. "complete"); never rendered. */
  event?: string;
};

export interface MtrHop {
  hop: number;
  asn: string;
  host: string;
  loss: string;
  snt: string;
  last: string;
  avg: string;
  best: string;
  wrst: string;
}

export interface TracerouteMpls {
  label: string;
  tc: string;
  ttl: string;
}

export interface TracerouteResponder {
  ip: string;
  times: number[];
  mpls: TracerouteMpls | null;
}

export interface TracerouteHop {
  hop: number;
  responders: TracerouteResponder[];
  unanswered: boolean;
  ecmp: boolean;
}

export function parseTracerouteHop(value: unknown): TracerouteHop | undefined {
  if (!value || typeof value !== "object") return undefined;
  const v = value as Record<string, unknown>;
  if (typeof v.hop !== "number" || !Number.isFinite(v.hop)) return undefined;
  if (!Array.isArray(v.responders)) return undefined;
  const responders: TracerouteResponder[] = [];
  for (const raw of v.responders) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    if (typeof r.ip !== "string") continue;
    const times = Array.isArray(r.times) ? r.times.filter((t): t is number => typeof t === "number" && Number.isFinite(t)) : [];
    let mpls: TracerouteMpls | null = null;
    if (r.mpls && typeof r.mpls === "object") {
      const m = r.mpls as Record<string, unknown>;
      if (typeof m.label === "string") mpls = { label: m.label, tc: String(m.tc ?? ""), ttl: String(m.ttl ?? "") };
    }
    responders.push({ ip: r.ip, times, mpls });
  }
  return { hop: v.hop, responders, unanswered: v.unanswered === true, ecmp: responders.length > 1 };
}

function parseMtrHop(value: unknown): MtrHop | undefined {
  if (!value || typeof value !== "object") return undefined;
  const v = value as Record<string, unknown>;
  const str = (key: string): string => (typeof v[key] === "string" ? v[key] as string : "");
  if (typeof v.hop !== "number" || !Number.isFinite(v.hop)) return undefined;
  return {
    hop: v.hop,
    asn: str("asn"),
    host: str("host"),
    loss: str("loss"),
    snt: str("snt"),
    last: str("last"),
    avg: str("avg"),
    best: str("best"),
    wrst: str("wrst"),
  };
}

export function parseLiveJobFrame(raw: string): LiveJobFrame {
  try {
    const payload = JSON.parse(raw) as { stream?: unknown; line?: unknown; mode?: unknown; key?: unknown; kind?: unknown; hop?: unknown; mtr?: unknown; event?: unknown; trace?: unknown };
    if (payload.stream === "control") {
      return { stream: "control", line: "", event: typeof payload.event === "string" ? payload.event : "" };
    }
    if ((payload.stream === "stdout" || payload.stream === "debug") && typeof payload.line === "string") {
      const frame: LiveJobFrame = { stream: payload.stream, line: payload.line };
      if (payload.mode === "append" || payload.mode === "command" || payload.mode === "replace") frame.mode = payload.mode;
      if (typeof payload.key === "string") frame.key = payload.key;
      if (payload.kind === "mtr" || payload.kind === "mtr-header" || payload.kind === "traceroute") frame.kind = payload.kind;
      if (typeof payload.hop === "number" && Number.isFinite(payload.hop)) frame.hop = payload.hop;
      const mtr = parseMtrHop(payload.mtr);
      if (mtr) frame.mtr = mtr;
      const trace = parseTracerouteHop(payload.trace);
      if (trace) frame.trace = trace;
      return frame;
    }
  } catch {
    // Plain text frames are kept for compatibility with older workers.
  }
  return { stream: "stdout", line: raw };
}

export interface LiveJobPayloadInput {
  tool: string;
  target: string;
  ipver: string;
  count?: number;
  remoteDNS: boolean;
  selectedAddress?: string;
}

export interface LiveJobPayload {
  tool: string;
  target: string;
  ipver: string;
  count: number;
  remote_dns: boolean;
  original_target?: string;
}

export interface TerminalLine {
  key?: string;
  text: string;
  /** Structural type carried through from the frame (mtr/traceroute rows). */
  kind?: "mtr" | "mtr-header" | "traceroute";
  /** mtr hop number, used to keep rows ordered. */
  hop?: number;
  /** Structured mtr row fields (present when kind is "mtr"). */
  mtr?: MtrHop;
  /** Structured traceroute hop (present when kind is "traceroute"). */
  trace?: TracerouteHop;
}

export interface LiveSessionState {
  nodeID: string;
  token: string;
  expiresAt: number;
}

export const LIVE_SESSION_REFRESH_MARGIN_SECONDS = 30;

export function liveSessionUsable(state: LiveSessionState | null, nodeID?: string): state is LiveSessionState {
  if (!state || !nodeID || state.nodeID !== nodeID) return false;
  return state.expiresAt - Math.floor(Date.now() / 1000) > LIVE_SESSION_REFRESH_MARGIN_SECONDS;
}

export function buildLiveJobPayload(input: LiveJobPayloadInput): LiveJobPayload | null {
  const trimmedTarget = input.target.trim();
  if (!trimmedTarget) return null;
  const selectedAddress = input.selectedAddress?.trim() || "";
  const target = input.remoteDNS || isIPAddress(trimmedTarget) ? trimmedTarget : selectedAddress;
  if (!target) return null;
  return {
    tool: input.tool,
    target,
    ipver: input.ipver,
    count: normalizeJobCount(input.count),
    remote_dns: input.remoteDNS,
    original_target: trimmedTarget,
  };
}

export function normalizeJobCount(count: unknown): number {
  return Number(count) === 10 ? 10 : 5;
}

export function formatLiveJobCommand(payload: LiveJobPayload, originalTarget = ""): string {
  const ipFlag = payload.ipver === "ipv6" ? "-6" : "-4";
  const comment = !payload.remote_dns && originalTarget && originalTarget !== payload.target ? ` # ${originalTarget}` : "";
  if (payload.tool === "ping") return `ping ${ipFlag} -O -c ${payload.count} -W 2 ${payload.target}${comment}`;
  if (payload.tool === "mtr") return `mtr ${ipFlag} --split ${payload.target}${comment}`;
  if (payload.tool === "traceroute") return `traceroute ${ipFlag} -n -w 2 -e ${payload.target}${comment}`;
  if (payload.tool === "nexttrace") return `nexttrace ${payload.ipver === "ipv6" ? "--ipv6" : "--ipv4"} --map -g en ${payload.target}${comment}`;
  return `${payload.tool} ${payload.target}${comment}`;
}

export function applyLiveJobFrame(current: TerminalLine[], frame: LiveJobFrame, maxLines = LG_OUTPUT_MAX_LINES): TerminalLine[] {
  if (frame.stream === "debug" || frame.stream === "control") return current;
  const text = frame.line.replace(/\r?\n$/, "");
  if (frame.mode === "command") return [{ key: "command", text }];
  if (frame.mode === "replace" && frame.key) {
    const replacement: TerminalLine = { key: frame.key, text, kind: frame.kind, hop: frame.hop, mtr: frame.mtr, trace: frame.trace };
    const index = current.findIndex((line) => line.key === frame.key);
    if (index >= 0) {
      const next = [...current];
      if (
        current[index].mtr?.asn &&
        replacement.mtr &&
        !replacement.mtr.asn &&
        current[index].mtr?.host === replacement.mtr.host
      ) {
        replacement.mtr.asn = current[index].mtr!.asn;
      }
      next[index] = replacement;
      return next;
    }
    if (replacement.kind === "mtr" && typeof replacement.hop === "number") {
      return [...fillMtrGaps(current, replacement.hop), replacement].slice(-maxLines);
    }
    return [...current, replacement].slice(-maxLines);
  }
  return [...current, { text, kind: frame.kind, hop: frame.hop, mtr: frame.mtr, trace: frame.trace }].slice(-maxLines);
}

function fillMtrGaps(lines: TerminalLine[], hop: number): TerminalLine[] {
  let highest = 0;
  for (const line of lines) {
    if (line.kind === "mtr" && typeof line.hop === "number" && line.hop > highest) highest = line.hop;
  }
  if (hop <= highest + 1) return lines;
  const filled = [...lines];
  for (let missing = highest + 1; missing < hop; missing += 1) {
    filled.push({
      key: `mtr-hop-${missing}`,
      text: `${missing} ???`,
      kind: "mtr",
      hop: missing,
      mtr: { hop: missing, asn: "", host: "???", loss: "", snt: "", last: "", avg: "", best: "", wrst: "" },
    });
  }
  return filled;
}

export const LGTerminal = memo(function LGTerminal({ className, node, debugEnabled = true, onDebug, challengeSiteKey = "" }: Props) {
  const [target, setTarget] = useState("");
  const [tool, setTool] = useState("ping");
  const [ipver, setIpver] = useState("ipv4");
  const count = 10;
  const [remoteDNS, setRemoteDNS] = useState(true);
  const [dnsChoiceKey, setDNSChoiceKey] = useState("");
  const [dnsChoices, setDNSChoices] = useState<string[]>([]);
  const [selectedAddress, setSelectedAddress] = useState("");
  const [lines, setLines] = useState<TerminalLine[]>([{ text: "Select a node, choose a tool, and run a signed job." }]);
  const [connected, setConnected] = useState(false);
  const [copied, setCopied] = useState(false);
  const [challengeVisible, setChallengeVisible] = useState(false);
  const [challengeToken, setChallengeToken] = useState("");
  const [isRequestingSession, setIsRequestingSession] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const sessionRef = useRef<LiveSessionState | null>(null);
  const challengeRef = useRef<ChallengeGateHandle | null>(null);
  const retriedWithoutSessionRef = useRef(false);
  const submittedChallengeRef = useRef("");
  const pendingPayloadRef = useRef("");
  const sessionRequestRef = useRef(0);

  const stickToBottomRef = useRef(true);
  const handleTerminalScroll = () => {
    const terminal = terminalRef.current;
    if (!terminal) return;
    stickToBottomRef.current = terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight <= 24;
  };
  useLayoutEffect(() => {
    const terminal = terminalRef.current;
    if (!terminal) return;
    if (stickToBottomRef.current) terminal.scrollTop = terminal.scrollHeight;
  }, [lines]);

  useEffect(() => {
    return () => {
      sessionRequestRef.current += 1;
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [node?.id]);

  useEffect(() => {
    sessionRef.current = null;
    setChallengeVisible(false);
    setChallengeToken("");
    setIsRequestingSession(false);
    sessionRequestRef.current += 1;
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }
  }, [node?.id]);

  useEffect(() => {
    setDNSChoiceKey("");
    setDNSChoices([]);
    setSelectedAddress("");
  }, [target, ipver, remoteDNS]);

  function clearOutput() {
    setLines([]);
  }

  async function copyOutput() {
    if (lines.length === 0) return;
    try {
      const text = lines
        .map((l) => {
          if (l.kind === "mtr-header") {
            return "Hop\tAS\tHost\tLoss%\tSnt\tLast\tAvg\tBest\tWrst";
          }
          const row = l.kind === "mtr" ? l.mtr : undefined;
          if (row) {
            return [row.hop, row.asn, row.host, row.loss, row.snt, row.last, row.avg, row.best, row.wrst].join("\t");
          }
          return stripAnsi(l.text);
        })
        .join("\n");
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  }

  function stop() {
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }
    setConnected(false);
    appendStdout("\n--- job stopped by user ---");
    appendDebug("job stopped by user");
  }

  function appendDebug(line: string) {
    if (!debugEnabled) return;
    onDebug?.(line);
  }

  function appendStdout(line: string) {
    setLines((current) => applyLiveJobFrame(current, { stream: "stdout", line }));
  }

  function sessionUsable(state: LiveSessionState | null, nodeID?: string): state is LiveSessionState {
    return liveSessionUsable(state, nodeID);
  }

  function openSocket(nodeID: string, token: string, payload: string) {
    socketRef.current?.close();
    const socket = new WebSocket(buildLiveWSURL({ id: nodeID }, token));
    socketRef.current = socket;
    let opened = false;
    const pendingFrames: LiveJobFrame[] = [];
    let flushScheduled = false;

    const flushFrames = () => {
      flushScheduled = false;
      if (pendingFrames.length === 0 || socketRef.current !== socket) return;
      const batch = pendingFrames.splice(0);
      setLines((current) => {
        let next = current;
        for (const frame of batch) {
          next = applyLiveJobFrame(next, frame);
        }
        return next;
      });
    };

    const finishJob = () => {
      flushFrames();
      setConnected(false);
      socket.close();
      if (socketRef.current === socket) socketRef.current = null;
    };

    socket.onopen = () => {
      if (socketRef.current !== socket) return;
      opened = true;
      setConnected(true);
      appendDebug("live websocket open");
      socket.send(payload);
    };
    socket.onmessage = (event) => {
      if (socketRef.current !== socket) return;
      const frame = parseLiveJobFrame(String(event.data));
      if (frame.stream === "control") {
        if (frame.event === "complete") finishJob();
        return;
      }
      if (frame.stream === "debug") {
        appendDebug(frame.line);
        // Debug diagnostics are non-terminal; stdout carries user-facing errors.
        if (frame.line.trim() === "command closed" || frame.line.trim() === "--- command closed ---") {
          finishJob();
        }
      } else {
        pendingFrames.push(frame);
        if (isJobFinishedOutput(frame.line)) {
          queueMicrotask(finishJob);
        } else if (!flushScheduled) {
          flushScheduled = true;
          queueMicrotask(flushFrames);
        }
      }
    };
    socket.onerror = () => {
      if (socketRef.current === socket) appendDebug("live websocket error");
    };
    socket.onclose = (event) => {
      if (socketRef.current !== socket) return;
      flushFrames();
      setConnected(false);
      appendDebug(`live websocket closed (${event.code})`);
      if (socketRef.current === socket) socketRef.current = null;
      if (!opened && !retriedWithoutSessionRef.current) {
        appendStdout("error: connection failed");
      }
      if (event.code === 1006 || event.code === 1015) {
        if (!retriedWithoutSessionRef.current && node && sessionRef.current) {
          retriedWithoutSessionRef.current = true;
          appendDebug("live session rejected; requesting a new session token");
          sessionRef.current = null;
          void openSocketWithSession(node.id, payload, true);
        }
      }
    };
    return socket;
  }

  async function openSocketWithSession(nodeID: string, payload: string, force = false): Promise<void> {
    const cached = sessionRef.current;
    if (!force && sessionUsable(cached, nodeID) && cached) {
      openSocket(nodeID, cached.token, payload);
      return;
    }
    if (isRequestingSession) return;
    setIsRequestingSession(true);
    const requestID = ++sessionRequestRef.current;
    try {
      const next = await requestLiveSession(nodeID, challengeToken || undefined);
      if (requestID !== sessionRequestRef.current || node?.id !== nodeID) return;
      const state: LiveSessionState = { nodeID, token: next.token, expiresAt: next.expires_at };
      sessionRef.current = state;
      setChallengeVisible(false);
      setChallengeToken("");
      openSocket(nodeID, state.token, payload);
    } catch (error) {
      if (requestID !== sessionRequestRef.current || node?.id !== nodeID) return;
      const detail = error instanceof Error ? error.message : "session request failed";
      appendDebug(`live session request failed: ${detail}`);
      appendStdout(detail === "turnstile_required" ? "verify to continue" : `session error: ${detail}`);
      setChallengeVisible(true);
      // Let the widget issue a fresh token for the next attempt.
      challengeRef.current?.reset();
    } finally {
      if (requestID === sessionRequestRef.current) setIsRequestingSession(false);
    }
  }

  async function run() {
    if (!node) return;
    retriedWithoutSessionRef.current = false;
    const trimmedTarget = target.trim();
    if (trimmedTarget !== target) setTarget(trimmedTarget);
    if (!trimmedTarget) {
      setLines([{ text: "command skipped: empty target" }]);
      appendDebug("empty target; command skipped");
      return;
    }
    if (!isValidTarget(trimmedTarget)) {
      setLines([{ text: `error: invalid target "${trimmedTarget}" (must be a valid IP address or domain name)` }]);
      appendDebug(`invalid target ${trimmedTarget}; command rejected`);
      return;
    }
    setLines([{ text: `Preparing ${tool} for ${trimmedTarget}...` }]);
    appendDebug(`preparing command: ${tool} ${trimmedTarget} count=${normalizeJobCount(count)} remote_dns=${remoteDNS}`);
    const nextDNSChoiceKey = `${trimmedTarget}|${ipver}`;
    if (!remoteDNS && !isIPAddress(trimmedTarget) && (dnsChoiceKey !== nextDNSChoiceKey || dnsChoices.length === 0 || !selectedAddress)) {
      const dns = await resolveFrontendDNS(target, ipver);
      if (dns.lines.length > 0) {
        setLines((current) => dns.lines.reduce((next, line) => applyLiveJobFrame(next, { stream: "stdout", line }), current));
      }
      setDNSChoiceKey(nextDNSChoiceKey);
      setDNSChoices(dns.answers);
      setSelectedAddress(dns.answers[0] || "");
      if (dns.answers.length > 0) {
        appendStdout("select resolved address, then run again");
        appendDebug(`frontend dns found ${dns.answers.length} address(es) for ${trimmedTarget}`);
        return;
      }
      if (!dns.skipped) {
        const recordType = ipver === "ipv6" ? "IPv6 (AAAA)" : "IPv4 (A)";
        const mockPayload: LiveJobPayload = {
          tool,
          target: trimmedTarget,
          ipver,
          count: normalizeJobCount(count),
          remote_dns: false,
          original_target: trimmedTarget,
        };
        setLines([
          { key: "command", text: `$ ${formatLiveJobCommand(mockPayload, trimmedTarget)}` },
          ...(dns.lines.length > 0 ? dns.lines.map((l) => ({ text: l })) : []),
          { text: `error: DNS resolution failed: no ${recordType} record found for "${trimmedTarget}"` },
          { text: "command skipped: frontend dns did not return an address" },
        ]);
        appendDebug(`frontend dns did not resolve ${trimmedTarget}; command skipped`);
        return;
      }
    }
    const payloadObject = buildLiveJobPayload({ tool, target: trimmedTarget, ipver, count, remoteDNS, selectedAddress });
    if (!payloadObject) {
      appendStdout("command skipped: select a resolved address first");
      appendDebug(`no selected frontend dns address for ${trimmedTarget}; command skipped`);
      return;
    }
    const payload = JSON.stringify(payloadObject);
    setLines([{ key: "command", text: `$ ${formatLiveJobCommand(payloadObject, trimmedTarget)}` }]);
    // A new run starts fresh: follow its output from the top again even if the
    // previous run was left scrolled up.
    stickToBottomRef.current = true;
    pendingPayloadRef.current = payload;
    appendDebug(`sending command over live websocket: ${payloadObject.tool} ${payloadObject.target}`);
    retriedWithoutSessionRef.current = false;
    if (challengeVisible) {
      appendStdout("verify to continue");
      return;
    }
    if (sessionUsable(sessionRef.current, node.id)) return void openSocket(node.id, (sessionRef.current as LiveSessionState).token, payload);
    if (challengeSiteKey) {
      // Turnstile is configured: show the gate first, the auto-run effect
      // submits the session request once the widget yields a token.
      appendStdout("verify to continue");
      setChallengeVisible(true);
      return;
    }
    await openSocketWithSession(node.id, payload);
  }

  // Mirrors IperfSession/DownloadTest: once the challenge widget yields a token,
  // immediately exchange it for a live session token.
  useEffect(() => {
    if (!challengeVisible || !challengeToken || !node || isRequestingSession) return;
    if (submittedChallengeRef.current === challengeToken) return;
    submittedChallengeRef.current = challengeToken;
    void openSocketWithSession(node.id, pendingPayloadRef.current);
  }, [challengeVisible, challengeToken, isRequestingSession, node]);

  const trimmedTarget = target.trim();
  const isTargetInvalid = trimmedTarget.length > 0 && !isValidTarget(trimmedTarget);

  const ipVersionControl = (
    <ChoiceToggleGroup
      ariaLabel="IP version"
      value={ipver}
      options={[
        { value: "ipv4", label: "v4" },
        { value: "ipv6", label: "v6" },
      ]}
      onValueChange={setIpver}
    />
  );
  const runButton = connected ? (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex">
          <Button
            size="sm"
            variant="destructive"
            onClick={stop}
            className="h-9 w-9 shrink-0 text-xs [@container(min-width:42rem)]:w-auto [@container(min-width:42rem)]:px-2"
            aria-label="Stop diagnostic job"
          >
            <Square data-icon="inline-start" className="size-3.5 fill-current" />
            <span className="sr-only [@container(min-width:42rem)]:not-sr-only [@container(min-width:42rem)]:inline">Stop</span>
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>Stop current job</TooltipContent>
    </Tooltip>
  ) : (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex">
          <Button
            size="sm"
            disabled={!node || isRequestingSession || isTargetInvalid}
            onClick={run}
            className="h-9 w-9 shrink-0 text-xs [@container(min-width:42rem)]:w-auto [@container(min-width:42rem)]:px-2"
            aria-label="Run Looking Glass job"
          >
            {isRequestingSession ? (
              <Loader2 data-icon="inline-start" className="size-3.5 animate-spin" />
            ) : (
              <Play data-icon="inline-start" />
            )}
            <span className="sr-only [@container(min-width:42rem)]:not-sr-only [@container(min-width:42rem)]:inline">
              {isRequestingSession ? "Connecting…" : "Run"}
            </span>
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>{isRequestingSession ? "Connecting…" : isTargetInvalid ? "Invalid IP address or domain" : "Run network diagnostic"}</TooltipContent>
    </Tooltip>
  );

  return (
    <TooltipProvider delayDuration={150}>
      <div className={cn("flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card [container-type:inline-size]", className)}>
      <div className="flex h-10 items-center justify-between border-b bg-muted/30 px-3.5">
        <div className="flex items-center gap-2.5">
          <div className="flex size-6 items-center justify-center rounded-md border border-primary/25 bg-primary/10 text-primary">
            <Terminal className="size-3.5" />
          </div>
          <span className="text-xs font-bold text-foreground">Network Diagnostics</span>
        </div>
        <div className="flex items-center gap-1">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-7 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={copyOutput}
                disabled={lines.length === 0}
                aria-label="Copy terminal output"
              >
                <Copy className="size-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{copied ? "Copied!" : "Copy output"}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-7 rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={clearOutput}
                disabled={lines.length === 0}
                aria-label="Clear terminal output"
              >
                <Eraser className="size-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Clear output</TooltipContent>
          </Tooltip>
        </div>
      </div>

      <div className="flex flex-nowrap items-center gap-1.5 border-b bg-background/45 px-2.5 py-2 [@container(min-width:42rem)]:px-3.5">
        <Select value={tool} onValueChange={setTool}>
          <SelectTrigger
            aria-label="Looking Glass tool"
            className="h-9 w-[3.5rem] shrink-0 bg-background px-1.5 py-1 font-mono text-xs [@container(min-width:42rem)]:w-[4.75rem] [@container(min-width:42rem)]:px-2.5"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {["ping","mtr","traceroute","nexttrace"].map((v) => (
                <SelectItem key={v} value={v} className="font-mono text-xs">{v}</SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        <InputGroup className={cn("h-9 min-w-0 flex-1 transition-colors", isTargetInvalid && "border-destructive/60 bg-destructive/5 focus-within:ring-destructive/30")}>
          <InputGroupInput
            id="target"
            aria-label="Target IP or hostname"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onBlur={() => setTarget((prev) => prev.trim())}
            onKeyDown={(e) => e.key === "Enter" && (connected ? stop() : run())}
            className="pl-3 font-mono text-xs"
            placeholder="IP address or domain"
          />
          <InputGroupAddon align="inline-end" className="gap-0.5 pl-1 pr-1">
            <RemoteDnsControl checked={remoteDNS} onCheckedChange={setRemoteDNS} />
          </InputGroupAddon>
        </InputGroup>
        <div className="flex shrink-0 items-center gap-1 [@container(min-width:42rem)]:gap-1.5">
          {ipVersionControl}
          {runButton}
        </div>
      </div>

      {isTargetInvalid && (
        <div className="flex items-center gap-1.5 border-b border-destructive/25 bg-destructive/10 px-3.5 py-1.5 text-[0.6875rem] font-medium text-destructive">
          <Info className="size-3.5 shrink-0" />
          <span>Please enter a valid IPv4, IPv6, or domain name (e.g. 1.1.1.1, 2606:4700:4700::1111, example.com)</span>
        </div>
      )}

      {!remoteDNS && dnsChoices.length > 0 && (
        <div className="flex items-center gap-2.5 border-b border-primary/20 bg-primary/5 px-3.5 py-2">
          <span className="flex items-center gap-1.5 rounded-md bg-primary/10 px-2 py-1 text-[0.6875rem] font-bold text-primary">
            <Globe className="size-3" />
            Resolved IP
          </span>
          <Select value={selectedAddress} onValueChange={setSelectedAddress}>
            <SelectTrigger id="dns-choice" className="h-8 min-w-0 flex-1 border-primary/20 bg-background px-2.5 py-1 font-mono text-xs shadow-2xs">
              <SelectValue placeholder="Select resolved IP address" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {dnsChoices.map((addr) => <SelectItem key={addr} value={addr} className="font-mono text-xs">{addr}</SelectItem>)}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Button size="sm" disabled={!node || !selectedAddress || connected} onClick={run} className="h-8 shrink-0 gap-1.5 px-3 text-xs font-semibold shadow-xs" aria-label="Run with the selected IP">
            <Play data-icon="inline-start" className="size-3" />
            Run
          </Button>
        </div>
      )}

      {challengeVisible && (
        <div className="flex flex-col items-center gap-2 border-b bg-muted/20 px-3.5 py-2">
          <span className="flex items-center gap-1.5 font-mono text-xs font-medium text-muted-foreground">
            <ShieldAlert className="size-3.5" />
            Verify to continue
          </span>
          <ChallengeGate ref={challengeRef} siteKey={challengeSiteKey} onToken={setChallengeToken} />
          <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setChallengeVisible(false)}>
            Cancel
          </Button>
        </div>
      )}

      <div ref={terminalRef} onScroll={handleTerminalScroll} className="terminal-surface h-[20rem] overflow-auto p-3.5 font-mono text-xs leading-relaxed lg:h-auto lg:min-h-0 lg:flex-1 [tab-size:8]">
        <div className="mb-2.5 flex items-center justify-between border-b border-white/10 pb-2 text-[0.6875rem] text-slate-400">
          <div className="flex min-w-0 items-center gap-2 truncate">
            <span className={cn("size-2 flex-shrink-0 rounded-full", connected ? "bg-emerald-400 animate-pulse" : "bg-slate-500")} />
            <span className="truncate font-medium">{node ? node.domain : "select a node to begin"}</span>
          </div>
          <div className="flex shrink-0 items-center gap-1.5 font-mono text-[0.625rem]">
            <span className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-slate-300">{tool}</span>
            <span className={cn("rounded border px-1.5 py-0.5 font-semibold", connected ? "border-emerald-500/40 bg-emerald-950/80 text-emerald-400" : "border-white/10 bg-white/5 text-slate-400")}>
              {connected ? "connected" : "idle"}
            </span>
          </div>
        </div>
        {lines.map((line, i) => {
          const cleanText = stripAnsi(line.text);
          if (line.kind === "mtr-header") {
            return (
              <div key={line.key || `${i}-mtr-hdr`} className="flex min-w-[40rem] items-center gap-2 border-b border-white/10 pb-1 font-mono text-xs font-bold text-sky-400/90 select-none">
                <span className="w-8 shrink-0">Hop</span>
                <span className="w-16 shrink-0">AS</span>
                <span className="min-w-0 flex-1">Host</span>
                <span className="w-16 shrink-0 text-right">Loss%</span>
                <span className="w-10 shrink-0 text-right">Snt</span>
                <span className="w-14 shrink-0 text-right">Last</span>
                <span className="w-14 shrink-0 text-right">Avg</span>
                <span className="w-14 shrink-0 text-right">Best</span>
                <span className="w-14 shrink-0 text-right">Wrst</span>
              </div>
            );
          }

          // Text alone cannot distinguish traceroute hops from MTR rows.
          const row = line.kind === "mtr" ? line.mtr : undefined;
          if (row) {
            const placeholder = row.host === "???";
            return (
              <div
                key={line.key || `${i}-${line.text}`}
                className="flex min-w-[40rem] items-center gap-2 py-0.5 font-mono text-xs hover:bg-white/5 rounded px-1 -mx-1 transition-colors"
              >
                <span className="w-8 shrink-0 font-bold text-slate-400">{row.hop}</span>
                <span className="w-16 shrink-0 font-mono text-[0.6875rem] text-sky-300/80">{row.asn || "—"}</span>
                <span className={cn("min-w-0 flex-1 truncate", placeholder ? "text-slate-500" : "font-medium text-slate-100")} title={row.host}>
                  {row.host}
                </span>
                <span className={cn("w-16 shrink-0 text-right tabular-nums", getMtrLossColor(row.loss))}>
                  {row.loss || "—"}
                </span>
                <span className="w-10 shrink-0 text-right text-slate-400 tabular-nums">{row.snt || "—"}</span>
                <span className={cn("w-14 shrink-0 text-right tabular-nums", getMtrLatencyColor(row.last, row.loss))}>
                  {row.last || "—"}
                </span>
                <span className={cn("w-14 shrink-0 text-right tabular-nums", getMtrLatencyColor(row.avg, row.loss))}>
                  {row.avg || "—"}
                </span>
                <span className={cn("w-14 shrink-0 text-right tabular-nums", getMtrLatencyColor(row.best, row.loss))}>
                  {row.best || "—"}
                </span>
                <span className={cn("w-14 shrink-0 text-right tabular-nums", getMtrLatencyColor(row.wrst, row.loss))}>
                  {row.wrst || "—"}
                </span>
              </div>
            );
          }

          const isCmd = cleanText.startsWith("$");
          const isHeader = cleanText.startsWith("traceroute to ") || cleanText.startsWith("(built-in) traceroute to ") || cleanText.startsWith("frontend dns:");
          const isError = cleanText.startsWith("error:") || cleanText.startsWith("job rejected:") || cleanText.startsWith("command skipped:") || isJobStopLine(line.text);
          if (line.kind === "traceroute" && line.trace) {
            const hop = line.trace;
            return (
              <div key={line.key || `${i}-trace-${hop.hop}`} className="font-mono text-xs leading-relaxed">
                {hop.responders.length === 0 ? (
                  <div><span className="inline-block w-8 text-right text-slate-500">{hop.hop}</span> <span className="text-slate-500">*</span></div>
                ) : (
                  hop.responders.map((r, ri) => (
                    <div key={`${ri}-${r.ip}`} className="whitespace-pre-wrap break-words">
                      <span className="inline-block w-8 text-right text-slate-500">{ri === 0 ? hop.hop : ""}</span>{" "}
                      <span className="text-sky-200">{r.ip}</span>{" "}
                      {r.times.map((t, ti) => (
                        <span key={ti} className={cn("tabular-nums", getMtrLatencyColor(String(t), "0%"))}>{t} ms{ti < r.times.length - 1 ? " " : ""}</span>
                      ))}
                      {hop.ecmp && <span className="ml-1 text-fuchsia-400/90">[ECMP]</span>}
                      {r.mpls && <span className="ml-1 text-amber-300/90">[MPLS {r.mpls.label}/TC{r.mpls.tc}/TTL{r.mpls.ttl}]</span>}
                    </div>
                  ))
                )}
              </div>
            );
          }
          return (
            <div
              key={line.key || `${i}-${line.text}`}
              className={cn(
                "whitespace-pre-wrap break-words font-mono leading-relaxed",
                isCmd && "font-semibold text-emerald-400",
                isHeader && "font-semibold text-sky-400/90",
                isError && "font-semibold text-destructive",
                !isCmd && !isHeader && !isError && "text-slate-200",
              )}
            >
              {hasAnsi(line.text) ? (
                parseAnsi(line.text).map((span, sIdx) => (
                  <span key={sIdx} className={span.className} style={span.style}>
                    {span.text}
                  </span>
                ))
              ) : (
                line.text
              )}
            </div>
          );
        })}
      </div>
    </div>
    </TooltipProvider>
  );
});

function RemoteDnsControl({
  checked,
  onCheckedChange,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-0.5">
      <span className="sr-only">{REMOTE_DNS_HELP}</span>
      <Popover>
        <PopoverTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="hidden size-5 shrink-0 rounded-sm text-muted-foreground hover:text-foreground [@media(pointer:coarse)]:inline-flex [@media(pointer:coarse)]:size-7"
            aria-label="About Remote DNS"
          >
            <Info className="size-3.5" />
          </Button>
        </PopoverTrigger>
        <PopoverContent align="end" sideOffset={8} aria-label="Remote DNS details" className="w-64 bg-card text-card-foreground">
          <p className="text-sm leading-relaxed text-muted-foreground">{REMOTE_DNS_HELP}</p>
        </PopoverContent>
      </Popover>
      <Tooltip>
        <TooltipTrigger asChild>
          <InputGroupButton
            type="button"
            aria-pressed={checked}
            aria-label={checked ? "Remote DNS enabled: node resolves domain" : "Remote DNS disabled: browser resolves domain"}
            onClick={() => onCheckedChange(!checked)}
            className={cn(
              "h-7 shrink-0 gap-1 rounded-md px-2 font-medium text-xs transition-colors",
              checked
                ? "bg-primary/15 text-primary border border-primary/25 hover:bg-primary/20"
                : "bg-muted/50 text-muted-foreground border border-border/40 hover:bg-muted hover:text-foreground",
            )}
          >
            <Globe className={cn("size-3.5", checked ? "text-primary" : "text-muted-foreground")} />
            <span className="text-[0.6875rem] font-semibold hidden sm:inline">
              {checked ? "Remote DNS" : "Local DNS"}
            </span>
            <span className="text-[0.6875rem] font-semibold sm:hidden">
              {checked ? "Remote" : "Local"}
            </span>
          </InputGroupButton>
        </TooltipTrigger>
        <TooltipContent className="max-w-64">
          {checked
            ? "Remote DNS (Active): The target hostname is resolved directly by the remote node."
            : "Local DNS (Active): The target hostname is resolved in your browser first."}
        </TooltipContent>
      </Tooltip>
    </div>
  );
}

function ChoiceToggleGroup({
  ariaLabel,
  value,
  options,
  onValueChange,
}: {
  ariaLabel: string;
  value: string;
  options: Array<{ value: string; label: string }>;
  onValueChange: (value: string) => void;
}) {
  return (
    <ToggleGroup
      type="single"
      value={value}
      onValueChange={(next) => {
        if (next) onValueChange(next);
      }}
      className="flex h-9 shrink-0 items-center gap-0 rounded-md border bg-background p-0.5 [@container(min-width:34rem)]:gap-1 [@container(min-width:34rem)]:p-1"
      aria-label={ariaLabel}
    >
      {options.map((option) => (
        <ToggleGroupItem
          key={option.value}
          value={option.value}
          aria-label={`${ariaLabel}: ${option.label}`}
          className="h-7 min-w-0 rounded px-1.5 font-mono text-[0.625rem] font-semibold text-muted-foreground hover:text-foreground data-[state=on]:bg-primary data-[state=on]:text-primary-foreground data-[state=on]:shadow-sm data-[state=on]:hover:bg-primary data-[state=on]:hover:text-primary-foreground [@container(min-width:34rem)]:px-2.5 [@container(min-width:34rem)]:text-xs"
        >
          {option.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}
