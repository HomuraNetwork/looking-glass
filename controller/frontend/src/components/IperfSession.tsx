import { type ReactNode, memo, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, CircleDashed, Copy, Gauge, Info, Play, RotateCcw, SlidersHorizontal, Square, Terminal } from "lucide-react";
import { ChallengeGate, type ChallengeGateHandle } from "@/components/ChallengeGate";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import type { PublicNode } from "@/lib/api";
import { buildIperfWSURL, closeIperfSession, requestIperfSession } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Props {
  className?: string;
  node?: PublicNode;
  challengeSiteKey: string;
  onDebug?: (line: string) => void;
}

export interface IperfDisplayEventInput {
  type?: string;
  line?: string;
  port?: number;
  remaining_seconds?: number;
  remaining_runs?: number;
  runs_used?: number;
  max_runs?: number;
  close_reason?: string;
  command?: string;
  mode?: string;
  reverse?: boolean;
  at?: number;
}

export interface IperfDisplayEvent {
  stream: "output" | "debug" | "status";
  line?: string;
  closeReason?: string;
}

export function buildIperfServerCommand(port?: number): string {
  return port ? `$ iperf3 -s -p ${port}` : "$ iperf3 -s";
}

export interface IperfClientCommandOptions {
  mode: "tcp" | "udp";
  reverse: boolean;
  duration: number;
  parallel: number;
}

export type IperfHostFamily = "ipv4" | "ipv6";
export type IperfHostChoice = "default" | IperfHostFamily;
export type AgentIperfFlow = { mode: "tcp" | "udp"; reverse: boolean } | null;
export type IperfRunOutcome = "" | "cancelled" | "finished" | "expired" | "error" | "closed";

const IPERF_OUTPUT_HISTORY_LINES = 119;
const DEBUG_EVENT_PREVIEW_CHARS = 160;

export function buildIperfClientCommand(host: string | undefined, port: number | undefined, options: IperfClientCommandOptions): string {
  if (!host) return "Select a node";
  const args = ["iperf3"];
  if (options.mode === "udp") args.push("-u");
  args.push("-c", host);
  if (port) args.push("-p", String(port));
  if (options.parallel > 1) args.push("-P", String(options.parallel));
  if (options.duration !== 10) args.push("-t", String(options.duration));
  if (options.reverse) args.push("-R");
  return args.join(" ");
}

export function formatIperfDisplayEvent(payload: IperfDisplayEventInput): IperfDisplayEvent {
  if (payload.type === "debug") {
    return { stream: "debug", line: payload.line || "" };
  }
  if (payload.type === "closed") {
    const reason = payload.close_reason || "closed";
    return {
      stream: "output",
      line: `${formatCloseReason(reason)}\n----- END AT ${formatEventTime(payload.at)} -----`,
      closeReason: reason,
    };
  }
  if (payload.type === "output" && payload.line) {
    if (payload.line.startsWith("server listening:") || payload.line.startsWith("---- server listening:")) {
      return { stream: "debug", line: payload.line };
    }
    return { stream: "output", line: payload.line };
  }
  return { stream: "status", closeReason: payload.close_reason };
}

export function formatIperfAgentDebugEvent(payload: IperfDisplayEventInput): string {
  const type = payload.type || "event";
  if (type === "status") {
    return [
      "agent status:",
      `port=${payload.port ?? "-"}`,
      `remaining=${payload.remaining_seconds ?? "-"}s`,
      `runs_left=${payload.remaining_runs ?? "-"}`,
      `runs_used=${payload.runs_used ?? "-"}`,
    ].join(" ");
  }
  if (type === "output") return `agent output: ${payload.line || ""}`;
  if (type === "debug") return `agent debug: ${payload.line || ""}`;
  if (type === "closed") return `agent closed: reason=${payload.close_reason || "closed"} at=${formatEventTime(payload.at)}`;
  return `agent ${type}: ${payload.line || JSON.stringify(payload)}`;
}

export function shouldAutoRunIperfChallenge(
  challengeVisible: boolean,
  challengeToken: string,
  isOpening: boolean,
  sessionActive: boolean,
): boolean {
  return challengeVisible && challengeToken.length > 0 && !isOpening && !sessionActive;
}

export function agentIperfFlowFromPayload(payload: { mode?: string; reverse?: boolean }): AgentIperfFlow {
  if (payload.mode !== "tcp" && payload.mode !== "udp") return null;
  return { mode: payload.mode, reverse: payload.reverse === true };
}

export function agentIperfFlowFromCommand(command?: string): AgentIperfFlow {
  const raw = command?.trim();
  if (!raw || !/\biperf3\b/.test(raw) || !/\s-c\s+\S+/.test(` ${raw}`)) return null;
  const padded = ` ${raw} `;
  return {
    mode: /\s-u(\s|$)/.test(padded) ? "udp" : "tcp",
    reverse: /\s-R(\s|$)/.test(padded),
  };
}

function agentIperfFlowFromEvent(payload: { mode?: string; reverse?: boolean }): AgentIperfFlow {
  return agentIperfFlowFromPayload(payload);
}

function formatCloseReason(reason: string): string {
  if (reason === "closed_by_request") return `cancelled: ${reason}`;
  if (reason === "ttl_expired") return `expired: ${reason}`;
  if (reason === "run_limit") return `completed: ${reason}`;
  if (reason === "event_stream_closed") return "event stream closed; session closed";
  if (reason.includes("limit") || reason.includes("error") || reason.includes("invalid") || reason.includes("unsupported")) {
    return `error: ${reason}`;
  }
  return `closed: ${reason}`;
}

function formatEventTime(epochSeconds?: number): string {
  const date = typeof epochSeconds === "number" && epochSeconds > 0 ? new Date(epochSeconds * 1000) : new Date();
  return date.toISOString().replace(".000Z", "Z");
}

export function iperfOutcomeFromOutput(line: string): IperfRunOutcome {
  if (line.includes("---------- RUN COMPLETE ----------")) return "finished";
  if (line.startsWith("cancelled:")) return "cancelled";
  if (line.startsWith("error:") || line.startsWith("client rejected:")) return "error";
  if (line.includes("accepted connection from") || line.includes("connected to")) return "";
  if (/\b(sender|receiver)\b/.test(line)) return "finished";
  return "";
}

export function iperfOutcomeFromCloseReason(reason: string): IperfRunOutcome {
  if (reason === "run_limit") return "finished";
  if (reason === "closed_by_request") return "cancelled";
  if (reason === "ttl_expired") return "expired";
  if (reason.includes("limit") || reason.includes("error") || reason.includes("invalid") || reason.includes("unsupported")) return "error";
  return "closed";
}

export const IperfSession = memo(function IperfSession({ className, node, challengeSiteKey, onDebug }: Props) {
  const [hostChoice, setHostChoice] = useState<IperfHostChoice>("ipv4");
  const [mode, setMode] = useState<"tcp" | "udp">("tcp");
  const [reverse, setReverse] = useState(false);
  const [duration, setDuration] = useState(10);
  const [parallel, setParallel] = useState(1);
  const [command, setCommand] = useState(() => buildIperfClientCommand(preferredIperfClientHost(node, "", "ipv4"), undefined, { mode: "tcp", reverse: false, duration: 10, parallel: 1 }));
  const [remainingSeconds, setRemainingSeconds] = useState(0);
  const [remainingRuns, setRemainingRuns] = useState(0);
  const [closeReason, setCloseReason] = useState("");
  const [sessionID, setSessionID] = useState("");
  const [sessionHost, setSessionHost] = useState("");
  const [sessionPort, setSessionPort] = useState<number | undefined>(undefined);
  const [sessionActive, setSessionActive] = useState(false);
  const [agentFlow, setAgentFlow] = useState<AgentIperfFlow>(null);
  // Status events keep the selected flow; output lines determine active transfer state.
  const [clientConnected, setClientConnected] = useState(false);
  const [outputLines, setOutputLines] = useState<string[]>([]);
  const [challengeVisible, setChallengeVisible] = useState(false);
  const [challengeToken, setChallengeToken] = useState("");
  const [isOpening, setIsOpening] = useState(false);
  const [copied, setCopied] = useState(false);
  const challengeRef = useRef<ChallengeGateHandle | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const terminalRef = useRef<HTMLPreElement | null>(null);
  const endedRef = useRef(false);
  const submittedChallengeRef = useRef("");
  const copiedTimerRef = useRef<number | null>(null);
  const appendedCloseReasonRef = useRef("");

  useEffect(() => {
    return () => {
      socketRef.current?.close();
      if (copiedTimerRef.current !== null) window.clearTimeout(copiedTimerRef.current);
    };
  }, []);

  useEffect(() => {
    setAgentFlow(null);
    setSessionActive(false);
    setSessionID("");
    setSessionHost("");
    setSessionPort(undefined);
    setOutputLines([]);
    setClientConnected(false);
    socketRef.current?.close();
    socketRef.current = null;
  }, [node?.id]);

  useLayoutEffect(() => {
    if (!terminalRef.current) return;
    terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [outputLines]);

  useEffect(() => {
    if (sessionActive || challengeVisible || isOpening || closeReason) return;
    setSessionHost("");
    setSessionPort(undefined);
    setCommand(buildCommandFor({ mode, reverse, duration, parallel }));
  }, [node?.id, node?.domain, node?.domain_v4, node?.domain_v6, node?.public_ipv4, node?.public_ipv6, hostChoice, mode, reverse, duration, parallel, sessionActive, challengeVisible, isOpening, closeReason]);

  function appendDebug(line: string) {
    onDebug?.(line);
  }

  function buildCommandFor(overrides: Partial<IperfClientCommandOptions> = {}, port = sessionPort, host = sessionHost, family = effectiveIperfHostFamily(hostChoice)): string {
    return buildIperfClientCommand(preferredIperfClientHost(node, host, family), port, { mode, reverse, duration, parallel, ...overrides });
  }

  function applyCommandSelection(overrides: Partial<IperfClientCommandOptions>, family = effectiveIperfHostFamily(hostChoice)) {
    setCommand(buildCommandFor(overrides, sessionPort, sessionHost, family));
  }

  function resetCommandOptions() {
    setHostChoice("ipv4");
    setMode("tcp");
    setReverse(false);
    setDuration(10);
    setParallel(1);
    setCommand(buildIperfClientCommand(preferredIperfClientHost(node, sessionHost, "ipv4"), sessionPort, {
      mode: "tcp",
      reverse: false,
      duration: 10,
      parallel: 1,
    }));
  }

  function beginOpen() {
    setCloseReason("");
    setChallengeVisible(true);
    setChallengeToken("");
    setAgentFlow(null);
    setClientConnected(false);
    appendedCloseReasonRef.current = "";
    submittedChallengeRef.current = "";
    setCommand("Complete challenge to start iPerf3");
  }

  async function open() {
    if (!node || !challengeToken) return;
    setIsOpening(true);
    setCommand("opening session");
    try {
      const session = await requestIperfSession({ node: node.id, mode, reverse, duration, parallel, turnstileToken: challengeToken });
      const host = preferredIperfClientHost(node, session.host, effectiveIperfHostFamily(hostChoice));
      const nextCommand = buildIperfClientCommand(host, session.port, { mode, reverse, duration, parallel });
      setSessionHost(host);
      setSessionPort(session.port);
      setCommand(nextCommand);
      setRemainingSeconds(Math.max(0, Math.floor(session.expires_at - Date.now() / 1000)));
      setRemainingRuns(session.max_runs);
      setCloseReason("");
      setSessionID(session.session_id);
      setSessionActive(true);
      setClientConnected(false);
      setChallengeVisible(false);
      setOutputLines([buildIperfServerCommand(session.port)]);
      appendDebug(`open session: ${session.session_id} server=${buildIperfServerCommand(session.port)} client="${nextCommand}" agent_client="${session.command}"`);
      endedRef.current = false;
      appendedCloseReasonRef.current = "";
      socketRef.current?.close();
      const socket = new WebSocket(buildIperfWSURL(node, session.session_id));
      socketRef.current = socket;
      let pendingLines: string[] = [];
      let flushScheduled = false;
      const flushLines = () => {
        flushScheduled = false;
        if (pendingLines.length === 0) return;
        const toAppend = pendingLines;
        pendingLines = [];
        setOutputLines((current) => [...current.slice(-IPERF_OUTPUT_HISTORY_LINES), ...toAppend].slice(-IPERF_OUTPUT_HISTORY_LINES));
      };

      socket.onmessage = (event) => {
        if (socketRef.current !== socket) return;
        let payload: IperfDisplayEventInput;
        try {
          payload = JSON.parse(String(event.data)) as IperfDisplayEventInput;
        } catch {
          flushLines();
          setCloseReason("bad_agent_event");
          setClientConnected(false);
          setOutputLines((current) => [...current.slice(-IPERF_OUTPUT_HISTORY_LINES), "error: bad_agent_event", `----- END AT ${formatEventTime()} -----`]);
          appendDebug(`agent bad event: ${String(event.data).slice(0, DEBUG_EVENT_PREVIEW_CHARS)}`);
          socket.close();
          return;
        }
        const nextFlow = agentIperfFlowFromEvent(payload);
        if (nextFlow) setAgentFlow(nextFlow);
        if (payload.type !== "output" && typeof payload.remaining_seconds === "number") setRemainingSeconds(payload.remaining_seconds);
        if (payload.type !== "output" && typeof payload.remaining_runs === "number") setRemainingRuns(payload.remaining_runs);
        const display = formatIperfDisplayEvent(payload);
        appendDebug(formatIperfAgentDebugEvent(payload));
        if (display.closeReason) {
          setCloseReason(display.closeReason);
          setClientConnected(false);
        }
        if (payload.type === "closed") {
          endedRef.current = true;
          setSessionActive(false);
        }
        if (display.stream === "output" && display.line) {
          if (display.closeReason && appendedCloseReasonRef.current === display.closeReason) return;
          if (display.closeReason) appendedCloseReasonRef.current = display.closeReason;
          if (display.line.includes("accepted connection from") || display.line.includes("connected to")) {
            setClientConnected(true);
          } else if (iperfOutcomeFromOutput(display.line)) {
            setClientConnected(false);
          }
          pendingLines.push(display.line);
          if (!flushScheduled) {
            flushScheduled = true;
            queueMicrotask(flushLines);
          }
        }
      };
      socket.onclose = () => {
        if (socketRef.current !== socket) return;
        flushLines();
        if (!endedRef.current) {
          setCloseReason("event_stream_closed");
          setClientConnected(false);
          setOutputLines((current) => [...current.slice(-IPERF_OUTPUT_HISTORY_LINES), `----- END AT ${formatEventTime()} -----`]);
          appendDebug("event websocket closed before agent closed event; closing session");
          void closeIperfSession(node.id, session.session_id).catch((error) => {
            appendDebug(`event websocket cleanup failed: ${error instanceof Error ? error.message : "unknown error"}`);
          });
        }
        socketRef.current = null;
        setSessionActive(false);
      };
    } catch (error) {
      setCommand(error instanceof Error ? error.message : "session request failed");
    } finally {
      challengeRef.current?.reset();
      setIsOpening(false);
    }
  }

  useEffect(() => {
    if (!shouldAutoRunIperfChallenge(challengeVisible, challengeToken, isOpening, sessionActive)) return;
    if (submittedChallengeRef.current === challengeToken) return;
    submittedChallengeRef.current = challengeToken;
    void open();
  }, [challengeVisible, challengeToken, isOpening, sessionActive]);

  async function stop() {
    if (!node || !sessionID) {
      socketRef.current?.close();
      setSessionActive(false);
      return;
    }
    setCommand("closing session");
    try {
      await closeIperfSession(node.id, sessionID);
      setCloseReason("closed_by_request");
      setClientConnected(false);
      setOutputLines((current) => [
        ...current.slice(-IPERF_OUTPUT_HISTORY_LINES),
        `${formatCloseReason("closed_by_request")}\n----- END AT ${formatEventTime()} -----`,
      ]);
      appendedCloseReasonRef.current = "closed_by_request";
      endedRef.current = true;
      appendDebug(`close session: ${sessionID}`);
    } catch (error) {
      setCommand(error instanceof Error ? error.message : "close failed");
      appendDebug(`close failed: ${error instanceof Error ? error.message : "unknown error"}`);
    } finally {
      socketRef.current?.close();
      socketRef.current = null;
      setSessionActive(false);
      setChallengeVisible(false);
      setIsOpening(false);
    }
  }

  async function copyCommand() {
    try {
      await navigator.clipboard?.writeText(command);
      setCopied(true);
      if (copiedTimerRef.current !== null) window.clearTimeout(copiedTimerRef.current);
      copiedTimerRef.current = window.setTimeout(() => {
        copiedTimerRef.current = null;
        setCopied(false);
      }, 1200);
    } catch (error) {
      appendDebug(`copy command failed: ${error instanceof Error ? error.message : "unknown error"}`);
    }
  }

  const hasOutput = outputLines.length > 0;
  const controlOverlayVisible = challengeVisible || isOpening || (!hasOutput && !closeReason);
  const optionsDisabled = isOpening;
  const restartInCommandAction = !sessionActive && hasOutput && !challengeVisible && !isOpening;
  const limitsSummary = `${duration}s · ${formatStreamCount(parallel)}`;
  const generatorSummary = `${hostChoice === "ipv6" ? "IPv6" : "IPv4"} · ${mode.toUpperCase()} · ${reverse ? "Download" : "Upload"}`;
  const options = (
    <div className="flex flex-col gap-2 rounded-xl border border-border/70 bg-muted/20 p-2.5 shadow-2xs" data-iperf-command-generator>
      <div className="flex min-w-0 items-center justify-between gap-2">
        <div className="flex items-center gap-1.5">
          <SlidersHorizontal className="size-3.5 text-primary" />
          <span className="text-xs font-bold text-foreground">Command generator</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Badge variant="outline" className="min-w-0 truncate px-2 py-0.5 font-mono text-[0.625rem] font-semibold text-muted-foreground bg-background/60">
            {generatorSummary}
          </Badge>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                size="icon"
                variant="ghost"
                className="size-6 rounded text-muted-foreground hover:bg-muted hover:text-foreground"
                disabled={optionsDisabled}
                onClick={resetCommandOptions}
                aria-label="Reset iPerf3 command options"
              >
                <RotateCcw className="size-3" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Reset command options</TooltipContent>
          </Tooltip>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <GeneratorPills
          label="Host"
          value={hostChoice}
          disabled={optionsDisabled}
          options={[
            { value: "ipv4", label: "IPv4", disabled: node?.has_ipv4 === false || (!node?.public_ipv4 && !node?.domain_v4 && !node?.domain) },
            { value: "ipv6", label: "IPv6", disabled: node?.has_ipv6 === false || (!node?.public_ipv6 && !node?.domain_v6 && !node?.domain) },
          ]}
          onValueChange={(value) => {
            const next = value === "ipv4" || value === "ipv6" ? value : "default";
            setHostChoice(next);
            applyCommandSelection({}, effectiveIperfHostFamily(next));
          }}
        />
        <GeneratorPills
          label="Protocol"
          value={mode}
          disabled={optionsDisabled}
          tooltip="TCP is iperf3's default mode. UDP adds -u to the generated command."
          options={[
            { value: "tcp", label: "TCP" },
            { value: "udp", label: "UDP" },
          ]}
          onValueChange={(value) => {
            const next = value === "udp" ? "udp" : "tcp";
            setMode(next);
            applyCommandSelection({ mode: next });
          }}
        />
        <GeneratorPills
          label="Direction"
          value={reverse ? "download" : "upload"}
          disabled={optionsDisabled}
          tooltip="Download adds -R, so the server sends traffic to you. Upload sends traffic from you to the server."
          options={[
            { value: "upload", label: "Upload" },
            { value: "download", label: "Download" },
          ]}
          onValueChange={(value) => {
            const next = value === "download";
            setReverse(next);
            applyCommandSelection({ reverse: next });
          }}
        />
        <GeneratorTile label="Limits">
          <Popover>
            <PopoverTrigger asChild>
              <Button
                type="button"
                variant="outline"
                disabled={optionsDisabled}
                className="flex h-8 min-h-8 w-full items-center justify-between gap-1.5 rounded-lg border border-border/70 bg-background px-2.5 font-mono text-[0.6875rem] font-bold shadow-2xs hover:bg-muted/50 transition-colors disabled:cursor-not-allowed disabled:opacity-45"
                aria-label={`iPerf3 limits: ${limitsSummary}`}
              >
                <span className="truncate text-foreground font-semibold">
                  {limitsSummary}
                </span>
                <SlidersHorizontal data-icon="inline-end" className="size-3 text-muted-foreground shrink-0" />
              </Button>
            </PopoverTrigger>
            <PopoverContent align="end" sideOffset={8} aria-label="iPerf3 limits" className="w-56 bg-card text-card-foreground shadow-xl rounded-xl p-3 border">
              <div className="flex flex-col gap-3">
                <div className="text-[0.6875rem] font-bold text-foreground uppercase tracking-wider">Session Limits</div>
                <GeneratorPills
                  label="Time"
                  value={duration === 10 ? "default" : String(duration)}
                  disabled={optionsDisabled}
                  options={[
                    { value: "default", label: "10s" },
                    { value: "20", label: "20s" },
                    { value: "40", label: "40s" },
                  ]}
                  onValueChange={(value) => {
                    const next = value === "default" ? 10 : Number(value);
                    setDuration(next);
                    applyCommandSelection({ duration: next });
                  }}
                />
                <GeneratorPills
                  label="Parallel streams"
                  tooltip="Parallel streams adds -P. One stream is iperf3's default."
                  value={parallel === 1 ? "default" : String(parallel)}
                  disabled={optionsDisabled}
                  options={[
                    { value: "default", label: "1 stream", shortLabel: "1" },
                    { value: "4", label: "4 streams", shortLabel: "4" },
                    { value: "10", label: "10 streams", shortLabel: "10" },
                  ]}
                  onValueChange={(value) => {
                    const next = value === "default" ? 1 : Number(value);
                    setParallel(next);
                    applyCommandSelection({ parallel: next });
                  }}
                />
              </div>
            </PopoverContent>
          </Popover>
        </GeneratorTile>
      </div>
    </div>
  );

  return (
    <TooltipProvider delayDuration={150}>
      <div className={cn("flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card", className)}>
        <div className="flex h-10 items-center gap-2.5 border-b bg-muted/30 px-3.5">
          <div className="flex size-6 items-center justify-center rounded-md border border-primary/25 bg-primary/10 text-primary">
            <Gauge className="size-3.5" />
          </div>
          <span className="text-xs font-bold text-foreground">iPerf3</span>
        </div>
        <div className="relative min-h-0 flex-none p-2 [@media_(min-height:846px)]:lg:flex-1" data-iperf-body="true">
          <div className="grid min-h-[13rem] gap-2 lg:min-h-0 lg:grid-cols-[minmax(18rem,22rem)_minmax(0,1fr)] xl:grid-cols-[minmax(20rem,28rem)_minmax(0,1fr)] [@media_(min-height:846px)]:lg:h-full" data-iperf-layout-grid>
            <div className="flex min-h-0 flex-col gap-2 lg:h-full">
              <div className="relative flex min-h-[11rem] flex-1 flex-col overflow-hidden p-0 lg:min-h-0" data-iperf-control-surface="true">
                <div className="flex min-h-0 flex-col gap-2.5 lg:h-full lg:overflow-y-auto lg:pr-1" data-iperf-control-content>
                  {closeReason && (
                    <div className="flex items-center justify-between rounded-lg border border-destructive/30 bg-destructive/10 px-2.5 py-1.5 text-xs text-destructive">
                      <span className="font-mono font-bold flex items-center gap-1.5">
                        <Square className="size-3 fill-destructive" />
                        Stopped
                      </span>
                      <span className="font-mono text-[0.6875rem] text-destructive/90">{formatCloseReason(closeReason)}</span>
                    </div>
                  )}
                  {!closeReason && <div className="flex flex-col gap-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                        <Terminal className="size-3.5 text-primary" />
                        Client command
                      </span>
                      <span className="text-[0.6875rem] text-muted-foreground">Run locally in terminal</span>
                    </div>
                    <InputGroup className="h-9 border-border/80 bg-background/80 shadow-2xs">
                      <InputGroupAddon align="inline-start" className="pl-3 pr-0.5 select-none font-mono text-xs font-bold text-primary">
                        $
                      </InputGroupAddon>
                      <InputGroupInput
                        aria-label="iPerf3 client command"
                        className="h-8 font-mono text-xs text-foreground pl-1.5"
                        spellCheck={false}
                        value={command}
                        onChange={(event) => setCommand(event.target.value)}
                      />
                      {!restartInCommandAction && (
                        <InputGroupAddon align="inline-end" className="pr-1">
                          <InputGroupButton
                            disabled={!command || command === "Select a node"}
                            onClick={copyCommand}
                            data-iperf-copy-command
                            className="h-7 gap-1 rounded-md px-2.5 font-semibold text-xs bg-primary/10 text-primary hover:bg-primary hover:text-primary-foreground transition-colors"
                          >
                            <Copy className="size-3" />
                            {copied ? "Copied" : "Copy"}
                          </InputGroupButton>
                        </InputGroupAddon>
                      )}
                    </InputGroup>
                  </div>}
                  {options}
                </div>
                {controlOverlayVisible && (
                  <div className="absolute inset-0 flex items-center justify-center overflow-auto rounded-xl bg-card/90 backdrop-blur-xs p-3 transition-all" data-iperf-start-overlay>
                    <div className="flex w-full max-w-sm flex-col gap-2.5 text-center">
                      {!challengeVisible ? (
                        <Button
                          size="default"
                          className="h-10 w-full gap-2 rounded-xl text-xs font-bold shadow-md transition-all active:scale-[0.98]"
                          disabled={!node || isOpening}
                          onClick={beginOpen}
                        >
                          <Play className="size-3.5 fill-current" />
                          Start iPerf3
                        </Button>
                      ) : (
                        <>
                          <ChallengeGate ref={challengeRef} siteKey={challengeSiteKey} onToken={setChallengeToken} />
                          <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => setChallengeVisible(false)}>
                            Cancel
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
              <div className="flex min-h-8 flex-wrap items-center gap-2" data-iperf-command-action>
                {restartInCommandAction ? (
                  <Button
                    size="sm"
                    variant="default"
                    className="h-9 w-full gap-1.5 rounded-lg text-xs font-semibold shadow-xs"
                    disabled={!node}
                    onClick={beginOpen}
                  >
                    <RotateCcw className="size-3.5" />
                    Restart
                  </Button>
                ) : sessionActive ? (
                  <Button
                    size="sm"
                    variant="destructive"
                    className="h-9 w-full gap-1.5 rounded-lg text-xs font-semibold shadow-xs"
                    onClick={stop}
                  >
                    <Square className="size-3.5 fill-current" />
                    Stop
                  </Button>
                ) : null}
              </div>
            </div>
            <div className="grid min-h-[13rem] gap-2 lg:h-full lg:min-h-0 lg:grid-cols-[minmax(0,1fr)_clamp(9.5rem,12vw,13rem)] lg:grid-rows-[minmax(0,1fr)] lg:overflow-hidden" data-iperf-right-pane>
              <div className="h-[13rem] max-h-[13rem] min-h-0 overflow-hidden rounded-lg border bg-background/60 [@media_(min-height:846px)]:lg:h-full [@media_(min-height:846px)]:lg:max-h-full" data-iperf-terminal>
                <pre ref={terminalRef} className="terminal-surface h-full max-h-[13rem] min-h-0 overflow-auto p-3 font-mono text-xs leading-relaxed text-slate-200 [@media_(min-height:846px)]:lg:max-h-full">
                  {outputLines.length > 0 ? outputLines.join("\n") : "\n\n"}
                </pre>
              </div>
              <div className="min-h-0" data-iperf-status-rail>
                <IperfFlowCard
                  agentFlow={agentFlow}
                  sessionActive={sessionActive}
                  clientConnected={clientConnected}
                  remainingSeconds={remainingSeconds}
                  remainingRuns={remainingRuns}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
});

export type IperfFlowDir = "to-you" | "to-server" | null;

export function iperfFlowDirection(flow: AgentIperfFlow, connected: boolean): IperfFlowDir {
  if (!connected || !flow) return null;
  return flow.reverse ? "to-you" : "to-server";
}

export function iperfFlowStatusLabel(sessionActive: boolean, dir: IperfFlowDir): string {
  if (dir) return "Running";
  if (sessionActive) return "Listening";
  return "Not started";
}

export function iperfFlowDirectionText(dir: IperfFlowDir): string {
  if (dir === "to-you") return "server to you";
  if (dir === "to-server") return "you to server";
  return "--";
}

function IperfFlowCard({
  agentFlow,
  sessionActive,
  clientConnected,
  remainingSeconds,
  remainingRuns,
}: {
  agentFlow: AgentIperfFlow;
  sessionActive: boolean;
  clientConnected: boolean;
  remainingSeconds: number;
  remainingRuns: number;
}) {
  const dir = iperfFlowDirection(agentFlow, sessionActive && clientConnected);
  const transferring = dir !== null;
  const protocol = transferring && agentFlow ? agentFlow.mode : null;
  const statusLabel = iperfFlowStatusLabel(sessionActive, dir);
  const budgetText = sessionActive
    ? [remainingSeconds > 0 ? `${remainingSeconds}s left` : null, remainingRuns > 0 ? `${remainingRuns} run${remainingRuns === 1 ? "" : "s"} left` : null]
        .filter(Boolean)
        .join(" · ")
    : "";

  return (
    <div
      className={cn(
        "flex h-full min-h-[9rem] flex-col justify-between gap-2.5 rounded-xl border bg-background/80 p-3 shadow-sm transition-colors lg:min-h-0",
        transferring ? "border-primary/40 ring-1 ring-primary/15" : sessionActive && "border-primary/25",
      )}
    >
      <span className="sr-only" aria-live="polite">
        iPerf3 transfer <span data-iperf-session-status>{statusLabel}</span>, direction{" "}
        <span data-iperf-direction-status>{iperfFlowDirectionText(dir)}</span>, protocol{" "}
        <span data-iperf-protocol-status>{protocol ?? "--"}</span>
        {budgetText ? `, ${budgetText}` : ""}
      </span>

      <div className="flex items-center justify-between gap-1.5" aria-hidden>
        <div className="flex items-center gap-1.5 min-w-0">
          <span className={cn("size-2 flex-shrink-0 rounded-full", transferring ? "animate-pulse bg-success" : sessionActive ? "animate-pulse bg-primary" : "bg-muted-foreground/40")} />
          <span className={cn("text-xs font-bold uppercase tracking-wider whitespace-nowrap", transferring ? "text-success" : sessionActive ? "text-foreground" : "text-muted-foreground")}>
            {statusLabel}
          </span>
        </div>
        {protocol && (
          <Badge variant="outline" className="font-mono text-[0.625rem] font-bold uppercase px-1.5 py-0 bg-primary/10 text-primary border-primary/30">
            {protocol}
          </Badge>
        )}
      </div>

      {sessionActive ? (
        <>
          <div className="flex flex-1 items-center justify-center my-auto" aria-hidden>
            <IperfFlowDiagram orientation="horizontal" className="flex w-full lg:hidden" dir={dir} protocol={protocol} active={transferring} />
            <IperfFlowDiagram orientation="vertical" className="hidden h-full lg:flex" dir={dir} protocol={protocol} active={transferring} />
          </div>
          <div className="grid grid-cols-2 gap-1 rounded-lg border border-border/70 bg-muted/30 p-1" aria-hidden>
            <div className="flex flex-col items-center justify-center py-1">
              <span className={cn("font-mono text-sm font-black leading-tight tabular-nums", remainingSeconds > 0 && remainingSeconds <= 20 ? "text-destructive" : "text-foreground")}>
                {remainingSeconds > 0 ? `${remainingSeconds}s` : "--"}
              </span>
              <span className="text-[0.625rem] font-medium text-muted-foreground">Time left</span>
            </div>
            <div className="flex flex-col items-center justify-center border-l border-border/60 py-1">
              <span className="font-mono text-sm font-black leading-tight tabular-nums text-foreground">
                {remainingRuns > 0 ? remainingRuns : "--"}
              </span>
              <span className="text-[0.625rem] font-medium text-muted-foreground">Runs left</span>
            </div>
          </div>
        </>
      ) : (
        <div className="flex flex-1 flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed bg-muted/15 p-3 text-center" aria-hidden>
          <div className="flex size-7 items-center justify-center rounded-full bg-muted/40 text-muted-foreground/60">
            <CircleDashed className="size-4" />
          </div>
          <span className="text-xs font-semibold text-muted-foreground">No active session</span>
          <span className="text-[0.6875rem] text-muted-foreground/75 leading-tight">Start iPerf3 to see the live transfer</span>
        </div>
      )}
    </div>
  );
}

function IperfFlowEndpoint({ label, sublabel, active }: { label: string; sublabel?: string; active: boolean }) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-lg border px-2.5 py-1 text-center transition-all w-full max-w-[6.5rem]",
        active
          ? "border-primary/50 bg-primary/10 text-primary shadow-xs ring-1 ring-primary/20"
          : "border-border/70 bg-card/80 text-muted-foreground",
      )}
    >
      <span className={cn("font-mono text-xs font-bold leading-tight", active ? "text-primary" : "text-foreground")}>
        {label}
      </span>
      {sublabel && (
        <span className="text-[0.5625rem] font-medium uppercase tracking-wider text-muted-foreground">
          {sublabel}
        </span>
      )}
    </div>
  );
}

function IperfFlowDiagram({
  orientation,
  className,
  dir,
  protocol,
  active,
}: {
  orientation: "horizontal" | "vertical";
  className?: string;
  dir: IperfFlowDir;
  protocol: "tcp" | "udp" | null;
  active: boolean;
}) {
  const vertical = orientation === "vertical";
  const proto = protocol ? protocol.toUpperCase() : null;
  const track = <IperfFlowTrack orientation={orientation} dir={dir} active={active} />;

  if (vertical) {
    return (
      <div className={cn("flex-col items-center justify-center gap-1 w-full", className)}>
        <IperfFlowEndpoint label="SERVER" sublabel="Node" active={dir === "to-you"} />
        <div className="flex flex-col items-center justify-center gap-0.5 py-1">
          {dir && (
            <span className="font-mono text-[0.625rem] font-bold uppercase tracking-wider text-primary">
              {dir === "to-you" ? "Download" : "Upload"}
            </span>
          )}
          {track}
        </div>
        <IperfFlowEndpoint label="YOU" sublabel="Client" active={dir === "to-server"} />
      </div>
    );
  }
  return (
    <div className={cn("items-center justify-between gap-2 w-full", className)}>
      <IperfFlowEndpoint label="SERVER" sublabel="Node" active={dir === "to-you"} />
      <div className="flex min-w-0 flex-1 flex-col items-center gap-0.5">
        <span className="font-mono text-[0.625rem] font-bold uppercase tracking-wider text-muted-foreground">
          {dir ? (dir === "to-you" ? "Download" : "Upload") : (proto ?? "Idle")}
        </span>
        {track}
      </div>
      <IperfFlowEndpoint label="YOU" sublabel="Client" active={dir === "to-server"} />
    </div>
  );
}

function IperfFlowTrack({
  orientation,
  dir,
  active,
}: {
  orientation: "horizontal" | "vertical";
  dir: IperfFlowDir;
  active: boolean;
}) {
  const vertical = orientation === "vertical";
  if (!dir) {
    return <span className={cn("rounded-full bg-muted-foreground/25", vertical ? "h-12 w-0.5" : "h-0.5 w-full max-w-24")} aria-hidden />;
  }
  const Chevron = vertical ? (dir === "to-server" ? ChevronUp : ChevronDown) : dir === "to-server" ? ChevronLeft : ChevronRight;
  return (
    <span className={cn("flex items-center justify-center text-primary", vertical ? "flex-col" : "flex-row")} aria-hidden>
      {[0, 1, 2].map((index) => (
        <Chevron
          key={index}
          className={cn(
            "size-4 -m-0.5",
            index === 1 && "[animation-delay:180ms]",
            index === 2 && "[animation-delay:360ms]",
            active && "animate-pulse",
          )}
        />
      ))}
    </span>
  );
}

function formatStreamCount(count: number): string {
  return `${count} stream${count === 1 ? "" : "s"}`;
}

function GeneratorTile({ label, tooltip, children }: { label: string; tooltip?: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <span className="flex min-w-0 items-center gap-1 text-[0.6875rem] font-semibold text-muted-foreground">
        <span className="truncate">{label}</span>
        {tooltip && (
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" className="inline-flex size-3.5 items-center justify-center rounded text-muted-foreground/70 hover:text-foreground" aria-label={`${label} help`}>
                <Info className="size-3" />
              </button>
            </TooltipTrigger>
            <TooltipContent className="max-w-64">{tooltip}</TooltipContent>
          </Tooltip>
        )}
      </span>
      {children}
    </div>
  );
}

export function preferredIperfClientHost(node?: PublicNode, fallbackHost = "", family: IperfHostFamily = "ipv4"): string {
  const fallback = fallbackHost.trim();
  if (family === "ipv6") {
    return node?.public_ipv6?.trim() || node?.domain_v6?.trim() || fallback || node?.domain?.trim() || "";
  }
  return node?.public_ipv4?.trim() || node?.domain_v4?.trim() || fallback || node?.domain?.trim() || "";
}

export function effectiveIperfHostFamily(choice: IperfHostChoice): IperfHostFamily {
  return choice === "ipv6" ? "ipv6" : "ipv4";
}

function GeneratorPills({
  label,
  value,
  disabled,
  options,
  tooltip,
  onValueChange,
}: {
  label: string;
  value: string;
  disabled: boolean;
  options: Array<{ value: string; label: string; shortLabel?: string; disabled?: boolean }>;
  tooltip?: string;
  onValueChange: (value: string) => void;
}) {
  return (
    <GeneratorTile label={label} tooltip={tooltip}>
      <ToggleGroup
        type="single"
        value={value}
        onValueChange={(next) => {
          if (next) onValueChange(next);
        }}
        className={cn(
          "grid h-8 w-full gap-1 rounded-lg border bg-muted/40 p-1 shadow-2xs",
          options.length === 2 ? "grid-cols-2" : "grid-cols-3",
        )}
        aria-label={label}
      >
        {options.map((option) => {
          const isSelected = value === option.value;
          return (
            <ToggleGroupItem
              key={option.value}
              value={option.value}
              disabled={disabled || option.disabled}
              aria-label={`${label}: ${option.label}`}
              className={cn(
                "h-6 min-w-0 truncate rounded-md px-1.5 font-mono text-[0.6875rem] font-medium transition-all",
                isSelected
                  ? "bg-background text-foreground font-semibold shadow-xs hover:bg-background hover:text-foreground"
                  : "text-muted-foreground hover:bg-background/50 hover:text-foreground",
              )}
              data-iperf-generator-option
            >
              {option.shortLabel ?? option.label}
            </ToggleGroupItem>
          );
        })}
      </ToggleGroup>
    </GeneratorTile>
  );
}
