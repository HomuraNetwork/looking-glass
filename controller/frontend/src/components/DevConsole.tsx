import { ChevronUp, Trash2 } from "lucide-react";
import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { clearDevLog, useDevLog, type DevConsoleLine } from "@/lib/dev-log";

export type { DevConsoleLine };

interface Props {
  enabled: boolean;
  lines?: DevConsoleLine[];
  onClear?: () => void;
}

export function DevConsole({ enabled, lines: propLines, onClear: propOnClear }: Props) {
  const storeLines = useDevLog();
  const lines = propLines ?? storeLines;
  const onClear = propOnClear ?? clearDevLog;
  const [open, setOpen] = useState(false);
  const panelId = useId();
  if (!enabled) return null;
  return (
    <div className="z-40 pointer-events-none sm:fixed sm:inset-x-0 sm:bottom-0">
      <div className="mx-auto max-w-7xl px-3">
        <div className="ml-auto w-full max-w-4xl pointer-events-auto">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={open}
            aria-controls={panelId}
            className="ml-auto flex h-8 items-center gap-2 rounded-b-none rounded-t-md border border-b-0 bg-background px-3 font-mono text-xs text-muted-foreground shadow-lg"
          >
            <ChevronUp className={open ? "rotate-180 transition-transform" : "transition-transform"} data-icon="inline-start" />
            dev
            <span className="rounded border px-1 text-xs">{lines.length}</span>
          </Button>
          {open && (
            <div id={panelId} className="flex max-h-[min(16rem,calc(100dvh-4rem))] flex-col overflow-hidden rounded-t-md border bg-background shadow-2xl sm:rounded-tl-md">
              <div className="flex items-center justify-between border-b bg-muted/40 px-3 py-2">
                <div className="font-mono text-xs font-bold text-foreground">Dev Console</div>
                <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={onClear}>
                  <Trash2 data-icon="inline-start" />
                  Clear
                </Button>
              </div>
              <pre className="min-h-0 flex-1 overflow-auto p-3 font-mono text-xs leading-[1.55] text-muted-foreground">
                {lines.length
                  ? lines.map((entry) => `[${entry.at}] ${entry.source}> ${entry.line}`).join("\n")
                  : "debug stream idle"}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
