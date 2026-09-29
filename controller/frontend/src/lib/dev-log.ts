import { useSyncExternalStore } from "react";

export interface DevConsoleLine {
  id: string;
  source: "lg" | "iperf";
  line: string;
  at: string;
}

type Listener = () => void;
const listeners = new Set<Listener>();
let lines: DevConsoleLine[] = [];
let debugSeq = 0;

function emitChange() {
  listeners.forEach((listener) => listener());
}

export function appendDevLog(source: DevConsoleLine["source"], line: string) {
  if (!line) return;
  const at = new Date().toISOString().slice(11, 19);
  lines = [...lines.slice(-399), { id: `dbg-${++debugSeq}`, source, line, at }];
  emitChange();
}

export function clearDevLog() {
  lines = [];
  emitChange();
}

export function useDevLog(): DevConsoleLine[] {
  return useSyncExternalStore(
    (notify) => {
      listeners.add(notify);
      return () => {
        listeners.delete(notify);
      };
    },
    () => lines,
    () => lines,
  );
}
