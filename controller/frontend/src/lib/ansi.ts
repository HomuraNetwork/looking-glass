import type { CSSProperties } from "react";

export interface AnsiSpan {
  text: string;
  className?: string;
  style?: CSSProperties;
}

// CSI sequences: ESC [ <parameter bytes 0x30-0x3F> <intermediate 0x20-0x2F> <final 0x40-0x7E>.
// The parameter class must include "?" (and friends) so DEC private
// sequences like \x1b[?25l (hide cursor, emitted by nexttrace --map) are
// consumed rather than leaking "[?25l" into the terminal.
const CSI_SEQUENCE = /\x1b\[[0-?]*[ -/]*[@-~]/g;
const ANSI_REGEX = /\x1b\[([0-9;?]*?)[ -/]*([@-~])/g;

export function stripAnsi(text: string): string {
  return text
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    .replace(CSI_SEQUENCE, "");
}

export function hasAnsi(text: string): boolean {
  CSI_SEQUENCE.lastIndex = 0;
  return CSI_SEQUENCE.test(text);
}

const STANDARD_COLORS: Record<number, string> = {
  30: "#1e293b", // black
  31: "#f87171", // red
  32: "#4ade80", // green
  33: "#facc15", // yellow
  34: "#60a5fa", // blue
  35: "#c084fc", // magenta
  36: "#38bdf8", // cyan
  37: "#f1f5f9", // white
  90: "#94a3b8", // bright black / gray
  91: "#fca5a5", // bright red
  92: "#86efac", // bright green
  93: "#fde047", // bright yellow
  94: "#93c5fd", // bright blue
  95: "#d8b4fe", // bright magenta
  96: "#7dd3fc", // bright cyan
  97: "#ffffff", // bright white
};

const STANDARD_BG_COLORS: Record<number, string> = {
  40: "#0f172a",
  41: "#7f1d1d",
  42: "#14532d",
  43: "#713f12",
  44: "#1e3a8a",
  45: "#581c87",
  46: "#164e63",
  47: "#334155",
  100: "#1e293b",
  101: "#991b1b",
  102: "#166534",
  103: "#854d0e",
  104: "#1d4ed8",
  105: "#6b21a8",
  106: "#155e75",
  107: "#475569",
};

function get256Color(code: number): string {
  if (code < 8) return STANDARD_COLORS[30 + code] || "#f1f5f9";
  if (code < 16) return STANDARD_COLORS[90 + (code - 8)] || "#ffffff";
  if (code >= 232) {
    const gray = Math.round(((code - 232) / 23) * 255);
    return `rgb(${gray}, ${gray}, ${gray})`;
  }
  const index = code - 16;
  const r = Math.floor(index / 36);
  const g = Math.floor((index % 36) / 6);
  const b = index % 6;
  const toVal = (v: number) => (v === 0 ? 0 : 55 + v * 40);
  return `rgb(${toVal(r)}, ${toVal(g)}, ${toVal(b)})`;
}

interface AnsiState {
  bold: boolean;
  dim: boolean;
  italic: boolean;
  underline: boolean;
  fgColor?: string;
  bgColor?: string;
}

function createEmptyState(): AnsiState {
  return {
    bold: false,
    dim: false,
    italic: false,
    underline: false,
  };
}

export function parseAnsi(text: string): AnsiSpan[] {
  if (!hasAnsi(text)) {
    return [{ text }];
  }

  const spans: AnsiSpan[] = [];
  let state = createEmptyState();
  let lastIndex = 0;

  ANSI_REGEX.lastIndex = 0;
  let match: RegExpExecArray | null;

  const emitChunk = (chunkText: string) => {
    if (!chunkText) return;

    const classNames: string[] = [];
    const style: CSSProperties = {};

    if (state.bold) classNames.push("font-bold");
    if (state.dim) classNames.push("opacity-70");
    if (state.italic) classNames.push("italic");
    if (state.underline) classNames.push("underline");

    if (state.fgColor) {
      style.color = state.fgColor;
    }
    if (state.bgColor) {
      style.backgroundColor = state.bgColor;
    }

    spans.push({
      text: chunkText,
      className: classNames.length > 0 ? classNames.join(" ") : undefined,
      style: Object.keys(style).length > 0 ? style : undefined,
    });
  };

  while ((match = ANSI_REGEX.exec(text)) !== null) {
    const rawChunk = text.slice(lastIndex, match.index);
    emitChunk(rawChunk);
    lastIndex = ANSI_REGEX.lastIndex;

    const command = match[2];
    if (command === "m") {
      const codeStr = match[1];
      const codes = codeStr ? codeStr.split(";").map((s) => (s ? parseInt(s, 10) : 0)) : [0];

      for (let i = 0; i < codes.length; i++) {
        const code = codes[i];
        if (code === 0) {
          state = createEmptyState();
        } else if (code === 1) {
          state.bold = true;
        } else if (code === 2) {
          state.dim = true;
        } else if (code === 3) {
          state.italic = true;
        } else if (code === 4) {
          state.underline = true;
        } else if (code === 22) {
          state.bold = false;
          state.dim = false;
        } else if (code === 23) {
          state.italic = false;
        } else if (code === 24) {
          state.underline = false;
        } else if (code >= 30 && code <= 37) {
          state.fgColor = STANDARD_COLORS[code];
        } else if (code === 39) {
          state.fgColor = undefined;
        } else if (code >= 40 && code <= 47) {
          state.bgColor = STANDARD_BG_COLORS[code];
        } else if (code === 49) {
          state.bgColor = undefined;
        } else if (code >= 90 && code <= 97) {
          state.fgColor = STANDARD_COLORS[code];
        } else if (code >= 100 && code <= 107) {
          state.bgColor = STANDARD_BG_COLORS[code];
        } else if (code === 38 && i + 2 < codes.length && codes[i + 1] === 5) {
          state.fgColor = get256Color(codes[i + 2]);
          i += 2;
        } else if (code === 38 && i + 4 < codes.length && codes[i + 1] === 2) {
          state.fgColor = `rgb(${codes[i + 2]}, ${codes[i + 3]}, ${codes[i + 4]})`;
          i += 4;
        } else if (code === 48 && i + 2 < codes.length && codes[i + 1] === 5) {
          state.bgColor = get256Color(codes[i + 2]);
          i += 2;
        } else if (code === 48 && i + 4 < codes.length && codes[i + 1] === 2) {
          state.bgColor = `rgb(${codes[i + 2]}, ${codes[i + 3]}, ${codes[i + 4]})`;
          i += 4;
        }
      }
    }
  }

  emitChunk(text.slice(lastIndex));
  return spans;
}
