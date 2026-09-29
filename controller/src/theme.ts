// Resolves a theme setting into the public CSS variables for light & dark, then emits a
// <style> the worker injects into the served HTML so the site is themed on first paint.
//
// A theme value (PUBLIC_THEME) is one of:
//   - a preset id, e.g. "homura"   → a full coordinated palette (see PRESET_PALETTES)
//   - a JSON palette string         → a preset base + explicit per-mode overrides:
//       {"preset":"homura","light":{"primary":"#..","accent":"#..","background":"#.."},"dark":{...}}
//   - a custom hex, e.g. "#4f46e5"  → homura base with the primary swapped (legacy)
//
// The operator configures three roles per mode (primary, accent, background). Surfaces
// (card, popover, secondary, muted, border, input) and status colours (success,
// warning, info, destructive) are conventional neutrals/semantics, not brand-derived —
// so only the page background and primary/accent change with the theme.

export interface ThemeVars {
  light: Record<string, string>;
  dark: Record<string, string>;
}

type Role = "primary" | "accent" | "background";
type ModeHex = Record<Role, string>;
interface Palette { light: ModeHex; dark: ModeHex }

export const DEFAULT_THEME = "homura";

// Conventional website themes: only primary/accent (and the page background) vary
// by preset; surfaces and status colours are fixed neutrals/semantics in
// modeVars(). "homura" is the product's own theme, restored to its original
// indigo palette. Dark backgrounds are kept deliberately dark (the daisyUI dark
// themes read too bright for this UI).
export const PRESET_PALETTES: Record<string, Palette> = {
  homura: {
    light: { primary: "#4c599a", accent: "#b0b9e8", background: "#f6f5ff" },
    dark: { primary: "#b0b9e8", accent: "#818bbb", background: "#13121d" },
  },
  slate: {
    light: { primary: "#4a5568", accent: "#cbd2dd", background: "#f7f8fa" },
    dark: { primary: "#aab4c5", accent: "#5b6577", background: "#11141a" },
  },
  ocean: {
    light: { primary: "#2563b3", accent: "#aacdf0", background: "#f0f6fc" },
    dark: { primary: "#7db8ec", accent: "#2c557f", background: "#0b1320" },
  },
  emerald: {
    light: { primary: "#2f8f5b", accent: "#b6e4cb", background: "#f1faf5" },
    dark: { primary: "#6fd99e", accent: "#2f6b4c", background: "#0d1712" },
  },
  violet: {
    light: { primary: "#7c4dd1", accent: "#d2bdf2", background: "#f8f4ff" },
    dark: { primary: "#c4a6f0", accent: "#5a3f8a", background: "#150f22" },
  },
  // Bloom — muted rose (lower saturation than a stock rose-500).
  rose: {
    light: { primary: "#b0526d", accent: "#e6c2cd", background: "#fbf6f7" },
    dark: { primary: "#d792a9", accent: "#8a5470", background: "#171016" },
  },
  amber: {
    light: { primary: "#a9761a", accent: "#ecd9a8", background: "#fbf8f2" },
    dark: { primary: "#dcb96a", accent: "#8a6b33", background: "#14110b" },
  },
};

const ROLES: Role[] = ["primary", "accent", "background"];

interface Hsl { h: number; s: number; l: number }

/**
 * Conventional, neutral surface tokens — deliberately NOT derived from the
 * brand hue, so cards, borders and muted fills read like a normal website
 * instead of taking on the operator's colour. Chosen to match the familiar
 * slate/gray UI palette; the page background itself still comes from the
 * operator's `background` role.
 */
function neutralSurfaces(dark: boolean): Record<string, string> {
  return dark
    ? {
        "--card": "222 16% 11%",
        "--card-foreground": "210 20% 96%",
        "--popover": "222 16% 13%",
        "--popover-foreground": "210 20% 96%",
        "--secondary": "222 15% 17%",
        "--secondary-foreground": "210 20% 96%",
        "--muted": "222 15% 16%",
        "--muted-foreground": "220 10% 66%",
        "--border": "222 14% 20%",
        "--input": "222 14% 20%",
      }
    : {
        "--card": "0 0% 100%",
        "--card-foreground": "222 30% 13%",
        "--popover": "0 0% 100%",
        "--popover-foreground": "222 30% 13%",
        "--secondary": "220 14% 96%",
        "--secondary-foreground": "222 30% 13%",
        "--muted": "220 14% 96%",
        "--muted-foreground": "220 9% 46%",
        "--border": "220 13% 91%",
        "--input": "220 13% 91%",
      };
}

/**
 * Conventional semantic status colours (fixed per mode, not brand-derived) so
 * success / warning / info / destructive read the same in every theme, the way
 * a normal product UI expects. Light mode uses saturated 500/600 shades with
 * white text; dark mode uses lighter 400 shades.
 */
function semanticColors(dark: boolean): Record<string, string> {
  return dark
    ? {
        "--success": "142 69% 55%",
        "--success-foreground": "144 70% 10%",
        "--warning": "38 92% 58%",
        "--warning-foreground": "30 70% 10%",
        "--info": "217 91% 68%",
        "--info-foreground": "220 70% 12%",
        "--destructive": "0 84% 66%",
        "--destructive-foreground": "0 70% 12%",
      }
    : {
        "--success": "142 71% 38%",
        "--success-foreground": "0 0% 100%",
        "--warning": "32 95% 42%",
        "--warning-foreground": "0 0% 100%",
        "--info": "217 91% 52%",
        "--info-foreground": "0 0% 100%",
        "--destructive": "0 72% 48%",
        "--destructive-foreground": "0 0% 100%",
      };
}

/**
 * Derive the full token set for one mode. The brand only drives primary/accent
 * (and the terminal hue is a fixed dark neutral); every surface and status
 * colour is a conventional neutral/semantic value. Exported so the frontend
 * preview can render the exact same variables (see the mirrored copy in
 * frontend/src/lib/theme-presets.ts — keep them in sync).
 */
export function modeVars(hex: ModeHex): Record<string, string> {
  const vars: Record<string, string> = {};
  const bg = parseHsl(hex.background);
  const dark = bg ? bg.l < 50 : false;

  if (bg) vars["--background"] = str(bg);
  vars["--foreground"] = dark ? "210 20% 96%" : "222 30% 13%";
  Object.assign(vars, neutralSurfaces(dark), semanticColors(dark));
  // The terminal is always a dark, neutral surface in both modes.
  vars["--term-bg"] = dark ? "222 30% 7%" : "222 30% 8%";

  const primary = parseHsl(hex.primary);
  if (primary) {
    vars["--primary"] = str(primary);
    vars["--primary-foreground"] = contrast(primary.l);
    vars["--ring"] = str(primary);
  }
  const accent = parseHsl(hex.accent);
  if (accent) {
    vars["--accent"] = str(accent);
    vars["--accent-foreground"] = contrast(accent.l);
  }
  return vars;
}

function merge(base: ModeHex, over: Partial<ModeHex> | undefined): ModeHex {
  const out = { ...base };
  if (over) for (const r of ROLES) {
    if (typeof over[r] === "string" && /^#[0-9a-f]{6}$/i.test(over[r]!)) out[r] = over[r]!;
  }
  return out;
}

/**
 * Legacy preset ids that were renamed. "indigo" was the pre-rename id of the
 * Homura theme, so saved settings (and stored JSON palettes) that still use it
 * resolve to the same palette instead of falling back.
 */
const PRESET_ALIASES: Record<string, string> = { indigo: "homura" };

export function resolvePresetId(id: string): string {
  const key = (id || "").trim().toLowerCase();
  return PRESET_ALIASES[key] ?? key;
}

export function resolveThemeVars(theme: string | undefined): ThemeVars {
  const value = (theme || DEFAULT_THEME).trim();
  if (value.startsWith("{")) {
    try {
      const json = JSON.parse(value) as { preset?: string; light?: Partial<ModeHex>; dark?: Partial<ModeHex> };
      const preset = resolvePresetId(json.preset || DEFAULT_THEME);
      const base = PRESET_PALETTES[preset] ?? PRESET_PALETTES[DEFAULT_THEME];
      return { light: modeVars(merge(base.light, json.light)), dark: modeVars(merge(base.dark, json.dark)) };
    } catch {
      return paletteVars(PRESET_PALETTES[DEFAULT_THEME]);
    }
  }
  if (value.startsWith("#") && /^#[0-9a-f]{6}$/i.test(value)) {
    const base = PRESET_PALETTES[DEFAULT_THEME];
    return { light: modeVars({ ...base.light, primary: value }), dark: modeVars({ ...base.dark, primary: value }) };
  }
  const preset = resolvePresetId(value);
  return paletteVars(PRESET_PALETTES[preset] ?? PRESET_PALETTES[DEFAULT_THEME]);
}

function paletteVars(p: Palette): ThemeVars {
  return { light: modeVars(p.light), dark: modeVars(p.dark) };
}

export function themeStyleTag(theme: string | undefined): string {
  const vars = resolveThemeVars(theme);
  const block = (selector: string, map: Record<string, string>) =>
    `${selector}{${Object.entries(map).map(([k, v]) => `${k}:${v}`).join(";")}}`;
  return `<style id="lg-theme">${block(":root", vars.light)}${block('[data-theme="dark"]', vars.dark)}</style>`;
}

function parseHsl(hex: string): Hsl | null {
  const m = /^#?([0-9a-f]{6})$/i.exec((hex || "").trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  const r = ((n >> 16) & 255) / 255;
  const g = ((n >> 8) & 255) / 255;
  const b = (n & 255) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  let h = 0;
  let s = 0;
  if (d !== 0) {
    s = d / (1 - Math.abs(2 * l - 1));
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h = (Math.round(h * 60) + 360) % 360;
  }
  return { h, s: Math.round(s * 100), l: Math.round(l * 100) };
}

function str(c: Hsl): string {
  return `${c.h} ${c.s}% ${c.l}%`;
}

// Black-ish or white foreground depending on lightness.
function contrast(l: number): string {
  return l > 60 ? "248 22% 15%" : "0 0% 100%";
}

