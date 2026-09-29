// Theme generation lives in controller/src/theme.ts; keep the palettes and variables in sync.

export type PaletteRole = "primary" | "accent" | "background";
export type ThemeMode = "light" | "dark";
export type ModePalette = Record<PaletteRole, string>; // hex
export interface Palette {
  light: ModePalette;
  dark: ModePalette;
}

export interface ThemePreset {
  id: string;
  label: string;
  swatch: string; // light primary, for the swatch dot
}

// Preset ids are stored in PUBLIC_THEME; labels can change independently.
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

const PRESET_LABELS: Record<string, string> = {
  homura: "Homura",
  slate: "Standard",
  ocean: "Harbor",
  emerald: "Moss",
  violet: "Orbit",
  rose: "Bloom",
  amber: "Brass",
};

const PRESET_ORDER = ["homura", "slate", "ocean", "emerald", "violet", "rose", "amber"];

export const THEME_PRESETS: ThemePreset[] = PRESET_ORDER.map((id) => ({
  id,
  label: PRESET_LABELS[id],
  swatch: PRESET_PALETTES[id].light.primary,
}));

export const PALETTE_ROLES: { role: PaletteRole; label: string }[] = [
  { role: "primary", label: "Primary" },
  { role: "accent", label: "Accent" },
  { role: "background", label: "Background" },
];

const ROLES: PaletteRole[] = ["primary", "accent", "background"];

interface Hsl { h: number; s: number; l: number }

/** Conventional neutral surfaces — intentionally not derived from the brand. */
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

/** Conventional semantic status colours (fixed, not brand-derived). */
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

export function modeVars(hex: ModePalette): Record<string, string> {
  const vars: Record<string, string> = {};
  const bg = parseHsl(hex.background);
  const dark = bg ? bg.l < 50 : false;

  if (bg) vars["--background"] = hsl(bg);
  vars["--foreground"] = dark ? "210 20% 96%" : "222 30% 13%";
  Object.assign(vars, neutralSurfaces(dark), semanticColors(dark));
  vars["--term-bg"] = dark ? "222 30% 7%" : "222 30% 8%";

  const primary = parseHsl(hex.primary);
  if (primary) {
    vars["--primary"] = hsl(primary);
    vars["--primary-foreground"] = contrast(primary.l);
    vars["--ring"] = hsl(primary);
  }
  const accent = parseHsl(hex.accent);
  if (accent) {
    vars["--accent"] = hsl(accent);
    vars["--accent-foreground"] = contrast(accent.l);
  }
  return vars;
}

const PRESET_ALIASES: Record<string, string> = { indigo: "homura" };

export function resolvePresetId(id: string): string {
  const key = (id || "").trim().toLowerCase();
  return PRESET_ALIASES[key] ?? key;
}

/** Resolve a PUBLIC_THEME value into a full hex palette for the editor. */
export function resolvePalette(theme: string): Palette {
  const value = (theme || "homura").trim();
  if (value.startsWith("{")) {
    try {
      const json = JSON.parse(value) as { preset?: string; light?: Partial<ModePalette>; dark?: Partial<ModePalette> };
      const base = PRESET_PALETTES[resolvePresetId(json.preset || "homura")] ?? PRESET_PALETTES.homura;
      return {
        light: { ...base.light, ...sanitize(json.light) },
        dark: { ...base.dark, ...sanitize(json.dark) },
      };
    } catch {
      return clone(PRESET_PALETTES.homura);
    }
  }
  if (value.startsWith("#") && /^#[0-9a-f]{6}$/i.test(value)) {
    const base = clone(PRESET_PALETTES.homura);
    base.light.primary = value;
    base.dark.primary = value;
    return base;
  }
  return clone(PRESET_PALETTES[resolvePresetId(value)] ?? PRESET_PALETTES.homura);
}

/** Build the JSON palette string stored in PUBLIC_THEME. */
export function paletteToTheme(palette: Palette, presetId = "homura"): string {
  return JSON.stringify({ preset: presetId, light: palette.light, dark: palette.dark });
}

export function presetIdOf(theme: string): string | null {
  const v = (theme || "").trim();
  if (v.startsWith("{")) {
    try {
      const preset = (JSON.parse(v) as { preset?: string }).preset;
      return preset ? resolvePresetId(preset) : null;
    } catch { return null; }
  }
  const key = resolvePresetId(v);
  return PRESET_PALETTES[key] ? key : null;
}

function sanitize(p: Partial<ModePalette> | undefined): Partial<ModePalette> {
  if (!p) return {};
  const out: Partial<ModePalette> = {};
  for (const role of ROLES) {
    if (typeof p[role] === "string" && /^#[0-9a-f]{6}$/i.test(p[role]!)) out[role] = p[role];
  }
  return out;
}

function parseHsl(value: string): Hsl | null {
  const m = /^#?([0-9a-f]{6})$/i.exec((value || "").trim());
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

function hsl(c: Hsl): string {
  return `${c.h} ${c.s}% ${c.l}%`;
}

function contrast(l: number): string {
  return l > 60 ? "248 22% 15%" : "0 0% 100%";
}

function clone(p: Palette): Palette {
  return { light: { ...p.light }, dark: { ...p.dark } };
}
