import { describe, expect, it } from "vitest";
import { PRESET_PALETTES as workerPalettes, resolveThemeVars, themeStyleTag } from "../src/theme";
import {
  PRESET_PALETTES as frontendPalettes,
  modeVars as frontendModeVars,
  resolvePalette,
  resolvePresetId,
} from "../frontend/src/lib/theme-presets";

describe("theme presets", () => {
  it("keeps the worker and frontend palettes in sync", () => {
    expect(frontendPalettes).toEqual(workerPalettes);
  });

  it("resolves the legacy 'indigo' id to the Homura palette", () => {
    expect(resolveThemeVars("indigo")).toEqual(resolveThemeVars("homura"));
    expect(resolveThemeVars('{"preset":"indigo"}')).toEqual(resolveThemeVars('{"preset":"homura"}'));
    // The frontend editor maps the legacy id to the Homura preset too.
    expect(resolvePalette("indigo")).toEqual(resolvePalette("homura"));
    expect(resolvePresetId("indigo")).toBe("homura");
    expect(resolvePresetId("INDIGO")).toBe("homura");
  });

  it("derives the same tokens in the worker and the frontend preview", () => {
    const theme = '{"preset":"ocean","light":{"primary":"#ff0000"},"dark":{"background":"#000000"}}';
    const worker = resolveThemeVars(theme);
    const preview = resolvePalette(theme);
    expect(frontendModeVars(preview.light)).toEqual(worker.light);
    expect(frontendModeVars(preview.dark)).toEqual(worker.dark);
  });

  it("emits a light :root and dark-scoped style block", () => {
    const tag = themeStyleTag("homura");
    expect(tag.startsWith('<style id="lg-theme">')).toBe(true);
    expect(tag).toContain(":root{");
    expect(tag).toContain('[data-theme="dark"]{');
  });
});
