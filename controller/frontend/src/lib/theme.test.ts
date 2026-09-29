// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi } from "vitest";
import { getStoredTheme, applyTheme, toggleTheme, initTheme, resolveTheme } from "./theme";

describe("theme", () => {
  beforeEach(() => {
    localStorage.clear();
    delete document.documentElement.dataset.theme;
    delete document.documentElement.dataset.themePreference;
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: false,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      })),
    });
  });

  it("resolves and applies stored, explicit, and system theme preferences", () => {
    expect(getStoredTheme()).toBe("system");
    applyTheme("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.dataset.themePreference).toBe("dark");
    document.documentElement.dataset.theme = "dark";
    applyTheme("light");
    expect(document.documentElement.dataset.theme).toBe("");
    expect(document.documentElement.dataset.themePreference).toBe("light");
    window.matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: true,
      media: query,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }));
    expect(resolveTheme("system")).toBe("dark");
    expect(applyTheme("system")).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(document.documentElement.dataset.themePreference).toBe("system");
  });

  it("persists toggles and applies the stored choice during startup", () => {
    const next = toggleTheme();
    expect(next).toBe("dark");
    expect(getStoredTheme()).toBe("dark");
    localStorage.setItem("lg-theme", "dark");
    expect(toggleTheme()).toBe("light");
    expect(getStoredTheme()).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("");
    localStorage.setItem("lg-theme", "light");
    expect(toggleTheme()).toBe("dark");
    expect(getStoredTheme()).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    localStorage.setItem("lg-theme", "dark");
    const theme = initTheme();
    expect(theme).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
  });
});
