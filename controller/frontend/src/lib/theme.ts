export type Theme = "light" | "dark";
export type ThemePreference = Theme | "system";

const storageKey = "lg-theme";

export function getSystemTheme(): Theme {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function getStoredTheme(): ThemePreference {
  try {
    const stored = localStorage.getItem(storageKey);
    return stored === "dark" || stored === "light" ? stored : "system";
  } catch {
    return "system";
  }
}

export function resolveTheme(preference: ThemePreference): Theme {
  return preference === "system" ? getSystemTheme() : preference;
}

export function applyTheme(preference: ThemePreference): Theme {
  const theme = resolveTheme(preference);
  document.documentElement.dataset.theme = theme === "dark" ? "dark" : "";
  document.documentElement.dataset.themePreference = preference;
  return theme;
}

export function toggleTheme(): Theme {
  const currentTheme = resolveTheme(getStoredTheme());
  const next: Theme = currentTheme === "dark" ? "light" : "dark";
  try { localStorage.setItem(storageKey, next); } catch { /* ignore */ }
  applyTheme(next);
  return next;
}

export function initTheme(): ThemePreference {
  const preference = getStoredTheme();
  applyTheme(preference);
  return preference;
}

export function subscribeToSystemTheme(callback: () => void): () => void {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return () => {};
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", callback);
  return () => media.removeEventListener("change", callback);
}
