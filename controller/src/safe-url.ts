export function isSafePublicLink(value: string): boolean {
  const normalized = value.trim();
  if (!normalized) return true;
  if (normalized.startsWith("/")) return !normalized.startsWith("//") && !/[\u0000-\u001f\\]/.test(normalized);
  try {
    const url = new URL(normalized);
    return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.hostname) && !url.username && !url.password;
  } catch {
    return false;
  }
}
