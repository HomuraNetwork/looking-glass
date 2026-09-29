// Validate persisted values at render time too; older settings may predate save-time checks.
export function safeNavHref(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("#")) return trimmed;
  if (trimmed.startsWith("/")) return trimmed.startsWith("//") ? null : trimmed;
  if (trimmed.startsWith("https://")) return trimmed;
  if (trimmed.startsWith("mailto:")) return trimmed;
  return null;
}
