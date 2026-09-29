export function normalizeJobCount(count: unknown): number {
  return Number(count) === 10 ? 10 : 5;
}
