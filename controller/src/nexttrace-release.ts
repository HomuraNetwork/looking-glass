export interface NexttraceReleaseAsset {
  tool: "nexttrace";
  arch: "amd64" | "arm64";
  version: string;
  name: string;
  sha256: string;
  size: number;
}

const repository = "nxtrace/NTrace-core";
const assetsByArch = [
  ["amd64", "nexttrace_linux_amd64"],
  ["arm64", "nexttrace_linux_arm64"],
] as const;

let cachedRelease: { expiresAt: number; value: Promise<NexttraceReleaseAsset[]> } | undefined;
const CACHE_MS = 5 * 60 * 1000;

export function fetchNexttraceRelease(fetchImpl: typeof fetch = fetch): Promise<NexttraceReleaseAsset[]> {
  if (fetchImpl !== fetch) return loadNexttraceRelease(fetchImpl);
  if (cachedRelease && cachedRelease.expiresAt > Date.now()) return cachedRelease.value;

  const value = loadNexttraceRelease(fetchImpl).catch((error: unknown) => {
    if (cachedRelease?.value === value) cachedRelease.expiresAt = Date.now() + 30_000;
    throw error;
  });
  cachedRelease = { expiresAt: Date.now() + CACHE_MS, value };
  return value;
}

async function loadNexttraceRelease(fetchImpl: typeof fetch): Promise<NexttraceReleaseAsset[]> {
  const response = await fetchImpl(`https://api.github.com/repos/${repository}/releases/latest`, {
    headers: {
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "HLG-Controller",
    },
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`GitHub NextTrace release API returned ${response.status}`);
  const release = await response.json() as { tag_name?: unknown; assets?: unknown };
  const version = release.tag_name;
  const assets = release.assets;
  if (typeof version !== "string" || !/^v\d+(?:\.\d+){1,3}$/.test(version) || !Array.isArray(assets)) {
    throw new Error("GitHub NextTrace latest release metadata is invalid");
  }

  return assetsByArch.map(([arch, name]) => {
    const asset = assets.find((candidate: { name?: unknown }) => candidate?.name === name) as { digest?: unknown; size?: unknown } | undefined;
    const match = typeof asset?.digest === "string" ? /^sha256:([a-f0-9]{64})$/i.exec(asset.digest) : null;
    if (!asset || !match || !Number.isSafeInteger(asset.size) || (asset.size as number) <= 0) {
      throw new Error(`GitHub NextTrace release is missing a valid SHA-256 digest for ${name}`);
    }
    return { tool: "nexttrace", arch, version, name, sha256: match[1].toLowerCase(), size: asset.size as number };
  });
}
