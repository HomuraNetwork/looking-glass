type DNSRecordType = "A" | "AAAA";

interface CloudflareDNSAnswer {
  type: number;
  data: string;
}

interface CloudflareDNSResponse {
  Answer?: CloudflareDNSAnswer[];
}

type DNSFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface FrontendDNSResult {
  lines: string[];
  answers: string[];
  skipped: boolean;
  error?: string;
}

export function buildCloudflareDNSURL(name: string, type: DNSRecordType): string {
  const params = new URLSearchParams({ name, type });
  return `https://cloudflare-dns.com/dns-query?${params.toString()}`;
}

export async function resolveFrontendDNS(target: string, ipver: string, fetcher: DNSFetch = fetch): Promise<FrontendDNSResult> {
  const normalizedTarget = target.trim();
  if (!normalizedTarget || isIPAddress(normalizedTarget)) {
    return { lines: [], answers: normalizedTarget ? [normalizedTarget] : [], skipped: true };
  }
  if (!isDomainName(normalizedTarget)) {
    return { lines: ["invalid target: not a domain or IP"], answers: [], skipped: false, error: "invalid_target" };
  }
  const types: DNSRecordType[] = ipver === "ipv6" ? ["AAAA"] : ["A"];
  const lines: string[] = [`frontend dns: ${normalizedTarget}`];
  const resolvedAnswers: string[] = [];
  for (const type of types) {
    try {
      const response = await fetcher(buildCloudflareDNSURL(normalizedTarget, type), {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) {
        lines.push(`  ${type} lookup failed: http ${response.status}`);
        continue;
      }
      const payload = (await response.json()) as CloudflareDNSResponse;
      const expectedType = type === "A" ? 1 : 28;
      const answers = (payload.Answer || []).filter((answer) => answer.type === expectedType).map((answer) => answer.data).sort();
      if (answers.length === 0) {
        lines.push(`  no ${type} records found`);
        continue;
      }
      resolvedAnswers.push(...answers);
      for (const answer of answers) {
        lines.push(`  ${type} ${answer}`);
      }
    } catch (error) {
      lines.push(`  ${type} lookup failed: ${error instanceof Error ? error.message : "unknown error"}`);
    }
  }
  return {
    lines,
    answers: resolvedAnswers,
    skipped: false,
  };
}

export function isIPAddress(value: string): boolean {
  return parseIPv4(value) !== null || parseIPv6(value) !== null;
}

export function isDomainName(value: string): boolean {
  const normalized = value.trim().replace(/\.$/, "");
  if (!normalized || normalized.length > 253 || normalized.includes("..")) return false;
  return normalized.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

export function isValidTarget(value: string): boolean {
  const normalized = value.trim();
  if (!normalized) return false;
  return isIPAddress(normalized) || isDomainName(normalized);
}

function parseIPv4(value: string): number[] | null {
  const parts = value.trim().split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) return Number.NaN;
    const byte = Number(part);
    return byte >= 0 && byte <= 255 ? byte : Number.NaN;
  });
  return bytes.every((byte) => Number.isInteger(byte)) ? bytes : null;
}

function parseIPv6(value: string): string | null {
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.includes(".") || !normalized.includes(":")) return null;
  const pieces = normalized.split("::");
  if (pieces.length > 2) return null;
  const head = parseHextets(pieces[0]);
  const tail = pieces.length === 2 ? parseHextets(pieces[1]) : [];
  if (!head || !tail) return null;
  const missing = 8 - head.length - tail.length;
  if ((pieces.length === 1 && missing !== 0) || missing < 0) return null;
  return normalized;
}

function parseHextets(value: string): number[] | null {
  if (!value) return [];
  const parts = value.split(":");
  const hextets = parts.map((part) => {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return Number.NaN;
    return Number.parseInt(part, 16);
  });
  return hextets.every((hextet) => Number.isInteger(hextet)) ? hextets : null;
}
