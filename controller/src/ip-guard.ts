import { getBooleanProjectSetting } from "./project-settings";
import type { SqlDatabase } from "./runtime";

type DNSFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

interface JobTargetInput {
  target: string;
  ipver?: string;
  remoteDNS?: boolean;
}

export interface JobTargetGuardResult {
  allowed: boolean;
  target: string;
  checkedIPs: string[];
  error?: string;
  status?: number;
}

interface CloudflareDNSAnswer {
  type: number;
  data: string;
}

interface CloudflareDNSResponse {
  Answer?: CloudflareDNSAnswer[];
}

export async function inspectJobTarget(
  input: JobTargetInput,
  db: SqlDatabase | undefined,
  fetcher: DNSFetch = fetch,
): Promise<JobTargetGuardResult> {
  const target = input.target.trim();
  if (!target) return denied("invalid_target", 400, target, []);
  const family = ipFamily(target);
  if (!family && !isDomainName(target)) return denied("invalid_target", 400, target, []);
  if (family && !ipFamilyMatches(family, input.ipver || "ipv4")) {
    return denied("ip_family_mismatch", 400, target, [target]);
  }

  if (!input.remoteDNS && !family) {
    return denied("frontend_dns_required", 400, target, []);
  }
  if (!(await privateIPGuardEnabled(db))) return { allowed: true, target, checkedIPs: [] };

  const checkedIPs = family ? [target] : await resolveWorkerDNS(target, input.ipver || "ipv4", fetcher);
  if (checkedIPs.length === 0) return denied("dns_no_records", 400, target, []);

  if (checkedIPs.some((ip) => isPrivateIPAddress(ip))) {
    return denied("blocked_private_ip", 403, target, checkedIPs);
  }

  return { allowed: true, target, checkedIPs };
}

function denied(error: string, status: number, target: string, checkedIPs: string[]): JobTargetGuardResult {
  return { allowed: false, error, status, target, checkedIPs };
}

function privateIPGuardEnabled(db: SqlDatabase | undefined): Promise<boolean> {
  return getBooleanProjectSetting(db, "LG_BLOCK_PRIVATE_IPS");
}

async function resolveWorkerDNS(target: string, ipver: string, fetcher: DNSFetch): Promise<string[]> {
  const type = ipver === "ipv6" ? "AAAA" : "A";
  try {
    const response = await fetcher(`https://cloudflare-dns.com/dns-query?${new URLSearchParams({ name: target, type }).toString()}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return [];
    const payload = (await response.json()) as CloudflareDNSResponse;
    const expectedType = type === "A" ? 1 : 28;
    return (payload.Answer || [])
      .filter((answer) => answer.type === expectedType)
      .map((answer) => answer.data)
      .filter((answer) => isIPAddress(answer))
      .sort();
  } catch {
    return [];
  }
}

export function isIPAddress(value: string): boolean {
  return ipFamily(value) !== null;
}

function ipFamily(value: string): "ipv4" | "ipv6" | null {
  if (parseIPv4(value) !== null) return "ipv4";
  if (parseIPv6Bytes(value) !== null) return "ipv6";
  return null;
}

function ipFamilyMatches(family: "ipv4" | "ipv6", ipver: string): boolean {
  return ipver === family;
}

function isDomainName(value: string): boolean {
  const normalized = value.trim().replace(/\.$/, "");
  if (!normalized || normalized.length > 253 || normalized.includes("..")) return false;
  return normalized.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}

// Canonical private/reserved IP blocklist — MUST stay in sync with
// agent/internal/guard/guard.go (there is no shared package between the
// worker and the agent, so both ends duplicate this list; update both
// whenever a range is added or removed):
//
// IPv4:
//   0.0.0.0/8            "this network"
//   10.0.0.0/8           private
//   100.64.0.0/10        CGNAT shared address space
//   127.0.0.0/8          loopback
//   169.254.0.0/16       link-local
//   172.16.0.0/12        private
//   192.0.0.0/24         IETF protocol assignments
//   192.168.0.0/16       private
//   198.18.0.0/15        benchmarking
//   224.0.0.0/4          multicast
//   240.0.0.0/4          reserved (includes 255.255.255.255 broadcast)
// IPv6:
//   ::/128               unspecified
//   ::1/128              loopback
//   fc00::/7             unique local
//   fe80::/10            link-local
//   ff00::/8             multicast
//   ::ffff:0:0/96        IPv4-mapped → re-checked against the IPv4 list
export function isPrivateIPAddress(value: string): boolean {
  // IPv4-mapped IPv6 in dotted form (::ffff:10.0.0.1): parseIPv6Bytes
  // rejects anything containing "." so the mapping is detected here and
  // the extracted IPv4 is run through the IPv4 blocklist.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value.trim());
  if (mapped) {
    return isPrivateIPv4Bytes(parseIPv4(mapped[1]));
  }

  const ipv4 = parseIPv4(value);
  if (ipv4) return isPrivateIPv4Bytes(ipv4);

  const ipv6 = parseIPv6Bytes(value);
  if (!ipv6) return false;
  // IPv4-mapped IPv6 in hex form (::ffff:c0a8:0001 etc.): bytes 0-9 are
  // zero and bytes 10-11 are 0xff/0xff; re-check the embedded IPv4.
  if (ipv6.slice(0, 10).every((byte) => byte === 0) && ipv6[10] === 0xff && ipv6[11] === 0xff) {
    return isPrivateIPv4Bytes(ipv6.slice(12));
  }
  // Deprecated IPv4-compatible form ::a.b.c.d (represented here in hex).
  // Keep the embedded IPv4 blocklist aligned with the agent guard.
  if (ipv6.slice(0, 12).every((byte) => byte === 0)) {
    return isPrivateIPv4Bytes(ipv6.slice(12));
  }
  const allZero = ipv6.every((byte) => byte === 0);
  const loopback = ipv6.slice(0, 15).every((byte) => byte === 0) && ipv6[15] === 1;
  const uniqueLocal = (ipv6[0] & 0xfe) === 0xfc;
  const linkLocal = ipv6[0] === 0xfe && (ipv6[1] & 0xc0) === 0x80;
  const multicast = ipv6[0] === 0xff;
  return allZero || loopback || uniqueLocal || linkLocal || multicast;
}

function isPrivateIPv4Bytes(bytes: number[] | null): boolean {
  if (!bytes) return false;
  const [a, b, c] = bytes;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a >= 224 && a <= 239) ||
    a >= 240
  );
}

export function parseIPv4(value: string): number[] | null {
  const parts = value.trim().split(".");
  if (parts.length !== 4) return null;
  const bytes = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) return Number.NaN;
    const byte = Number(part);
    return byte >= 0 && byte <= 255 ? byte : Number.NaN;
  });
  return bytes.every((byte) => Number.isInteger(byte)) ? bytes : null;
}

export function parseIPv6Bytes(value: string): number[] | null {
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.includes(".")) return null;
  const pieces = normalized.split("::");
  if (pieces.length > 2) return null;
  const head = parseHextets(pieces[0]);
  const tail = pieces.length === 2 ? parseHextets(pieces[1]) : [];
  if (!head || !tail) return null;
  const missing = 8 - head.length - tail.length;
  if ((pieces.length === 1 && missing !== 0) || missing < 0) return null;
  const hextets = [...head, ...Array(missing).fill(0), ...tail];
  if (hextets.length !== 8) return null;
  return hextets.flatMap((hextet) => [(hextet >> 8) & 0xff, hextet & 0xff]);
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
