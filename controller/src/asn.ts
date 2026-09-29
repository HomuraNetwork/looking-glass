import { isIPAddress, parseIPv6Bytes } from "./ip-guard";
import type { TcpRuntime } from "./runtime";

/**
 * Team Cymru ASN lookup for mtr hop addresses.
 *
 * The agent's mtr may or may not report an AS number (`mtr -z` needs DNS and
 * adds latency, and some builds omit it), so the controller fills in any hop
 * that lacks one. It uses Cymru's whois bulk protocol over one TCP connection:
 * many addresses per session, so an mtr run costs a single query instead of one
 * lookup per hop. The exchange is deliberately one-shot (see TcpRuntime).
 *
 * Privacy note: this sends the mtr target's hop addresses to Team Cymru. That
 * is the requested behavior (the user asked for ASN enrichment); the addresses
 * are public internet addresses the trace already traversed.
 */

export interface AsnRecord {
  /** "AS15169" (already prefixed for display). */
  asn: string;
  /** Registered owner, e.g. "GOOGLE - Google LLC, US". */
  name: string;
  /** Announced prefix, e.g. "8.8.8.0/24". */
  prefix: string;
  country: string;
  registry: string;
}

export const CYMRU_HOST = "whois.cymru.com";
export const CYMRU_PORT = 43;
/** Bulk queries are capped so one trace cannot build an unbounded request. */
const CYMRU_MAX_ADDRESSES = 128;
/**
 * Completion waits for this lookup before announcing the job is done, so it is
 * kept short: Cymru normally answers a bulk query well under a second, the
 * result is cached, and on timeout the ASN column is simply left blank.
 */
const DEFAULT_QUERY_TIMEOUT_MS = 3000;
const DEFAULT_QUERY_LIMIT_BYTES = 256 * 1024;
/** ASN assignments change rarely; cache per isolate to spare repeated queries. */
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
/** Negative results ("NA": private/unannounced space) are cached briefly too, so
 * an mtr run does not re-query the same unresolvable hop every cycle. */
const CACHE_NEGATIVE_TTL_MS = 15 * 60 * 1000;
const CACHE_MAX_ENTRIES = 4096;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const cache = new Map<string, { record: AsnRecord | null; expiresAt: number }>();

/** Build the Cymru bulk whois request. `verbose` adds prefix/registry/name. */
export function buildCymruQuery(addresses: string[]): Uint8Array {
  return encoder.encode(`begin\nverbose\n${addresses.join("\n")}\nend\n`);
}

/**
 * Parse Cymru's verbose bulk response into a map keyed by canonical IP.
 *
 * Columns: `AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name`.
 * Unresolvable addresses come back as `NA` and are omitted. The response is
 * sorted by origin AS, so callers must match on the echoed IP, never position.
 */
export function parseCymruResponse(text: string): Map<string, AsnRecord> {
  const out = new Map<string, AsnRecord>();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("Bulk mode") || line.startsWith("Error:")) continue;
    const parts = line.split("|").map((part) => part.trim());
    if (parts.length < 7) continue;
    const [asn, ip, prefix, country, registry, , name] = parts;
    if (!/^\d+$/.test(asn) || !ip || ip === "NA") continue;
    out.set(canonicalIPKey(ip), { asn: `AS${asn}`, name, prefix, country, registry });
  }
  return out;
}

/**
 * Resolve the ASN for a set of hop addresses. Non-IP hosts ("???", hostnames)
 * are skipped. Cached addresses are dropped from the query (a cached "no ASN"
 * marks the address as already-answered), and failures resolve to an empty map
 * so enrichment never blocks or breaks job completion.
 */
export async function lookupAsns(tcp: TcpRuntime | undefined, addresses: string[]): Promise<Map<string, AsnRecord>> {
  const unique = new Map<string, string>(); // canonical key -> original address
  for (const address of addresses) {
    if (!isIPAddress(address)) continue;
    const key = canonicalIPKey(address);
    if (!unique.has(key)) unique.set(key, address);
  }

  const resolved = new Map<string, AsnRecord>();
  const now = Date.now();
  const pending: string[] = [];
  for (const [key, original] of unique) {
    const cached = cache.get(key);
    if (cached && cached.expiresAt > now) {
      if (cached.record) resolved.set(key, cached.record);
      continue;
    }
    pending.push(original);
  }
  if (pending.length === 0 || !tcp) return resolved;

  const requested = pending.slice(0, CYMRU_MAX_ADDRESSES);
  try {
    const response = await tcp.query(CYMRU_HOST, CYMRU_PORT, buildCymruQuery(requested), {
      timeoutMs: DEFAULT_QUERY_TIMEOUT_MS,
      limit: DEFAULT_QUERY_LIMIT_BYTES,
    });
    const records = parseCymruResponse(decoder.decode(response));
    for (const [key, record] of records) {
      cache.set(key, { record, expiresAt: now + CACHE_TTL_MS });
      resolved.set(key, record);
    }
    // Addresses Cymru answered with "NA" (private/unannounced) are cached
    // negatively: querying again this run would return the same answer.
    for (const original of requested) {
      const key = canonicalIPKey(original);
      if (!records.has(key)) cache.set(key, { record: null, expiresAt: now + CACHE_NEGATIVE_TTL_MS });
    }
    pruneCache(now);
  } catch {
    // Best-effort: a failed lookup leaves the ASN column blank, it never fails
    // the job. Do not negative-cache a transport failure.
  }
  return resolved;
}

/** A stable match key: lowercase for IPv4, byte-canonical for IPv6. */
export function canonicalIPKey(value: string): string {
  const trimmed = value.trim();
  const bytes = parseIPv6Bytes(trimmed);
  if (!bytes) return trimmed.toLowerCase();
  const hextets: string[] = [];
  for (let i = 0; i < 8; i++) {
    hextets.push(((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16));
  }
  // Compress the longest run of zero hextets, per RFC 5952.
  let bestStart = -1;
  let bestLength = 0;
  let start = -1;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && hextets[i] === "0") {
      if (start < 0) start = i;
    } else if (start >= 0) {
      const length = i - start;
      if (length > bestLength) {
        bestStart = start;
        bestLength = length;
      }
      start = -1;
    }
  }
  if (bestLength < 2) return hextets.join(":");
  const head = hextets.slice(0, bestStart).join(":");
  const tail = hextets.slice(bestStart + bestLength).join(":");
  return `${head}::${tail}`;
}

function pruneCache(now: number): void {
  if (cache.size <= CACHE_MAX_ENTRIES) return;
  for (const [key, entry] of cache) {
    if (entry.expiresAt <= now) cache.delete(key);
    if (cache.size <= CACHE_MAX_ENTRIES) break;
  }
  // Still oversized: drop oldest insertions.
  while (cache.size > CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

/** Test hook: reset the module-level cache between cases. */
export function clearAsnCache(): void {
  cache.clear();
}
