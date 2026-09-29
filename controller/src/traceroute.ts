/**
 * Parse a `traceroute` hop line into structured rows, so the worker can emit a
 * typed frame (kind "traceroute") the client renders without guessing the tool
 * from its own UI state. Handles the three variants:
 *
 *   - system `traceroute -n -e`:  ` 5  192.0.2.30 <MPLS:L=..>  0.5 ms 0.9 ms`
 *   - system with reverse DNS:    ` 5  host (192.0.2.30) <MPLS:..>  0.5 ms`
 *   - the built-in probe:         ` 5  192.0.2.30 0.5 ms 0.9 ms [ECMP] [MPLS ..]`
 *
 * One hop can be answered by multiple addresses (ECMP); each responder keeps
 * every probe RTT. Hostnames are dropped. Returns null for non-hop lines.
 */

export interface TracerouteMpls {
  label: string;
  tc: string;
  ttl: string;
}

export interface TracerouteResponder {
  ip: string;
  times: number[];
  mpls: TracerouteMpls | null;
}

export interface TracerouteHop {
  hop: number;
  responders: TracerouteResponder[];
  unanswered: boolean;
  ecmp: boolean;
}

const HOP_RE = /^\s*(\d+)\s+(.*)$/;
const SCAN_RE =
  /(\S+)\s+\(([0-9a-fA-F:.]+)\)\s*(<[^>]+>)?|<([^>]+)>\s*|\[(MPLS[^\]]*)\]|\[(ECMP)\]|\*|([0-9.]+)\s*ms|([0-9a-fA-F:.]+)/g;

export function parseTracerouteHop(line: string): TracerouteHop | null {
  const hopMatch = HOP_RE.exec(line);
  if (!hopMatch) return null;
  const hop = Number(hopMatch[1]);
  const body = hopMatch[2];
  if (!/ms|\*/.test(body)) return null;

  const responders: TracerouteResponder[] = [];
  const index = new Map<string, number>();
  let current: TracerouteResponder | undefined;
  let unanswered = false;
  let pendingMpls: TracerouteMpls | null = null;

  const ensure = (ip: string): TracerouteResponder => {
    const at = index.get(ip);
    if (at !== undefined) return responders[at];
    const created: TracerouteResponder = { ip, times: [], mpls: pendingMpls };
    pendingMpls = null;
    index.set(ip, responders.length);
    responders.push(created);
    return created;
  };

  SCAN_RE.lastIndex = 0;
  for (let m = SCAN_RE.exec(body); m !== null; m = SCAN_RE.exec(body)) {
    const [full, , hostIp, hostMpls, bareMpls, mplsMarker, ecmpMarker, time, bareIp] = m;
    if (ecmpMarker !== undefined) continue;
    if (time !== undefined) {
      if (current) current.times.push(Number(time));
      continue;
    }
    if (hostIp !== undefined) {
      current = ensure(hostIp);
      const parsed = parseMplsTag(hostMpls ?? "");
      if (parsed) current.mpls = parsed;
      continue;
    }
    if (bareMpls !== undefined || mplsMarker !== undefined) {
      const parsed = parseMplsTag(bareMpls ?? mplsMarker ?? "");
      if (current) current.mpls = parsed;
      else pendingMpls = parsed;
      continue;
    }
    if (full === "*") {
      unanswered = true;
      continue;
    }
    if (bareIp !== undefined) {
      current = ensure(bareIp);
      continue;
    }
  }

  if (responders.length === 0 && !unanswered) return null;
  return { hop, responders, unanswered, ecmp: responders.length > 1 };
}

/**
 * A space-separated, hostname-free rendering of one hop (one line per responder,
 * extra responders indented), used as the human-readable `line` for copy/legacy
 * clients; the structured fields are what the client renders.
 */
export function compactTracerouteHop(hop: TracerouteHop): string {
  if (hop.responders.length === 0) return `${hop.hop}  *`;
  return hop.responders
    .map((r, i) => {
      const prefix = i === 0 ? `${hop.hop}  ` : "   ";
      const times = r.times.map((t) => `${t} ms`).join(" ");
      const marks = `${hop.ecmp ? " [ECMP]" : ""}${r.mpls ? ` [MPLS ${r.mpls.label}/TC${r.mpls.tc}/TTL${r.mpls.ttl}]` : ""}`;
      return `${prefix}${r.ip} ${times}${marks}`;
    })
    .join("\n");
}

/** Normalise any MPLS tag form into {label,tc,ttl}. */
export function parseMplsTag(raw: string): TracerouteMpls | null {
  const slash = /MPLS\s+(\d+)\/TC(\d+)\/TTL(\d+)/i.exec(raw);
  if (slash) return { label: slash[1], tc: slash[2], ttl: slash[3] };
  const body = raw.replace(/^<?mpls:?/i, "").replace(/>$/, "");
  const result: TracerouteMpls = { label: "", tc: "0", ttl: "" };
  for (const field of body.split(",")) {
    const eq = field.indexOf("=");
    if (eq < 0) continue;
    const key = field.slice(0, eq).trim().toUpperCase();
    const value = field.slice(eq + 1).trim();
    if (key === "L") result.label = value;
    else if (key === "E") result.tc = value;
    else if (key === "T") result.ttl = value;
  }
  return result.label ? result : null;
}
