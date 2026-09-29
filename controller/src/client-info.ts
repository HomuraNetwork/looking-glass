import { json, clientIP } from "./http";
import { isIPAddress, isPrivateIPAddress } from "./ip-guard";
import { lookupAsns, canonicalIPKey } from "./asn";
import type { TcpRuntime } from "./runtime";

export interface ClientInfoResponse {
  ip: string;
  country: string;
  city: string;
  asn: string;
  asOrg: string;
  colo: string;
  httpProtocol: string;
  tlsVersion: string;
}

/** The subset of Cloudflare's request.cf we surface. Absent off-platform. */
interface CfProperties {
  country?: string;
  city?: string;
  asn?: number;
  asOrganization?: string;
  colo?: string;
  httpProtocol?: string;
  tlsVersion?: string;
}

/**
 * Build the visitor-info readout. On Cloudflare the edge supplies everything
 * via request.cf; off-platform only the client IP is known (adapter-provided),
 * so the ASN and its country fall back to a Team Cymru whois lookup when the
 * runtime offers TCP — colo/HTTP/TLS are edge concepts and stay empty there.
 */
export async function handleClientInfo(request: Request, tcp?: TcpRuntime): Promise<Response> {
  const cf = (request as unknown as { cf?: CfProperties }).cf;
  const ip = clientIP(request);
  const body: ClientInfoResponse = {
    ip,
    country: cf?.country ?? "",
    city: cf?.city ?? "",
    asn: cf?.asn ? `AS${cf.asn}` : "",
    asOrg: cf?.asOrganization ?? "",
    colo: cf?.colo ?? "",
    httpProtocol: cf?.httpProtocol ?? "",
    tlsVersion: cf?.tlsVersion ?? "",
  };

  // Off-platform the edge fields are absent: enrich the ASN + its country from
  // the same Cymru bulk lookup the mtr enrichment uses (cached, best-effort).
  if (tcp && !body.asn && isIPAddress(ip) && !isPrivateIPAddress(ip)) {
    const record = (await lookupAsns(tcp, [ip])).get(canonicalIPKey(ip));
    if (record) {
      body.asn = record.asn;
      body.asOrg = asnOrgFromName(record.name);
      if (!body.country) body.country = record.country;
    }
  }
  return json(body);
}

/** Extract the human org from Cymru's as-name ("GOOGLE - Google LLC, US" -> "Google LLC, US"). */
export function asnOrgFromName(name: string): string {
  const idx = name.indexOf(" - ");
  return idx >= 0 ? name.slice(idx + 3).trim() : name.trim();
}
