export interface DNSRecord {
  type: "A" | "AAAA" | "TXT";
  name: string;
  content: string;
}

export interface NodeDomainBaseInput {
  nodeID: string;
  base: string;
  v4Base?: string;
  v6Base?: string;
  singleBase?: boolean;
  prefix?: string;
  domain?: string;
  domainV4?: string;
  domainV6?: string;
}

export function nodeDomainsFromBases(input: NodeDomainBaseInput): { domain: string; domain_v4: string; domain_v6: string } {
  const base = normalizeBase(input.base);
  const prefix = normalizeLabel(input.prefix || input.nodeID);
  let generated: { domain: string; domain_v4: string; domain_v6: string };
  if (input.singleBase) {
    generated = {
      domain: `${prefix}.${base}`,
      domain_v4: `${prefix}-v4.${base}`,
      domain_v6: `${prefix}-v6.${base}`,
    };
  } else {
    generated = {
      domain: domainFromPrefixBase(prefix, input.base),
      domain_v4: domainFromPrefixBase(prefix, input.v4Base || input.base),
      domain_v6: domainFromPrefixBase(prefix, input.v6Base || input.base),
    };
  }
  return {
    domain: input.domain ? normalizeDomain(input.domain) : generated.domain,
    domain_v4: input.domainV4 ? normalizeDomain(input.domainV4) : generated.domain_v4,
    domain_v6: input.domainV6 ? normalizeDomain(input.domainV6) : generated.domain_v6,
  };
}

export function dnsRecordsForNode(input: NodeDomainBaseInput & { ipv4: string; ipv6: string }): DNSRecord[] {
  const domains = nodeDomainsFromBases(input);
  return [
    { type: "A", name: domains.domain, content: input.ipv4 },
    { type: "AAAA", name: domains.domain, content: input.ipv6 },
    { type: "A", name: domains.domain_v4, content: input.ipv4 },
    { type: "AAAA", name: domains.domain_v6, content: input.ipv6 },
  ];
}

export async function upsertDNSRecord(token: string, zoneID: string, record: DNSRecord): Promise<DNSRecord & { action: string }> {
  const query = new URLSearchParams({ type: record.type, name: record.name });
  const existing = await cloudflareFetch(token, `/zones/${zoneID}/dns_records?${query.toString()}`);
  const body: DNSRecord & { ttl: number; proxied?: boolean; comment: string } = {
    ...record,
    ttl: 300,
    comment: "HLG admin DNS",
  };
  if (record.type !== "TXT") body.proxied = false;
  const id = existing.result?.[0]?.id;
  if (id) {
    await cloudflareFetch(token, `/zones/${zoneID}/dns_records/${id}`, { method: "PATCH", body: JSON.stringify(body) });
    return { action: "updated", ...record };
  }
  await cloudflareFetch(token, `/zones/${zoneID}/dns_records`, { method: "POST", body: JSON.stringify(body) });
  return { action: "created", ...record };
}

export async function deleteDNSRecord(token: string, zoneID: string, record: Pick<DNSRecord, "type" | "name">): Promise<Array<Pick<DNSRecord, "type" | "name"> & { action: string }>> {
  const query = new URLSearchParams({ type: record.type, name: record.name });
  const existing = await cloudflareFetch(token, `/zones/${zoneID}/dns_records?${query.toString()}`);
  const deleted = [];
  for (const match of existing.result ?? []) {
    if (!match.id) continue;
    await cloudflareFetch(token, `/zones/${zoneID}/dns_records/${match.id}`, { method: "DELETE" });
    deleted.push({ action: "deleted", ...record });
  }
  return deleted;
}

function domainFromPrefixBase(prefix: string, base: string): string {
  return `${prefix}.${normalizeBase(base)}`;
}

function normalizeBase(base: string): string {
  return base.trim().replace(/^\.+/, "");
}

function normalizeDomain(domain: string): string {
  return normalizeBase(domain);
}

function normalizeLabel(label: string): string {
  return label.trim().replace(/^\.+|\.+$/g, "");
}

async function cloudflareFetch(token: string, path: string, init: RequestInit = {}): Promise<{ result?: Array<{ id?: string }> }> {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    ...init,
    signal: init.signal ?? AbortSignal.timeout(10000),
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  const body = (await response.json()) as { success?: boolean; result?: Array<{ id?: string }>; errors?: unknown };
  if (!response.ok || body.success === false) throw new Error(`cloudflare_api_failed:${response.status}`);
  return body;
}
