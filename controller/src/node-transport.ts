/**
 * Fetch a node over HTTPS only. Used for plain (non-WebSocket) requests:
 * control calls, certificate/config pulls and availability probes. WebSocket
 * connections go through the runtime's SocketRuntime (Cloudflare cannot open
 * one with a plain fetch, and Node cannot upgrade a fetch at all).
 *
 * There is intentionally no plaintext-HTTP fallback: an agent that has not yet
 * obtained a valid certificate is unreachable from the worker, and that is the
 * designed behavior. Recovery is driven by the agent's own polling loop
 * (agent -> worker is always reachable outbound), not by the worker reaching
 * into an unauthenticated node.
 */
export async function fetchNode(
  input: {
    domain: string;
    port?: number;
    path: string;
    init?: RequestInit | Request;
  },
): Promise<Response> {
  const url = nodeURL(input.domain, input.port, input.path);
  const request = input.init instanceof Request ? input.init : new Request(url, input.init);
  return fetch(request);
}

/** Build the HTTPS origin for a node or its reverse proxy. */
export function nodeOrigin(domain: string, port = 443): string {
  const url = new URL(`https://${domain}`);
  url.port = port === 443 ? "" : String(port);
  return url.origin;
}

/** Build a node request URL while preserving the selected HTTPS port. */
export function nodeURL(domain: string, port = 443, path = "/"): URL {
  return new URL(path, `${nodeOrigin(domain, port)}/`);
}
