import { getRuntimeJWK } from "./runtime-secrets";
import { bytesToBase64URL, kidFromJWK, sha256Hex, signBytes } from "./signing";
import type { SqlDatabase } from "./runtime";

const encoder = new TextEncoder();

export async function signedAgentRequest(db: SqlDatabase | undefined, input: {
  method: string;
  url: string;
  path: string;
  nodeID: string;
  body: string;
  headers?: Record<string, string>;
}): Promise<Request> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomUUID();
  const bodyHash = await sha256Hex(input.body);
  // Sign the path only. Binding the query was tried and reverted: it is pure
  // defense-in-depth (the agent's single-use nonce cache already blocks
  // replays, and TLS protects the query in transit) but it forced a deploy
  // ordering constraint where an un-updated agent rejects the iperf events
  // stream for every other request. Agents still accept path-only signatures,
  // so this stays wire-compatible with both old and new agents.
  const signingInput = [input.method, input.path, timestamp, nonce, bodyHash, input.nodeID].join("\n");
  const jwk = await getRuntimeJWK(db, "LG_ADMIN_SIGN_JWK");
  const signature = await signBytes(encoder.encode(signingInput), jwk);
  const headers = new Headers(input.headers);
  headers.set("content-type", "application/json");
  headers.set("x-lg-timestamp", timestamp);
  headers.set("x-lg-nonce", nonce);
  headers.set("x-lg-key-id", await kidFromJWK(jwk));
  headers.set("x-lg-signature", bytesToBase64URL(signature));
  const init: RequestInit = {
    method: input.method,
    headers,
  };
  if (input.method !== "GET" && input.method !== "HEAD") init.body = input.body;
  return new Request(input.url, init);
}
