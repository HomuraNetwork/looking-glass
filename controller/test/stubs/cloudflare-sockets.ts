/**
 * Vitest stand-in for `cloudflare:sockets`.
 *
 * Tests import the Cloudflare runtime adapter (directly, or transitively via
 * src/index.ts) in Node, where the real module does not exist. An alias in
 * vitest.config.ts maps the specifier here. `connect` is only reached through
 * cfTcp.query, which tests exercise with an injected TcpRuntime instead, so
 * throwing is the correct signal if it is ever called for real.
 */
export function connect(): never {
  throw new Error("cloudflare:sockets connect() is not available under vitest");
}
