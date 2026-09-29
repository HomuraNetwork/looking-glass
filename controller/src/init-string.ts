/**
 * One-line "init string": the controller and the one-time init key in a single
 * value, so a container or host only needs `LG_INIT_STRING` instead of
 * `LG_CONTROLLER` + `LG_INIT_TOKEN`.
 *
 * Form: `[http://|https://]host[:port]/lginit_<key>`
 *
 * https is assumed when the scheme is omitted, and the port is included only
 * when non-default. The node's domain and node id are intentionally NOT carried
 * here: they are authoritative in the controller's signed config bundle. The
 * agent parses the same format in agent/internal/initstring.
 */

export function encodeInitString(controllerOrigin: string, initKey: string): string {
  const url = new URL(controllerOrigin);
  const defaultPort = url.protocol === "https:" ? "443" : "80";
  const host = url.hostname; // includes brackets for IPv6
  const authority = url.port && url.port !== defaultPort ? `${host}:${url.port}` : host;
  const scheme = url.protocol === "https:" ? "" : `${url.protocol}//`;
  return `${scheme}${authority}/${initKey}`;
}
