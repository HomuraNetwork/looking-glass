import type { PublicNode } from "./api";

const NODE_QUERY_PARAM = "node";

export function nodeIDFromSearch(search = globalThis.location?.search || ""): string {
  return new URLSearchParams(search).get(NODE_QUERY_PARAM)?.trim() || "";
}

export function resolveSelectedNodeID(nodes: Pick<PublicNode, "id">[], currentID = "", search = globalThis.location?.search || ""): string {
  const requestedID = nodeIDFromSearch(search);
  if (requestedID && nodes.some((node) => node.id === requestedID)) return requestedID;
  if (currentID && nodes.some((node) => node.id === currentID)) return currentID;
  return nodes[0]?.id || "";
}

export function writeNodeIDToURL(nodeID: string, mode: "push" | "replace" = "push"): void {
  if (!nodeID || !globalThis.location || !globalThis.history) return;
  const url = new URL(globalThis.location.href);
  if (url.searchParams.get(NODE_QUERY_PARAM) === nodeID) return;
  url.searchParams.set(NODE_QUERY_PARAM, nodeID);
  const next = `${url.pathname}${url.search}${url.hash}`;
  if (mode === "replace") {
    globalThis.history.replaceState(null, "", next);
    return;
  }
  globalThis.history.pushState(null, "", next);
}
