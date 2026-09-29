/**
 * Runtime abstraction barrel. The core imports `SqlDatabase` and friends from
 * here so a second runtime can be added without touching call sites.
 */
export type { AssetServer, HTMLTransform, ProxiedSocket, SocketPair, SocketPairFactory, SocketRuntime, SqlDatabase, SqlResult, SqlStatement, TcpQueryOptions, TcpRuntime } from "./types";
