import type { AssetServer, SqlDatabase } from "./runtime";

export interface Env {
  DB?: SqlDatabase;
  ASSETS?: AssetServer;
}

export class ServiceConfigError extends Error {
  constructor(public readonly setting: string) {
    super(`missing_config:${setting}`);
    this.name = "ServiceConfigError";
  }
}
