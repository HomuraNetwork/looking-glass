declare module "node:fs" {
  export function mkdtempSync(prefix: string): string;
  export function writeFileSync(path: string, data: string): void;
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
}
declare module "node:os" { export function tmpdir(): string; }
declare module "node:path" { export function join(...parts: string[]): string; }
declare module "node:child_process" {
  export function execFileSync(file: string, args: string[], options?: { cwd?: string; env?: Record<string, string | undefined>; stdio?: string; timeout?: number }): Uint8Array;
}
declare const process: { cwd(): string; env: Record<string, string | undefined> };
