import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const controllerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(controllerRoot, "..");
const iperfArches = ["amd64", "arm64"];
export function iperfLicensePath(arch) {
  if (!iperfArches.includes(arch)) throw new Error(`unsupported architecture: ${arch}`);
  return resolve(controllerRoot, `build/iperf3-LICENSE-${arch}.txt`);
}
export const LICENSE_URL = "/THIRD_PARTY_LICENSES.txt";

// This published npm package omits LICENSE, and its npm gitHead is not
// available upstream. Preserve the author's license from an audited, fixed
// commit, checked in as a build input so notice generation needs no network.
// A version change requires rechecking this exception.
const upstreamLicenses = {
  "react-remove-scroll-bar@2.3.8": {
    file: resolve(controllerRoot, "licenses/react-remove-scroll-bar-2.3.8-LICENSE.txt"),
    url: "https://raw.githubusercontent.com/theKashey/react-remove-scroll-bar/7301c160fda44cb8cf2b9fdfde61efad35736196/LICENSE",
    sha256: "a79aae0c0f21990d9d963bb3c5a79cdcea9a46f8523ba55c58d7fe776b6ebc84",
  },
};

async function upstreamLicense(key) {
  const source = upstreamLicenses[key];
  if (!source) throw new Error(`no license text found for ${key}; add a verified upstream license source`);
  const bytes = readFileSync(source.file);
  if (createHash("sha256").update(bytes).digest("hex") !== source.sha256) {
    throw new Error(`upstream license checksum mismatch for ${key}`);
  }
  return section(`${key} / upstream LICENSE`, `Source: ${source.url}\n\n${bytes.toString("utf8")}`);
}

function section(title, text) {
  if (!text.trim()) throw new Error(`empty license notice: ${title}`);
  return `=== ${title} ===\n\n${text.trimEnd()}\n\n`;
}

function installedPackage(name, from, optional) {
  for (let dir = from; ; dir = dirname(dir)) {
    const candidate = join(dir, "node_modules", name);
    if (existsSync(join(candidate, "package.json"))) return realpathSync(candidate);
    if (dirname(dir) === dir) break;
  }
  if (optional) return null;
  throw new Error(`cannot resolve runtime dependency ${name} from ${from}`);
}

// Traverse installed runtime dependencies, including peers and optional
// dependencies that are present. Dev-only tools are excluded. Tailwind is an
// explicit input because its framework CSS is included in the frontend output.
export async function collectNpmLicenses(roots, extraDependencies = [], runtimeHelpers = []) {
  const seen = new Set();
  const notices = new Map();
  async function dependencies(pkg, dir) {
    const optional = pkg.optionalDependencies ?? {};
    const peers = pkg.peerDependencies ?? {};
    const names = { ...peers, ...pkg.dependencies, ...optional };
    for (const name of Object.keys(names).sort()) {
      if (name.startsWith("@types/")) continue; // Type-only peers are not runtime code.
      const mayBeMissing = name in optional
        || (name in peers && !(name in (pkg.dependencies ?? {})) && pkg.peerDependenciesMeta?.[name]?.optional);
      await visit(installedPackage(name, dir, mayBeMissing));
    }
  }
  async function visit(dir, traverse = true) {
    if (!dir || seen.has(dir)) return;
    seen.add(dir);
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    const files = readdirSync(dir, { withFileTypes: true })
      .filter((file) => file.isFile() && /^(licen[cs]e|copying|notice|copyright(?:notice)?|third[-_]party[-_](?:licenses?|notices?))([._-].*)?$/i.test(file.name))
      .map((file) => file.name).sort();
    const key = `${pkg.name}@${pkg.version}`;
    let text = files.map((name) => section(`${key} / ${name}`, readFileSync(join(dir, name), "utf8"))).join("");
    if (!files.some((name) => /^(licen[cs]e|copying)/i.test(name))) text += await upstreamLicense(key);
    notices.set(key, text);
    if (traverse) await dependencies(pkg, dir);
  }
  for (const root of roots) {
    await dependencies(JSON.parse(readFileSync(join(root, "package.json"), "utf8")), root);
  }
  for (const [root, name] of extraDependencies) await visit(installedPackage(name, root, false));
  // Bundlers inject helper code into output. Preserve their notices without
  // pulling their compiler/native build dependencies into the runtime graph.
  for (const [root, name] of runtimeHelpers) await visit(installedPackage(name, root, false), false);
  return [...notices].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, text]) => text).join("");
}

export async function writeThirdPartyLicenses({ requireIperf3 = false } = {}) {
  const frontend = resolve(controllerRoot, "frontend");
  const dist = resolve(frontend, "dist");
  let text = "Homura Looking Glass — distribution license notices\n\n";
  text += section("HLG", readFileSync(resolve(repoRoot, "LICENSE"), "utf8"));
  text += section("Copied source notices", readFileSync(resolve(repoRoot, "THIRD_PARTY_NOTICES.md"), "utf8"));
  const vite = installedPackage("vite", frontend, false);
  text += await collectNpmLicenses([controllerRoot, frontend], [[frontend, "tailwindcss"]], [[controllerRoot, "esbuild"], [vite, "rolldown"]]);
  const arches = iperfArches.filter((arch) => requireIperf3 || existsSync(resolve(dist, "_deps", `hlg-iperf3-linux-${arch}`)));
  if (arches.length) {
    // Each architecture's intermediate notice is copied out of its build.
    // Preserve both runtime versions; CI must not overwrite one with another.
    text += section("iPerf3", arches.map((arch) => section(`linux/${arch}`, readFileSync(iperfLicensePath(arch), "utf8"))).join(""));
  }
  mkdirSync(dist, { recursive: true });
  writeFileSync(resolve(dist, "THIRD_PARTY_LICENSES.txt"), text);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await writeThirdPartyLicenses({ requireIperf3: process.argv.includes("--require-iperf3") });
}
