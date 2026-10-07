import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";
import { collectNpmLicenses } from "./build-licenses.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "hlg-licenses-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  function pkg(dir, metadata, files = {}) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify(metadata));
    for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  }
  return { root, pkg };
}

test("includes full runtime LICENSE and NOTICE texts, excludes dev-only inputs", async (t) => {
  const { root, pkg } = fixture(t);
  pkg(root, { dependencies: { runtime: "1" }, devDependencies: { buildTool: "1" } });
  pkg(join(root, "node_modules/runtime"), {
    name: "runtime", version: "1.0.0", dependencies: { child: "1" },
    optionalDependencies: { absent: "1" },
    peerDependencies: { "@types/runtime": "1" },
  }, { LICENSE: "Complete permission and copyright notice\n", NOTICE: "Upstream attribution\n", "CopyrightNotice.txt": "Separate copyright notice\n" });
  pkg(join(root, "node_modules/child"), { name: "child", version: "1.0.0" }, { "LICENSE.txt": "Child full license\n" });
  const notices = await collectNpmLicenses([root]);
  assert.match(notices, /Complete permission and copyright notice/);
  assert.match(notices, /Upstream attribution/);
  assert.match(notices, /Separate copyright notice/);
  assert.match(notices, /Child full license/);
  assert.doesNotMatch(notices, /buildTool|absent|@types/);
  assert.equal(await collectNpmLicenses([root]), notices);
});

test("fails when a required runtime dependency cannot be resolved", async (t) => {
  const { root, pkg } = fixture(t);
  pkg(root, { dependencies: { missing: "1" } });
  await assert.rejects(collectNpmLicenses([root]), /cannot resolve runtime dependency missing/);
});

test("includes injected runtime helper notices without compiler dependencies", async (t) => {
  const { root, pkg } = fixture(t);
  pkg(root, {});
  pkg(join(root, "node_modules/bundler"), { name: "bundler", version: "1", dependencies: { compilerOnly: "1" } },
    { LICENSE: "Helper runtime permission\n", "THIRD-PARTY-LICENSE": "Derived helper notice\n" });
  const notices = await collectNpmLicenses([root], [], [[root, "bundler"]]);
  assert.match(notices, /Helper runtime permission/);
  assert.match(notices, /Derived helper notice/);
  assert.doesNotMatch(notices, /compilerOnly/);
});

test("fails for license metadata without actual permission text", async (t) => {
  const { root, pkg } = fixture(t);
  pkg(root, { dependencies: { missingLicense: "1" } });
  pkg(join(root, "node_modules/missingLicense"), { name: "missingLicense", version: "1.0.0", license: "MIT" });
  await assert.rejects(collectNpmLicenses([root]), /no license text found for missingLicense@1.0.0/);
});

test("uses the checked-in missing npm license without network access", async (t) => {
  const { root, pkg } = fixture(t);
  pkg(root, { dependencies: { "react-remove-scroll-bar": "2.3.8" } });
  pkg(join(root, "node_modules/react-remove-scroll-bar"), { name: "react-remove-scroll-bar", version: "2.3.8", license: "MIT" });
  t.mock.method(globalThis, "fetch", () => { throw new Error("network is unavailable"); });
  const notices = await collectNpmLicenses([root]);
  assert.match(notices, /Copyright \(c\) 2025 Anton Korzunov/);
  assert.match(notices, /7301c160fda44cb8cf2b9fdfde61efad35736196\/LICENSE/);
  assert.match(notices, /THE SOFTWARE IS PROVIDED "AS IS"/);
  pkg(join(root, "node_modules/react-remove-scroll-bar"), { name: "react-remove-scroll-bar", version: "2.3.9", license: "MIT" });
  await assert.rejects(collectNpmLicenses([root]), /no license text found for react-remove-scroll-bar@2.3.9/);
});

test("keeps both architectures' runtime provenance and rejects missing release notices", async (t) => {
  const { root, pkg } = fixture(t);
  const controller = join(root, "controller");
  const frontend = join(controller, "frontend");
  const dist = join(frontend, "dist");
  pkg(controller, {});
  pkg(frontend, {});
  for (const name of ["vite", "tailwindcss", "rolldown"]) {
    pkg(join(frontend, "node_modules", name), { name, version: "1" }, { LICENSE: `${name} full license\n` });
  }
  pkg(join(controller, "node_modules/esbuild"), { name: "esbuild", version: "1" }, { LICENSE: "esbuild full license\n" });
  mkdirSync(join(controller, "scripts"));
  const copy = join(controller, "scripts/build-licenses.mjs");
  copyFileSync(new URL("./build-licenses.mjs", import.meta.url), copy);
  const { writeThirdPartyLicenses } = await import(pathToFileURL(copy).href);
  writeFileSync(join(root, "LICENSE"), "HLG MIT permission\n");
  writeFileSync(join(root, "THIRD_PARTY_NOTICES.md"), "Copied source notices\n");
  mkdirSync(join(controller, "build"));
  const nativeNotice = join(controller, "build/iperf3-LICENSE-amd64.txt");
  const crossNotice = join(controller, "build/iperf3-LICENSE-arm64.txt");
  writeFileSync(nativeNotice, "iPerf3 upstream license\nglibc source version: native-version\n");
  writeFileSync(crossNotice, "iPerf3 upstream license\nglibc source version: cross-version\n");
  await writeThirdPartyLicenses({ requireIperf3: true });
  const notices = readFileSync(join(dist, "THIRD_PARTY_LICENSES.txt"), "utf8");
  assert.match(notices, /=== linux\/amd64 ===[\s\S]*native-version/);
  assert.match(notices, /=== linux\/arm64 ===[\s\S]*cross-version/);
  await writeThirdPartyLicenses({ requireIperf3: true });
  assert.equal(readFileSync(join(dist, "THIRD_PARTY_LICENSES.txt"), "utf8"), notices);
  rmSync(crossNotice);
  await assert.rejects(writeThirdPartyLicenses({ requireIperf3: true }), /iperf3-LICENSE-arm64\.txt/);
  mkdirSync(join(dist, "_deps"));
  writeFileSync(join(dist, "_deps/hlg-iperf3-linux-amd64"), "binary fixture");
  await writeThirdPartyLicenses();
  assert.doesNotMatch(readFileSync(join(dist, "THIRD_PARTY_LICENSES.txt"), "utf8"), /cross-version|linux\/arm64/);
});
