import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

const script = resolve(dirname(fileURLToPath(import.meta.url)), "../deps/write-libc-notices.sh");

function fixture(t, metadata) {
  const root = mkdtempSync(join(tmpdir(), "hlg-libc-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const archive = join(root, "packaged-libc.a");
  const lookup = join(root, "libc.a");
  const copyright = join(root, "copyright");
  writeFileSync(archive, "unmodified Debian archive");
  symlinkSync(archive, lookup);
  writeFileSync(copyright, "Complete Debian copyright and permission text\n");
  const bin = join(root, "bin");
  mkdirSync(bin);
  // Stand in for dpkg's database, including architecture-qualified ownership
  // and cross-toolchain-base's separate Built-Using source dependency.
  writeFileSync(join(bin, "dpkg-query"), `#!/bin/sh
case "$1" in
  -S)
    test "$2" = "$ARCHIVE" || exit 1
    printf '%s: %s\\n' "$PACKAGE" "$ARCHIVE" ;;
  -L) printf '%s\\n' "$COPYRIGHT" ;;
  -W)
    case "$2" in
      '-f=\${Version}') printf '%s' "$VERSION" ;;
      '-f=\${source:Package}') printf '%s' "$SOURCE" ;;
      '-f=\${source:Version}') printf '%s' "$SOURCE_VERSION" ;;
      '-f=\${Built-Using}') printf '%s' "$BUILT_USING" ;;
      '-f=\${Static-Built-Using}') printf '%s' "$STATIC_BUILT_USING" ;;
      *) exit 1 ;;
    esac ;;
  *) exit 1 ;;
esac
`, { mode: 0o755 });
  const env = {
    ...process.env, PATH: `${bin}:${process.env.PATH}`, ARCHIVE: archive, COPYRIGHT: copyright,
    PACKAGE: metadata.package, VERSION: metadata.version, SOURCE: metadata.source,
    SOURCE_VERSION: metadata.sourceVersion, BUILT_USING: metadata.builtUsing ?? "",
    STATIC_BUILT_USING: metadata.staticBuiltUsing ?? "",
  };
  return { run: () => execFileSync("sh", [script, lookup], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
}

test("records the native Debian package, exact source, resolved archive and copyright", (t) => {
  const { run } = fixture(t, { package: "libc6-dev:amd64", version: "2.36-9+deb12u13", source: "glibc", sourceVersion: "2.36-9+deb12u13" });
  const notices = run();
  assert.match(notices, /Binary package: libc6-dev:amd64/);
  assert.match(notices, /glibc source version: 2\.36-9\+deb12u13/);
  assert.match(notices, /https:\/\/snapshot\.debian\.org\/package\/glibc\/2\.36-9\+deb12u13\//);
  assert.ok(notices.includes(createHash("sha256").update("unmodified Debian archive").digest("hex")));
  assert.match(notices, /Complete Debian copyright and permission text/);
});

test("uses Built-Using glibc version instead of the cross packaging version", (t) => {
  const { run } = fixture(t, { package: "libc6-dev-arm64-cross", version: "2.36-8cross1", source: "cross-toolchain-base", sourceVersion: "66", builtUsing: "linux (= 6.1.4-1), glibc (= 2.36-8)" });
  const notices = run();
  assert.match(notices, /Package source version: 66/);
  assert.match(notices, /glibc source version: 2\.36-8\n/);
  assert.match(notices, /Packaging source: https:\/\/snapshot\.debian\.org\/package\/cross-toolchain-base\/66\//);
  assert.doesNotMatch(notices, /glibc source version: (66|2\.36-8cross1)/);
});

test("accepts Static-Built-Using and fails rather than guessing absent or conflicting glibc versions", (t) => {
  const cross = { package: "libc6-dev-amd64-cross", version: "2.36-8cross1", source: "cross-toolchain-base", sourceVersion: "66" };
  assert.match(fixture(t, { ...cross, staticBuiltUsing: "glibc (= 2.36-8)" }).run(), /glibc source version: 2\.36-8\n/);
  for (const fields of [{}, { builtUsing: "glibc (= 2.36-8)", staticBuiltUsing: "glibc (= 2.36-9)" }]) {
    assert.throws(fixture(t, { ...cross, ...fields }).run, (error) => {
      assert.match(error.stderr.toString(), /cannot determine the exact glibc source version/);
      return true;
    });
  }
});
