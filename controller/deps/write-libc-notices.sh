#!/bin/sh
set -eu

# The caller supplies the archive resolved by the actual build compiler.
# Resolve cross-compiler lookup symlinks before querying Debian ownership.
libc_archive=$(readlink -f "$1")
test -f "$libc_archive"
package=$(dpkg-query -S "$libc_archive" | sed 's/: \/.*$//')
if [ "$(printf '%s\n' "$package" | wc -l)" -ne 1 ]; then
  echo "cannot determine a unique Debian owner for $libc_archive" >&2
  exit 1
fi
binary_version=$(dpkg-query -W -f='${Version}' "$package")
source_package=$(dpkg-query -W -f='${source:Package}' "$package")
source_version=$(dpkg-query -W -f='${source:Version}' "$package")
built_using=$(dpkg-query -W -f='${Built-Using}' "$package")
static_built_using=$(dpkg-query -W -f='${Static-Built-Using}' "$package")

if [ "$source_package" = glibc ]; then
  glibc_version=$source_version
else
  # Cross libc packages are built by cross-toolchain-base. Their source
  # version is NOT glibc's version; Debian records that in Built-Using.
  glibc_version=$(printf '%s,%s\n' "$built_using" "$static_built_using" | tr ',' '\n' |
    sed -n 's/^[[:space:]]*glibc[[:space:]]*(=[[:space:]]*\([^)]*\))[[:space:]]*$/\1/p' |
    sed 's/[[:space:]]*$//' | sort -u)
fi
if [ -z "$glibc_version" ] || [ "$(printf '%s\n' "$glibc_version" | wc -l)" -ne 1 ]; then
  echo "cannot determine the exact glibc source version for $package" >&2
  exit 1
fi
test -n "$binary_version"
test -n "$source_package"
test -n "$source_version"
libc_copyright=$(dpkg-query -L "$package" | sed -n '/\/copyright$/p' | head -n 1)
if [ -z "$libc_copyright" ]; then
  libc_copyright="/usr/share/doc/${package%%:*}/copyright"
fi
test -s "$libc_copyright"

printf '\n=== Static C runtime: Debian glibc build source information ===\n\n'
printf 'Binary package: %s\nBinary package version: %s\n' "$package" "$binary_version"
printf 'Package source: %s\nPackage source version: %s\n' "$source_package" "$source_version"
printf 'Built-Using: %s\nStatic-Built-Using: %s\n' "$built_using" "$static_built_using"
printf 'Linked archive: %s\nArchive SHA-256: %s\n' "$libc_archive" "$(sha256sum "$libc_archive" | cut -d ' ' -f 1)"
printf 'glibc source package: glibc\nglibc source version: %s\n' "$glibc_version"
printf 'glibc source: https://snapshot.debian.org/package/glibc/%s/\n' "$glibc_version"
printf 'Packaging source: https://snapshot.debian.org/package/%s/%s/\n' "$source_package" "$source_version"
printf 'Source retrieval: apt-get source glibc=%s (enable the matching deb-src archive).\n' "$glibc_version"
printf 'For archived versions, download the .dsc and its source files from the snapshot source links above.\n'
printf 'HLG uses the Debian-provided library as delivered; it applies no glibc source or library modifications.\n'
printf '\n=== Static C runtime: glibc (Debian copyright) ===\n\n'
cat "$libc_copyright"
for license in $(grep -o '/usr/share/common-licenses/[A-Za-z0-9.-]*' "$libc_copyright" | sort -u); do
  printf '\n=== %s ===\n\n' "$license"
  cat "$license"
done
