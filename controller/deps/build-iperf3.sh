#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Pinned release and SHA-256 from https://software.es.net/iperf/news.html.
version=3.21
sha256=656e4405ebd620121de7ceca3eaf43a88f79ea1b857d041a6a0b1314801acdd8
archive="iperf-${version}.tar.gz"
case "${IPERF3_TARGET:-$(uname -m)}" in
  amd64|x86_64) target=amd64; triple=x86_64-linux-gnu ;;
  arm64|aarch64) target=arm64; triple=aarch64-linux-gnu ;;
  *) echo "unsupported iperf3 target" >&2; exit 1 ;;
esac
if [ ! -f "/tmp/${archive}" ]; then
  curl -fsSL "https://downloads.es.net/pub/iperf/${archive}" -o "/tmp/${archive}"
fi
printf '%s  %s\n' "$sha256" "/tmp/${archive}" | sha256sum -c -
mkdir -p "/src/${target}" /out
tar -xzf "/tmp/${archive}" -C "/src/${target}" --strip-components=1
cd "/src/${target}"
case "$(uname -m):${target}" in
  x86_64:amd64|aarch64:arm64) strip_cmd=strip ;;
  *)
    export CC="${triple}-gcc" AR="${triple}-ar" RANLIB="${triple}-ranlib"
    mkdir -p "/usr/lib/${triple}"
    for library in "/usr/${triple}/lib"/*; do
      ln -sfn "$library" "/usr/lib/${triple}/$(basename "$library")"
    done
    strip_cmd="${triple}-strip"
    set -- "--host=${triple}"
    ;;
esac
# Record the library selected by the same compiler that configure will use.
# This is a packaged static archive, not a glibc source build.
libc_archive=$(readlink -f "$("${CC:-gcc}" -print-file-name=libc.a)")
libc_sha256=$(sha256sum "$libc_archive" | cut -d ' ' -f 1)
notice="/out/iperf3-LICENSE-${target}.txt"
cp LICENSE "$notice"
printf '\n=== iPerf3 build source information (linux/%s) ===\n\n' "$target" >> "$notice"
printf 'Source: https://downloads.es.net/pub/iperf/%s\nArchive SHA-256: %s\n' "$archive" "$sha256" >> "$notice"
printf 'Build script: controller/deps/build-iperf3.sh\nCompiler target: %s\n' "$("${CC:-gcc}" -dumpmachine)" >> "$notice"
sh "$script_dir/write-libc-notices.sh" "$libc_archive" >> "$notice"
./configure --enable-static-bin --disable-shared --enable-static --disable-dependency-tracking --without-openssl --without-sctp "$@"
make -j"$(nproc)"
if [ "$(sha256sum "$libc_archive" | cut -d ' ' -f 1)" != "$libc_sha256" ]; then
  echo "the packaged glibc archive changed during the iperf3 build" >&2
  exit 1
fi
"${strip_cmd}" src/iperf3
cp src/iperf3 /out/iperf3
# The native CI artifact exports this name; the combined Docker build retains
# the architecture-specific originals so neither runtime's provenance is lost.
cp "$notice" /out/iperf3-LICENSE.txt
if readelf -l /out/iperf3 | grep -q INTERP; then
  echo "iperf3 is dynamically linked" >&2
  exit 1
fi
if [ "${CC:-}" = "" ]; then
  /out/iperf3 --version
fi
