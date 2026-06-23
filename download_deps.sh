#!/bin/sh
set -e
ZIG_VERSION="0.16.0"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  FILE="zig-x86_64-linux-${ZIG_VERSION}.tar.xz" ;;
  aarch64) FILE="zig-aarch64-linux-${ZIG_VERSION}.tar.xz" ;;
  *)       echo "unsupported arch: $ARCH"; exit 1 ;;
esac
DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$DIR/$FILE.tmp"

if [ -f "$DIR/$FILE" ]; then
  echo "$DIR/$FILE"
  exit 0
fi

# Mirrors from https://ziglang.org/download/community-mirrors.txt
# Fastly CDN first (global, fast, no throttling)
MIRRORS="\
https://ziglang.freetls.fastly.net
https://pkg.hexops.org/zig
https://zigmirror.hryx.net/zig
https://zig.linus.dev/zig
https://zig.squirl.dev
https://zig.mirror.mschae23.de/zig
https://zig.tilok.dev
https://zig-mirror.tsimnet.eu/zig
https://zig.karearl.com/zig
https://pkg.earth/zig
https://fs.liujiacai.net/zigbuilds
https://zigmirror.com
https://zig.chainsafe.dev
https://zig.savalione.com
https://ziglang.org/download/${ZIG_VERSION}"

echo "Downloading $FILE ..."

download_url() {
  local url="$1"
  rm -f "$TMP"
  curl -fsSL --connect-timeout 15 --max-time 180 "$url/$FILE" -o "$TMP" 2>/dev/null
}

for mirror in $MIRRORS; do
  echo "  trying $mirror ..."
  if download_url "$mirror"; then
    SIZE=$(stat -c%s "$TMP" 2>/dev/null || stat -f%z "$TMP" 2>/dev/null)
    if [ "$SIZE" -gt 1000000 ] 2>/dev/null; then
      mv "$TMP" "$DIR/$FILE"
      echo "done ($SIZE bytes from $mirror)"
      echo "$DIR/$FILE"
      exit 0
    fi
  fi
done

echo "error: all mirrors failed"
rm -f "$TMP"
exit 1
