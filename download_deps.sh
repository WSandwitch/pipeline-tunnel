#!/bin/sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Zig ---
download_zig() {
  ZIG_VERSION="0.16.0"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  FILE="zig-x86_64-linux-${ZIG_VERSION}.tar.xz" ;;
    aarch64) FILE="zig-aarch64-linux-${ZIG_VERSION}.tar.xz" ;;
    *)       echo "unsupported arch: $ARCH"; exit 1 ;;
  esac
  TMP="$DIR/$FILE.tmp"

  if [ -f "$DIR/$FILE" ]; then
    echo "$DIR/$FILE"
    return 0
  fi

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
  for mirror in $MIRRORS; do
    echo "  trying $mirror ..."
    rm -f "$TMP"
    curl -fsSL --connect-timeout 15 --max-time 180 "$mirror/$FILE" -o "$TMP" 2>/dev/null
    if [ -f "$TMP" ]; then
      SIZE=$(stat -c%s "$TMP" 2>/dev/null || stat -f%z "$TMP" 2>/dev/null)
      if [ "$SIZE" -gt 1000000 ] 2>/dev/null; then
        mv "$TMP" "$DIR/$FILE"
        echo "done ($SIZE bytes from $mirror)"
        echo "$DIR/$FILE"
        return 0
      fi
    fi
  done
  echo "error: all zig mirrors failed"
  rm -f "$TMP"
  exit 1
}

# --- Nim ---
download_nim() {
  NIM_VERSION="2.2.8"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  NIM_ARCH="x64" ;;
    aarch64) NIM_ARCH="arm64" ;;
    *)       echo "unsupported arch: $ARCH"; exit 1 ;;
  esac
  NIM_FILE="nim-${NIM_VERSION}-linux_${NIM_ARCH}.tar.xz"
  TMP="$DIR/$NIM_FILE.tmp"

  if [ -f "$DIR/$NIM_FILE" ]; then
    echo "$DIR/$NIM_FILE"
    return 0
  fi

  echo "Downloading $NIM_FILE ..."
  rm -f "$TMP"
  curl -fsSL --connect-timeout 30 --max-time 120 \
    "https://nim-lang.org/download/${NIM_FILE}" -o "$TMP" 2>/dev/null
  if [ -f "$TMP" ]; then
    SIZE=$(stat -c%s "$TMP" 2>/dev/null || stat -f%z "$TMP" 2>/dev/null)
    if [ "$SIZE" -gt 1000000 ] 2>/dev/null; then
      mv "$TMP" "$DIR/$NIM_FILE"
      echo "done ($SIZE bytes)"
      echo "$DIR/$NIM_FILE"
      return 0
    fi
  fi
  echo "error: failed to download Nim"
  rm -f "$TMP"
  exit 1
}

download_zig
download_nim
