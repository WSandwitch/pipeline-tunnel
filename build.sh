#!/bin/sh
set -e

BUILD_TYPE="${1:-Debug}"
case "$BUILD_TYPE" in
  Debug|Release) ;;
  *) echo "Usage: $0 [Debug|Release]" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${2:-/tmp/modtunnel-hostbuild}"

cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
cmake --build "$BUILD_DIR" -j"$(nproc)"
