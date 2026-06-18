#!/bin/sh
set -e

BUILD_TYPE="${1:-Debug}"
case "$BUILD_TYPE" in
  Debug|Release) ;;
  *) echo "Usage: $0 [Debug|Release]" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/tests/runindocker.sh" sh -c "mkdir -p /app/build/tests/test_modules && cmake -B /app/build -DCMAKE_BUILD_TYPE=$BUILD_TYPE && cmake --build /app/build -j\$(nproc)"
