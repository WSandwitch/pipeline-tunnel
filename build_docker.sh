#!/bin/sh
set -e

TRACE=""
BUILD_TYPE="Debug"
for arg in "$@"; do
  case "$arg" in
    --trace|-t) TRACE="-DTRACE_ON=ON" ;;
    Debug|Release) BUILD_TYPE="$arg" ;;
    *) echo "Usage: $0 [Debug|Release] [--trace|-t]" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/tests/runindocker.sh" sh -c "mkdir -p /app/build/tests/test_modules && cmake -B /app/build -DCMAKE_BUILD_TYPE=$BUILD_TYPE $TRACE && cmake --build /app/build -j\$(nproc)"
