#!/bin/sh
set -e

TRACE=""
BUILD_TYPE="Debug"
BASE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --trace|-t) TRACE="-DTRACE_ON=ON"; shift ;;
    --base=*) BASE="${1#*=}"; shift ;;
    --base) BASE="$2"; shift 2 ;;
    Debug|Release) BUILD_TYPE="$1"; shift ;;
    *) echo "Usage: $0 [Debug|Release] [--base alpine|ubuntu] [--trace|-t]" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -z "$BASE" ] && BASE="ubuntu"
case "$BASE" in
  ubuntu) DOCKERFILE="Dockerfile.dev" ;;
  alpine) DOCKERFILE="Dockerfile.devalpine" ;;
  *) echo "Error: --base must be alpine or ubuntu (default: ubuntu)" >&2; exit 1 ;;
esac

exec "$SCRIPT_DIR/tests/runindocker.sh" "$DOCKERFILE" sh -c "mkdir -p /app/build/tests/test_modules && cmake -B /app/build -DCMAKE_BUILD_TYPE=$BUILD_TYPE $TRACE && cmake --build /app/build -j\$(nproc)"
