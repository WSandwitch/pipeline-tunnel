#!/bin/sh
set -e

IMAGE=pppltunnel:dev
USER_ID=$(id -u)
GROUP_ID=$(id -g)
BUILD_DIR=/tmp/modtunnel-build

[ -d "$BUILD_DIR" ] || mkdir -p "$BUILD_DIR"

STAMP_FILE="$BUILD_DIR/.docker_build_stamp"
NEEDS_BUILD=false
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  NEEDS_BUILD=true
elif [ ! -f "$STAMP_FILE" ] || [ "Dockerfile.dev" -nt "$STAMP_FILE" ]; then
  NEEDS_BUILD=true
fi
if [ "$NEEDS_BUILD" = true ]; then
  docker build -f Dockerfile.dev -t "$IMAGE" .
  touch "$STAMP_FILE"
fi

exec docker run --rm \
  --user "$USER_ID:$GROUP_ID" \
  -v "$(pwd):/app" \
  -v "$BUILD_DIR:/app/build" \
  -v /tmp:/tmp \
  "$IMAGE" ruby /app/tests/tester.rb -S /app/build -M /app/build/tests/test_modules "$@"
