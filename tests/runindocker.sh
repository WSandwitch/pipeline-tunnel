#!/bin/sh
set -e

IMAGE=pppltunnel:dev
USER_ID=$(id -u)
GROUP_ID=$(id -g)
BUILD_DIR=/tmp/modtunnel-build

[ -d "$BUILD_DIR" ] || mkdir -p "$BUILD_DIR"

docker image inspect "$IMAGE" >/dev/null 2>&1 || \
  docker build -f Dockerfile.dev -t "$IMAGE" .

exec docker run --rm \
  --user "$USER_ID:$GROUP_ID" \
  -v "$(pwd):/app" \
  -v "$BUILD_DIR:/app/build" \
  -v /tmp:/tmp \
  "$IMAGE" ruby /app/tests/tester.rb -S /app/build -M /app/build/tests/test_modules "$@"
