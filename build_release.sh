#!/bin/sh
set -e

VERSION=$(cat VERSION)

exec docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f Dockerfile.release \
  -t "pppltunnel:${VERSION}" \
  -t ppltunnel:latest \
  --load \
  .
