#!/bin/sh
set -e

cd "$(dirname "$0")"
VERSION=$(cat ../VERSION)
BASE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --base=*) BASE="${1#*=}"; shift ;;
    --base) BASE="$2"; shift 2 ;;
    *) echo "Usage: $0 [--base alpine|ubuntu]" >&2; exit 1 ;;
  esac
done
# Primary: ubuntu (fast, host-compatible). Legacy: alpine (musl, smaller).
[ -z "$BASE" ] && BASE="ubuntu"
case "$BASE" in
  alpine) DOCKERFILE="Dockerfile.alpine" ;;
  ubuntu) DOCKERFILE="Dockerfile.ubuntu" ;;
  *) echo "Error: --base must be alpine or ubuntu (default: ubuntu)" >&2; exit 1 ;;
esac

exec docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -f "$DOCKERFILE" \
  -t "pppltunnel:${VERSION}" \
  -t ppltunnel:latest \
  --load \
  ..
