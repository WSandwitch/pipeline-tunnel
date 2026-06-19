#!/usr/bin/env bash
# Usage: bench_tunnel.sh <config> [workers] [duration] [iperf3_flags]
# Example: bench_tunnel.sh "copy" 1 10
# Example: bench_tunnel.sh "base64;base64" 2 15 --bidir
# Example: bench_tunnel.sh "base64;base64" 1 10 -R

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/tmp/modtunnel-hostbuild}"
SERV="$BUILD_DIR/server/ppltunnel-server"
CLI="$BUILD_DIR/client/ppltunnel-client"
MOD_DIR="$BUILD_DIR/tests/test_modules"
CONFIG="${1:?bench_tunnel.sh <config> [workers] [duration] [iperf3_flags]}"
WORKERS="${2:-1}"
DURATION="${3:-10}"
IPERF_FLAGS="${4:-}"

cleanup() {
  kill $SVR_PID $CLI_PID 2>/dev/null || true
  killall -9 iperf3 ppltunnel-server ppltunnel-client 2>/dev/null || true
}

find_port() {
  python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()"
}

IPERF_PORT=$(find_port)
SVR_PORT=$(find_port)
CLI_PORT=$(find_port)

echo "=== bench_tunnel ==="
echo "  Config:     $CONFIG"
echo "  Workers:    $WORKERS"
echo "  Duration:   ${DURATION}s"
echo "  iperf args: $IPERF_FLAGS"
echo "  Ports:      iperf=$IPERF_PORT  svr=$SVR_PORT  cli=$CLI_PORT"
echo ""

trap cleanup EXIT INT TERM

iperf3 -s -D -p $IPERF_PORT >/dev/null 2>&1

$SERV -l127.0.0.1:$SVR_PORT -Atestpass -M$MOD_DIR -t$WORKERS >/tmp/svr.log 2>&1 &
SVR_PID=$!
sleep 0.5

CHAIN_ARG="127.0.0.1:$SVR_PORT,testpass;$CONFIG;"
$CLI -L127.0.0.1:$CLI_PORT:127.0.0.1:$IPERF_PORT -M$MOD_DIR -t$WORKERS \
  "$CHAIN_ARG" >/tmp/cli.log 2>&1 &
CLI_PID=$!
sleep 0.5

iperf3 -c 127.0.0.1 -p $CLI_PORT -t $DURATION $IPERF_FLAGS

echo ""
echo "=== done ==="
