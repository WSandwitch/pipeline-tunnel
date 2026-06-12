#!/bin/sh
# Usage: measure_mem.sh <config> [direction] [duration]
#   config: module chain config, e.g. "copy;base64"
#   direction: forward|reverse|bidir (default: forward)
#   duration: benchmark duration in seconds (default: 10)
#
# Measures RSS of ppltunnel-server and ppltunnel-client during iperf3 transfer.

set -e

CONFIG="${1:?usage: measure_mem.sh <config> [direction] [duration]}"
DIR="${2:-forward}"
DUR="${3:-10}"

BUILD_DIR="${BUILD_DIR:-/tmp/modtunnel-hostbuild}"
MOD_DIR="${MOD_DIR:-$BUILD_DIR/tests/test_modules}"
SERVER="$BUILD_DIR/server/ppltunnel-server"
CLIENT="$BUILD_DIR/client/ppltunnel-client"
HOST="127.0.0.1"
PASS="testpass"

killall -9 ppltunnel-server ppltunnel-client iperf3 2>/dev/null || true
sleep 1

# Find free ports
free_port() {
  python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 0))
print(s.getsockname()[1])
s.close()
"
}

IPERF_PORT=$(free_port)
SVR_PORT=$(free_port)
CLI_PORT=$(free_port)

# Start iperf3 server
iperf3 -s -D -p "$IPERF_PORT" >/dev/null 2>&1

# Start tunnel server
"$SERVER" -l"$HOST:$SVR_PORT" -A"$PASS" -M"$MOD_DIR" -t2 >/dev/null 2>&1 &
SVR_PID=$!

# Wait for server
for i in $(seq 1 20); do
  ss -tln sport = "$SVR_PORT" 2>/dev/null | grep -q ":$SVR_PORT" && break
  sleep 0.1
done

# Start tunnel client
"$CLIENT" -L"$HOST:$CLI_PORT:$HOST:$IPERF_PORT" \
  -M"$MOD_DIR" -t2 \
  "$HOST:$SVR_PORT,$PASS;$CONFIG" >/dev/null 2>&1 &
CLI_PID=$!

# Wait for client
for i in $(seq 1 20); do
  ss -tln sport = "$CLI_PORT" 2>/dev/null | grep -q ":$CLI_PORT" && break
  sleep 0.1
done

# Build iperf3 args
IPERF_ARGS="-c $HOST -p $CLI_PORT -t $DUR"
[ "$DIR" = "reverse" ] && IPERF_ARGS="$IPERF_ARGS -R"
[ "$DIR" = "bidir" ] && IPERF_ARGS="$IPERF_ARGS --bidir"

# Start iperf3 in background with output to temp file
IPERF_OUT=$(mktemp)
iperf3 $IPERF_ARGS >"$IPERF_OUT" 2>&1 &
IPERF_PID=$!

sleep 1

echo "=== mem: $CONFIG dir=$DIR ==="
echo "sec   server(KB) client(KB)"
MAX_SVR=0
MAX_CLI=0
i=1
while kill -0 "$IPERF_PID" 2>/dev/null && [ $i -le $((DUR + 5)) ]; do
  SVR=$(ps -o rss= -p "$SVR_PID" 2>/dev/null | tr -d ' ' || echo 0)
  CLI=$(ps -o rss= -p "$CLI_PID" 2>/dev/null | tr -d ' ' || echo 0)
  printf "%-4s  %-10s  %s\n" "${i}s" "$SVR" "$CLI"
  [ "$SVR" -gt "$MAX_SVR" ] && MAX_SVR=$SVR
  [ "$CLI" -gt "$MAX_CLI" ] && MAX_CLI=$CLI
  sleep 1
  i=$((i + 1))
done

wait "$IPERF_PID" 2>/dev/null || true
echo "---"
echo "max server: $MAX_SVR KB ($((MAX_SVR / 1024)) MB)"
echo "max client: $MAX_CLI KB ($((MAX_CLI / 1024)) MB)"
echo ""
echo "iperf3 result:"
cat "$IPERF_OUT" | tail -8
rm -f "$IPERF_OUT"

kill "$SVR_PID" "$CLI_PID" 2>/dev/null || true
killall -9 ppltunnel-server ppltunnel-client iperf3 2>/dev/null || true
