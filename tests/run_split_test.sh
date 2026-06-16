#!/bin/sh
set -e

BUILD=/app/build
MODS=$BUILD/tests/test_modules
TRACE=/tmp/trace.log
> "$TRACE"

cleanup() {
  kill $ECHO_PID $SVR_PID $CLI_PID 2>/dev/null || true
  wait
}
trap cleanup EXIT

# Start python echo server
python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7777))
s.listen(5)
while True:
    c, _ = s.accept()
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
" &
ECHO_PID=$!
sleep 0.3

# Start tunnel server
"$BUILD/server/ppltunnel-server" -l0.0.0.0:32797 -Atestpass -M"$MODS" -t2 2>&1 &
SVR_PID=$!
sleep 0.3

# Start tunnel client
"$BUILD/client/ppltunnel-client" \
  -L0.0.0.0:33797:127.0.0.1:7777 \
  -M"$MODS" -t2 \
  "127.0.0.1:32797,testpass;split|n:3,trace,s:512" \
  2>&1 &
CLI_PID=$!
sleep 0.5

echo "=== split test ===" 2>&1

# Send ~1024 bytes, check response
python3 -c "
import socket
s = socket.socket()
s.settimeout(5)
s.connect(('127.0.0.1', 33797))
body = b'x' * 1000
s.sendall(body)
resp = s.recv(4096)
print('received', len(resp), 'bytes')
print('hex:', resp[:32].hex())
s.close()
" 2>&1

echo "--- exit: $? ---" 2>&1
sleep 1
