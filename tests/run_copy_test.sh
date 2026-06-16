#!/bin/sh
set -e

BUILD=/app/build
MODS=$BUILD/tests/test_modules

cleanup() {
  kill $ECHO_PID $SVR_PID $CLI_PID 2>/dev/null || true
  wait
}
trap cleanup EXIT

python3 -c "
import socket, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 7777))
s.listen(5)
while True:
    c, _ = s.accept()
    def echo(conn):
        while True:
            d = conn.recv(4096)
            if not d: break
            conn.sendall(d)
        conn.close()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
" &
ECHO_PID=$!
sleep 0.3

"$BUILD/server/ppltunnel-server" -l0.0.0.0:32797 -Atestpass -M"$MODS" -t2 2>&1 &
SVR_PID=$!
sleep 0.3

"$BUILD/client/ppltunnel-client" \
  -L0.0.0.0:33797:127.0.0.1:7777 \
  -M"$MODS" -t2 \
  "127.0.0.1:32797,testpass;copy|trace" \
  2>&1 &
CLI_PID=$!
sleep 0.5

echo "=== copy test ===" 2>&1

python3 -c "
import socket
s = socket.socket()
s.settimeout(5)
s.connect(('127.0.0.1', 33797))
body = b'x' * 1000
s.sendall(body)
resp = s.recv(4096)
print('received', len(resp), 'bytes')
print('match:', resp == body)
s.close()
" 2>&1

echo "--- exit: $? ---" 2>&1
sleep 1
