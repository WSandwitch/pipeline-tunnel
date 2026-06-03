#!/usr/bin/env python3
"""Test TCP forwarding: client → tunnel-server → target TCP service."""
import socket, struct, hashlib, subprocess, time, os, sys, random, threading

HOST, PORT = "127.0.0.1", 18080
PASS = "testpass"
APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(APP, "build", "server", "modtunnel-server")
TARGET_PORT = 19999

def msg(t, p=b""):
    return struct.pack(">HB", len(p), t) + p
def recv(s, timeout=5):
    s.settimeout(timeout)
    h = b""
    while len(h) < 3:
        c = s.recv(3 - len(h))
        if not c: return None
        h += c
    sz = struct.unpack(">H", h[:2])[0]
    t = h[2]
    p = b""
    while len(p) < sz:
        c = s.recv(sz - len(p))
        if not c: return None
        p += c
    return t, p
def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

target_recv_data = b""
echo_ready = threading.Event()
def echo_target():
    global target_recv_data
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", TARGET_PORT))
    srv.listen(1)
    echo_ready.set()
    conn, addr = srv.accept()
    conn.settimeout(2)
    while True:
        try:
            c = conn.recv(4096)
            if not c: break
            target_recv_data += c
            conn.sendall(c)
        except socket.timeout:
            continue
        except: break
    conn.close(); srv.close()

t = threading.Thread(target=echo_target, daemon=True)
t.start()
echo_ready.wait(timeout=3)

subprocess.run(["killall", "-9", "modtunnel-server"], capture_output=True)
time.sleep(0.5)
with open("/tmp/srv_tunnel.log", "w") as log:
    svr = subprocess.Popen([SERVER, f"-l{HOST}:{PORT}", f"-A{PASS}", "-Mtest_modules", "-vvv"],
                           stdout=log, stderr=log, cwd=APP)
time.sleep(1.5)

sock = socket.socket(); sock.settimeout(10)
sock.connect((HOST, PORT))

pkt = recv(sock); assert pkt and pkt[0]==0x01
sock.sendall(msg(0x02, sha256(pkt[1].decode()+PASS).encode()))
pkt = recv(sock); assert pkt and pkt[0]==0x03 and pkt[1]==b"\x01"
print("[+] Auth1 OK")

c2 = f"c{random.randint(0,999999)}"
sock.sendall(msg(0x01, c2.encode()))
pkt = recv(sock); assert pkt and pkt[0]==0x02 and pkt[1].decode()==sha256(c2+PASS)
sock.sendall(msg(0x03, b"\x01"))
print("[+] Auth2 OK")

sock.sendall(msg(0x10))
pkt = recv(sock); assert pkt and pkt[0]==0x11
print(f"[+] Module list: {pkt[1][0]} modules")

target_str = f"127.0.0.1:{TARGET_PORT}"
sock.sendall(msg(0x20, target_str.encode()))
pkt = recv(sock); assert pkt and pkt[0]==0x21 and pkt[1][0]==0x01
sid = int.from_bytes(pkt[1][1:9], 'little')
print(f"[+] Tunnel ready! session={sid:016x}")

data = b"Hello through the tunnel! " + os.urandom(50)
sock.sendall(data)

got = b""
deadline = time.time() + 5
while len(got) < len(data) and time.time() < deadline:
    try:
        sock.settimeout(0.5)
        c = sock.recv(65536)
        if not c: break
        got += c
    except socket.timeout: pass

if got == data:
    print(f"[+] SUCCESS: {len(got)} bytes echoed through tunnel!")
else:
    print(f"[!] FAIL: got {len(got)} vs {len(data)}")
    with open("/tmp/srv_tunnel.log") as f:
        for line in f.read().splitlines()[-10:]:
            print(f"  > {line}")
    sys.exit(1)

sock.close(); svr.terminate(); svr.wait()
print("[+] TCP forwarding tunnel test passed!")
