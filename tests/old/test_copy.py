#!/usr/bin/env python3
"""Test copy module chain (echo behavior through copy)."""
import socket, struct, hashlib, subprocess, time, os, sys, random

HOST, PORT = "127.0.0.1", 18080
PASS = "testpass"
APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(APP, "build", "server", "ppltunnel-server")

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

subprocess.run(["killall", "-9", "ppltunnel-server"], capture_output=True)
time.sleep(0.5)

with open("/tmp/srv_copy.log", "w") as log:
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

sock.sendall(msg(0x10)); pkt = recv(sock); assert pkt and pkt[0]==0x11
count = pkt[1][0]; pos = 1
names = []
for i in range(count):
    nl = pkt[1][pos]; pos += 1
    names.append(pkt[1][pos:pos+nl].decode()); pos += nl
print(f"[+] Module list: {names}")

try:
    copy_idx = names.index("copy")
except ValueError:
    print("[!] copy module not found"); sys.exit(1)

# Chain with copy module (index copy_idx, no config)
sock.sendall(msg(0x20, struct.pack("BB", copy_idx, 0)))
pkt = recv(sock); assert pkt and pkt[0]==0x21 and pkt[1][0]==0x01
sid = int.from_bytes(pkt[1][1:9], 'little')
print(f"[+] Copy chain ready! session={sid:016x}")

data = b"Hello Copy! " * 30
sock.sendall(data)

got = b""
deadline = time.time() + 5
while len(got) < len(data) and time.time() < deadline:
    try:
        sock.settimeout(0.5)
        c = sock.recv(65536)
        if not c: break
        got += c
    except socket.timeout:
        pass

if got == data:
    print(f"[+] SUCCESS: {len(got)} bytes through copy module!")
else:
    print(f"[!] FAIL: got {len(got)} vs {len(data)}")
    with open("/tmp/srv_copy.log") as f:
        for line in f.read().splitlines()[-10:]:
            print(f"  > {line}")
    sys.exit(1)

sock.close(); svr.terminate(); svr.wait()
print("[+] Copy module test passed!")
