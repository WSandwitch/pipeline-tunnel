#!/usr/bin/env python3
"""Test tunnel without processing modules (pure passthrough)."""
import socket, struct, hashlib, subprocess, time, os, sys, random

HOST, PORT = "127.0.0.1", 18080
PASS = "testpass"
APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(APP, "build", "server", "modtunnel-server")

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

subprocess.run(["killall", "-9", "modtunnel-server"], capture_output=True)
time.sleep(0.5)

with open("/tmp/srv_passthrough.log", "w") as log:
    svr = subprocess.Popen([SERVER, f"-l{HOST}:{PORT}", f"-A{PASS}", "-Mtest_modules", "-vvv"],
                           stdout=log, stderr=log, cwd=APP)
time.sleep(1.5)

sock = socket.socket(); sock.settimeout(10)
sock.connect((HOST, PORT))

# --- Auth ---
pkt = recv(sock); assert pkt and pkt[0]==0x01
sock.sendall(msg(0x02, sha256(pkt[1].decode()+PASS).encode()))
pkt = recv(sock); assert pkt and pkt[0]==0x03 and pkt[1]==b"\x01"
print("[+] Auth1 OK")

c2 = f"c{random.randint(0,999999)}"
sock.sendall(msg(0x01, c2.encode()))
pkt = recv(sock); assert pkt and pkt[0]==0x02 and pkt[1].decode()==sha256(c2+PASS)
sock.sendall(msg(0x03, b"\x01"))
print("[+] Auth2 OK")

# --- Module list (required for state transition) ---
sock.sendall(msg(0x10))
pkt = recv(sock); assert pkt and pkt[0]==0x11
count = pkt[1][0]
print(f"[+] Module list: {count} modules")

# --- Chain create with EMPTY payload (0 modules → passthrough) ---
sock.sendall(msg(0x20, b""))  # empty payload = 0 modules
pkt = recv(sock); assert pkt and pkt[0]==0x21 and pkt[1][0]==0x01
sid = int.from_bytes(pkt[1][1:9], 'little')
print(f"[+] Passthrough chain ready! session={sid:016x}")

# --- Send raw data ---
data = b"\x00" + os.urandom(100) + b"\xff"
sock.sendall(data)
print(f"[+] Sent {len(data)} bytes (hex: {data.hex()})")

# Read echo
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
    print(f"[+] SUCCESS: {len(got)} bytes echo'd through passthrough!")
    print(f"    hex: {got.hex()}")
else:
    print(f"[!] FAIL: {len(got)} vs {len(data)}")
    with open("/tmp/srv_passthrough.log") as f:
        for line in f.read().splitlines()[-15:]:
            print(f"  > {line}")
    sys.exit(1)

sock.close()
svr.terminate(); svr.wait()
print("[+] Passthrough tunnel test passed!")
