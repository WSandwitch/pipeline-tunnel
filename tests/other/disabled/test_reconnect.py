#!/usr/bin/env python3
"""Test reconnection: client disconnects, reconnects with same session_id, chain resumes."""
import socket, struct, hashlib, subprocess, time, os, sys, random

HOST, PORT = "127.0.0.1", 18080
PASS = "testpass"
APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(APP, "build", "server", "ppltunnel-server")

def write_varint(val):
    buf = b""
    while val > 0x7F:
        buf += bytes([(val & 0x7F) | 0x80])
        val >>= 7
    buf += bytes([val & 0x7F])
    return buf

def read_varint(s):
    val = 0
    shift = 0
    while True:
        c = s.recv(1)
        if not c: return None
        b = c[0]
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val
        shift += 7

def msg(t, p=b""):
    return write_varint(t) + write_varint(len(p)) + p
def recv(s, timeout=5):
    s.settimeout(timeout)
    t = read_varint(s)
    if t is None: return None
    sz = read_varint(s)
    if sz is None: return None
    p = b""
    while len(p) < sz:
        c = s.recv(sz - len(p))
        if not c: return None
        p += c
    return t, p
def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

def do_auth(sock):
    pkt = recv(sock); assert pkt and pkt[0]==0x01
    sock.sendall(msg(0x02, sha256(pkt[1].decode()+PASS).encode()))
    pkt = recv(sock); assert pkt and pkt[0]==0x03 and pkt[1]==b"\x01"
    c2 = f"c{random.randint(0,999999)}"
    sock.sendall(msg(0x01, c2.encode()))
    pkt = recv(sock); assert pkt and pkt[0]==0x02 and pkt[1].decode()==sha256(c2+PASS)
    sock.sendall(msg(0x03, b"\x01"))
    print("[+] Auth OK")

def do_module_list(sock):
    sock.sendall(msg(0x10))
    pkt = recv(sock); assert pkt and pkt[0]==0x11
    print(f"[+] Module list: {pkt[1][0]} modules")

def do_send_recv(sock, data, label="data"):
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
        print(f"[+] {label}: {len(got)} bytes match")
    else:
        print(f"[!] FAIL {label}: {len(got)} vs {len(data)}")
        sys.exit(1)

subprocess.run(["killall", "-9", "ppltunnel-server"], capture_output=True)
time.sleep(0.5)

with open("/tmp/srv_reconnect.log", "w") as log:
    svr = subprocess.Popen([SERVER, f"-l{HOST}:{PORT}", f"-A{PASS}", "-Mtest_modules", "-vvv"],
                           stdout=log, stderr=log, cwd=APP)
time.sleep(1.5)

# --- First connection ---
print("=== First connection ===")
sock1 = socket.socket(); sock1.settimeout(10)
sock1.connect((HOST, PORT))
do_auth(sock1)
do_module_list(sock1)

# Passthrough chain
sock1.sendall(msg(0x20, b""))
pkt = recv(sock1); assert pkt and pkt[0]==0x21 and pkt[1][0]==0x01
sid = int.from_bytes(pkt[1][1:9], 'little')
print(f"[+] Chain ready! session={sid:016x}")

# Send/receive before disconnect
data1 = b"\xaa" + os.urandom(100) + b"\xbb"
do_send_recv(sock1, data1, "pre-disconnect")

# --- Disconnect ---
print("=== Disconnect ===")
sock1.close()
time.sleep(1.0)

# --- Second connection (reconnect) ---
print("=== Reconnect ===")
sock2 = socket.socket(); sock2.settimeout(10)
sock2.connect((HOST, PORT))
do_auth(sock2)

# Send MSG_RECONNECT with old session_id
sid_bytes = struct.pack("<Q", sid)
sock2.sendall(msg(0x05, sid_bytes))
pkt = recv(sock2)
assert pkt and pkt[0]==0x03, f"Expected MSG_AUTH_OK, got type={pkt[0] if pkt else None}"
assert pkt[1]==b"\x01", f"Reconnect failed, got code={pkt[1][0]}"
print(f"[+] Reconnect OK, session={sid:016x} resumed")

# Send/receive after reconnect
data2 = b"\xcc" + os.urandom(100) + b"\xdd"
do_send_recv(sock2, data2, "post-reconnect")

sock2.close()
svr.terminate(); svr.wait()
print("[+] Reconnection test passed!")
