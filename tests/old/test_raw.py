#!/usr/bin/env python3
"""Send raw auth packets, print raw server responses (self-contained)."""
import socket, struct, hashlib, subprocess, time, os, sys

HOST, PORT = "127.0.0.1", 18084
PASS = "testpass"
APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(APP, "build", "server", "ppltunnel-server")

def msg(t, p=b""):
    return struct.pack(">HB", len(p), t) + p

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

subprocess.run(["killall", "-9", "ppltunnel-server"], capture_output=True)
time.sleep(0.5)

svr = subprocess.Popen([SERVER, f"-l{HOST}:{PORT}", f"-A{PASS}", "-vvv"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)

sock = socket.socket()
sock.settimeout(5)
sock.connect((HOST, PORT))
print("[+] Connected")

data = sock.recv(4096)
print(f"[+] Initial data ({len(data)} bytes): {data.hex()}")
assert len(data) >= 3

sz = struct.unpack(">H", data[:2])[0]
t = data[2]
c1 = data[3:3+sz].decode()
print(f"[+] Challenge: type={t} size={sz}")

resp = sha256(c1 + PASS)
sock.sendall(msg(0x02, resp.encode()))
print(f"[+] Auth1 resp sent")

data = sock.recv(4096)
print(f"[+] Got ({len(data)} bytes): {data.hex()}")

sz = struct.unpack(">H", data[:2])[0]
t = data[2]
ok = data[3:3+sz]
print(f"[+] Auth1 OK: type={t} result={ok.hex()}")

c2 = "challenge2"
sock.sendall(msg(0x01, c2.encode()))
print(f"[+] Auth2 challenge sent")

data = sock.recv(4096)
print(f"[+] Got ({len(data)} bytes): {data.hex()}")

sz = struct.unpack(">H", data[:2])[0]
t = data[2]
resp2 = data[3:3+sz].decode()
print(f"[+] Auth2 response: type={t} resp={resp2[:20]}...")
assert resp2 == sha256(c2 + PASS), "Auth2 failed"

sock.sendall(msg(0x03, b"\x01"))
print(f"[+] Auth complete, sending module list req...")

sock.sendall(msg(0x10))
print(f"[+] MODULE_LIST_REQ sent, waiting for response...")

data = sock.recv(4096)
print(f"[+] Got ({len(data)} bytes): {data.hex()}")

sock.close()
svr.terminate()
svr.wait()
print("[+] Raw test passed!")
