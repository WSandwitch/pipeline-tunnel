#!/usr/bin/env python3
"""Legacy inline target test — broken under new protocol (sends raw data instead of MSG_CONNECT_REQ+MSG_DATA)."""
import sys, os, subprocess, socket, time, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_comprehensive import auth_and_modlist, msg, recv, killall, SERVER, HOST, PASS, APP

echo_data = []
def echo_server():
    es = socket.socket(); es.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    es.bind(("127.0.0.1", 19091)); es.listen(1); es.settimeout(10)
    try:
        c, _ = es.accept()
        d = c.recv(4096)
        echo_data.append(d)
        c.sendall(d)
        c.close()
    except: pass
    es.close()

def test_no_modules_inline():
    killall()
    svr = None
    try:
        svr = subprocess.Popen([SERVER, f"-l{HOST}:18091", f"-A{PASS}", "-Mtest_modules"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=APP)
        time.sleep(1.5)

        t = threading.Thread(target=echo_server, daemon=True); t.start()
        time.sleep(0.5)

        sock = socket.socket(); sock.settimeout(10)
        sock.connect((HOST, 18091))
        names = auth_and_modlist(sock)
        print(f"  [+] Modules: {names}")

        # Legacy inline target: include target in CHAIN_CREATE payload
        sock.sendall(msg(0x20, b"127.0.0.1:19091"))
        pkt = recv(sock)
        assert pkt and pkt[0]==0x21 and pkt[1][0]==0x01
        print("  [+] Inline tunnel ready")

        time.sleep(0.5)
        test_data = b"Hello inline tunnel!" * 20
        sock.sendall(test_data)
        time.sleep(2)

        sock.settimeout(3)
        total = b""
        try:
            while True:
                c = sock.recv(65536)
                if not c: break
                total += c
        except socket.timeout: pass

        assert total == test_data, f"Mismatch: {len(total)} != {len(test_data)}"
        print(f"  [+] SUCCESS: {len(total)} bytes echoed inline")
        sock.close()
        print("  [+] PASS: test_no_modules_inline")
    finally:
        if svr: svr.terminate(); svr.wait()

if __name__ == "__main__":
    test_no_modules_inline()
