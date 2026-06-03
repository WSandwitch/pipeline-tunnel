#!/usr/bin/env python3
"""
Integration test: server+client pair (black box).
- Tunnel mode: forward client data to TCP target
- Module chain mode: each available module, discovered dynamically
- No hardcoded module names or configs
"""
import socket, subprocess, time, os, sys, random, threading, tempfile

HOST = "127.0.0.1"
PASS = "testpass"
APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(os.path.dirname(APP), "build")
SERVER = os.path.join(BUILD, "server", "modtunnel-server")
CLIENT = os.path.join(BUILD, "client", "modtunnel-client")
MPATH = os.path.join(APP, "test_modules")

SHORT_COUNT = int(os.environ.get("INTEGRATION_SHORT", "50"))
LONG_COUNT = int(os.environ.get("INTEGRATION_LONG", "3"))
LONG_SIZE = int(os.environ.get("INTEGRATION_LONG_SIZE", str(256 * 1024)))
MCHAIN_SIZE = int(os.environ.get("INTEGRATION_MCHAIN_SIZE", "65536"))
BIDI_SIZE = int(os.environ.get("INTEGRATION_BIDI_SIZE", "262144"))
BLOCKING_SIZE = int(os.environ.get("INTEGRATION_BLOCKING_SIZE", "2097152"))
BLOCKING_CHUNK = int(os.environ.get("INTEGRATION_BLOCKING_CHUNK", "131072"))
TUNNEL_MIN_PCT = int(os.environ.get("INTEGRATION_MIN_PCT", "90"))


def _wait_port(port, timeout=5, listener=False):
    """Poll until port is ready.
    For listener ports (client): use ss (no connection established).
    For server ports: use TCP connect (harmless for server control port).
    """
    deadline = time.monotonic() + timeout
    hex_port = f":{port:04X}"
    while time.monotonic() < deadline:
        if listener:
            # Check LISTEN state without connecting (avoids triggering accept)
            try:
                r = subprocess.run(["ss", "-tln", f"sport = {port}"],
                                   capture_output=True, text=True, timeout=5)
                if f"127.0.0.1:{port}" in r.stdout or f"0.0.0.0:{port}" in r.stdout:
                    return
            except:
                pass
        else:
            try:
                s = socket.socket()
                s.settimeout(0.5)
                s.connect((HOST, port))
                s.close()
                return
            except:
                pass
        time.sleep(0.05)
    raise TimeoutError(f"port {port} not ready after {timeout}s")

def killall():
    subprocess.run(["killall", "-9", "modtunnel-server", "modtunnel-client"],
                   capture_output=True)
    time.sleep(0.3)


def discover_modules():
    r = subprocess.run([SERVER, "--module-list", f"-M{MPATH}"],
                       capture_output=True, text=True, cwd=APP)
    mods = []
    for line in r.stderr.split('\n'):
        if line.startswith("  "):
            name = line.strip().split()[0]
            mods.append(name)
    return mods


def short_http(cli_port, count):
    ok = 0
    for i in range(count):
        try:
            s = socket.socket()
            s.settimeout(10)
            s.connect((HOST, cli_port))
            s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            resp = b""
            while True:
                d = s.recv(65536)
                if not d: break
                resp += d
            s.close()
            if b"200 OK" in resp or b"200 ok" in resp:
                ok += 1
        except:
            pass
    return ok


def long_echo(cli_port, count, size):
    """Sequential echo test: client writes → tunnel → echo → client reads back."""
    ok = 0
    for _ in range(count):
        data = os.urandom(size)
        s = socket.socket()
        s.settimeout(30)
        try:
            s.connect((HOST, cli_port))
            s.sendall(data)
            total = b""
            while len(total) < len(data):
                d = s.recv(65536)
                if not d: break
                total += d
            if total == data:
                ok += 1
        except:
            pass
        finally:
            s.close()
    return ok


def blocking_echo(cli_port):
    """Blocking write (partial send) interleaved with read, 2MB data."""
    data = os.urandom(BLOCKING_SIZE)
    s = socket.socket()
    s.settimeout(30)
    try:
        s.connect((HOST, cli_port))
        pos = 0
        total = b""
        while pos < len(data) or len(total) < len(data):
            if pos < len(data):
                s.settimeout(0.05)
                try:
                    n = s.send(data[pos:pos + BLOCKING_CHUNK])
                    if n > 0:
                        pos += n
                except (socket.timeout, BlockingIOError):
                    pass
                finally:
                    s.settimeout(30)
            s.settimeout(0.05)
            try:
                while True:
                    d = s.recv(65536)
                    if not d: return False
                    total += d
            except (socket.timeout, BlockingIOError):
                pass
            finally:
                s.settimeout(30)
        while len(total) < len(data):
            d = s.recv(65536)
            if not d: break
            total += d
        return total == data
    except:
        return False
    finally:
        s.close()


def _recv_exact(sock, size):
    """Receive exactly `size` bytes from socket."""
    buf = b""
    while len(buf) < size:
        d = sock.recv(size - len(buf))
        if not d: return buf
        buf += d
    return buf


def long_bidi(cli_port, tgt_port, count, size):
    """Full-duplex test: parallel 4 threads per iteration, own connection per iteration."""
    ok = 0
    for _ in range(count):
        client_data = os.urandom(size)
        server_data = os.urandom(size)

        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((HOST, tgt_port))
        ls.listen(1)
        ls.settimeout(20)

        cconn = socket.socket()
        cconn.settimeout(10)
        try:
            cconn.connect((HOST, cli_port))
        except:
            ls.close(); cconn.close(); continue

        try:
            tconn, _ = ls.accept()
            tconn.settimeout(120)
        except:
            ls.close(); cconn.close(); continue
        ls.close()

        results = {}

        def client_writer():
            try: cconn.sendall(client_data)
            except: pass

        def target_reader():
            try:
                d = _recv_exact(tconn, len(client_data))
                if len(d) == len(client_data): results['tr'] = d
            except: pass

        def target_writer():
            try: tconn.sendall(server_data)
            except: pass

        def client_reader():
            try:
                d = _recv_exact(cconn, len(server_data))
                if len(d) == len(server_data): results['cr'] = d
            except: pass

        threads = [
            threading.Thread(target=client_writer, daemon=True),
            threading.Thread(target=target_reader, daemon=True),
            threading.Thread(target=target_writer, daemon=True),
            threading.Thread(target=client_reader, daemon=True),
        ]
        for t in threads: t.start()
        for t in threads: t.join(timeout=120)

        cconn.close()
        tconn.close()

        if results.get('tr') == client_data and results.get('cr') == server_data:
            ok += 1
    return ok


def _start_tunnel(svr_port, cli_port, tgt_port, chain_config=None, threads=1):
    """Start server+client pair, return (svr_proc, cli_proc)."""
    svr = subprocess.Popen([SERVER, f"-l{HOST}:{svr_port}", f"-A{PASS}",
                            f"-M{MPATH}", f"-t{threads}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           cwd=APP)
    _wait_port(svr_port)

    client_cmd = f"{HOST}:{svr_port},{PASS}"
    if chain_config:
        client_cmd += f";{chain_config}"
    cli = subprocess.Popen([CLIENT, f"-L{HOST}:{cli_port}:{HOST}:{tgt_port}",
                            f"-M{MPATH}", f"-t{threads}", client_cmd],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           cwd=APP)
    _wait_port(cli_port, listener=True)
    return svr, cli


def _stop_tunnel(svr, cli):
    cli.terminate(); cli.wait()
    svr.terminate(); svr.wait()


def run_tunnel_short_test():
    """Tunnel mode: short HTTP requests only."""
    tgt_port = random.randint(31000, 32000)
    svr_port = random.randint(32001, 33000)
    cli_port = random.randint(33001, 34000)

    httpd_dir = tempfile.mkdtemp()
    httpd = subprocess.Popen(["python3", "-m", "http.server", str(tgt_port),
                              "-d", httpd_dir],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_port(tgt_port)

    svr, cli = _start_tunnel(svr_port, cli_port, tgt_port)

    try:
        short_ok = short_http(cli_port, SHORT_COUNT)
        short_pct = short_ok * 100 // max(SHORT_COUNT, 1)
        print(f"  [tunnel] short={short_ok}/{SHORT_COUNT} ({short_pct}%)", flush=True)
        return short_pct >= TUNNEL_MIN_PCT
    finally:
        httpd.terminate(); httpd.wait(timeout=5)
        _stop_tunnel(svr, cli)


def run_tunnel_long_test():
    """Tunnel mode: long echo data (own echo target)."""
    tgt_port = random.randint(31000, 32000)
    svr_port = random.randint(32001, 33000)
    cli_port = random.randint(33001, 34000)

    echo_stop = threading.Event()
    echo_ready = threading.Event()
    def echo_acceptor():
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((HOST, tgt_port))
        ls.listen(5)
        echo_ready.set()
        while not echo_stop.is_set():
            ls.settimeout(1.0)
            try:
                conn, _ = ls.accept()
                conn.settimeout(30)
                t = threading.Thread(target=_echo_handler,
                                     args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except:
                break
        ls.close()

    def _echo_handler(conn):
        while True:
            try:
                d = conn.recv(65536)
                if not d: break
                conn.sendall(d)
            except:
                break
        conn.close()

    t = threading.Thread(target=echo_acceptor, daemon=True)
    t.start()
    echo_ready.wait()

    svr, cli = _start_tunnel(svr_port, cli_port, tgt_port)

    try:
        long_ok = long_echo(cli_port, LONG_COUNT, LONG_SIZE)
        long_pct = long_ok * 100 // max(LONG_COUNT, 1)
        print(f"  [tunnel] long={long_ok}/{LONG_COUNT} ({long_pct}%)", flush=True)
        return long_pct >= TUNNEL_MIN_PCT
    finally:
        echo_stop.set()
        _stop_tunnel(svr, cli)


def _long_bidi_once(cli_port, tgt_port, size):
    """Single bidi transfer: own tunnel instance, 4 parallel threads."""
    svr, cli = _start_tunnel(random.randint(32001, 33000), cli_port, tgt_port)
    try:
        client_data = os.urandom(size)
        server_data = os.urandom(size)

        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((HOST, tgt_port))
        ls.listen(1)
        ls.settimeout(20)

        cconn = socket.socket()
        cconn.settimeout(10)
        try:
            cconn.connect((HOST, cli_port))
        except:
            ls.close(); cconn.close(); return 0

        try:
            tconn, _ = ls.accept()
            tconn.settimeout(120)
        except:
            ls.close(); cconn.close(); return 0
        ls.close()

        results = {}

        def cw():
            try: cconn.sendall(client_data)
            except: pass

        def tr():
            try:
                d = _recv_exact(tconn, len(client_data))
                if len(d) == len(client_data): results['tr'] = d
            except: pass

        def tw():
            try: tconn.sendall(server_data)
            except: pass

        def cr():
            try:
                d = _recv_exact(cconn, len(server_data))
                if len(d) == len(server_data): results['cr'] = d
            except: pass

        threads = [threading.Thread(target=cw, daemon=True),
                   threading.Thread(target=tr, daemon=True),
                   threading.Thread(target=tw, daemon=True),
                   threading.Thread(target=cr, daemon=True)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=180)

        cconn.close()
        tconn.close()
        return 1 if results.get('tr') == client_data and results.get('cr') == server_data else 0
    finally:
        _stop_tunnel(svr, cli)


def run_tunnel_bidi_test():
    """Tunnel mode: parallel bidirectional data (fresh tunnel per iteration)."""
    ok = 0
    for i in range(LONG_COUNT):
        tgt_port = random.randint(31000, 32000)
        cli_port = random.randint(33001, 34000)
        result = _long_bidi_once(cli_port, tgt_port, BIDI_SIZE)
        ok += result
        print(f"  [tunnel] bidi iter {i}: {'OK' if result else 'FAIL'}", flush=True)
    bidi_pct = ok * 100 // max(LONG_COUNT, 1)
    print(f"  [tunnel] bidi={ok}/{LONG_COUNT} ({bidi_pct}%)", flush=True)
    return bidi_pct >= TUNNEL_MIN_PCT


def run_tunnel_blocking_test():
    """Tunnel mode: blocking write (partial send), interleaved read."""
    tgt_port = random.randint(31000, 32000)
    svr_port = random.randint(32001, 33000)
    cli_port = random.randint(33001, 34000)

    echo_stop = threading.Event()
    echo_ready = threading.Event()
    def echo_server():
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((HOST, tgt_port))
        ls.listen(5)
        echo_ready.set()
        while not echo_stop.is_set():
            ls.settimeout(1.0)
            try:
                conn, _ = ls.accept()
                conn.settimeout(30)
                t = threading.Thread(target=_echo_worker, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except:
                break
        ls.close()
    def _echo_worker(conn):
        while True:
            try:
                d = conn.recv(65536)
                if not d: break
                conn.sendall(d)
            except:
                break
        conn.close()
    t = threading.Thread(target=echo_server, daemon=True)
    t.start()
    echo_ready.wait()

    svr, cli = _start_tunnel(svr_port, cli_port, tgt_port)
    try:
        ok = blocking_echo(cli_port)
        print(f"  [tunnel] blocking={'OK' if ok else 'FAIL'}", flush=True)
        return ok
    finally:
        echo_stop.set()
        _stop_tunnel(svr, cli)


def run_tunnel_test():
    """Tunnel mode: short HTTP + long echo + blocking + bidi."""
    short_ok = run_tunnel_short_test()
    long_ok = run_tunnel_long_test()
    blocking_ok = run_tunnel_blocking_test()
    bidi_ok = run_tunnel_bidi_test()
    return short_ok and long_ok and blocking_ok and bidi_ok


def run_module_chain_test(label, chain_config):
    tgt_port = random.randint(31000, 32000)
    svr_port = random.randint(32001, 33000)
    cli_port = random.randint(33001, 34000)

    echo_ready = threading.Event()
    echo_stop = threading.Event()
    def echo_server():
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((HOST, tgt_port))
        ls.listen(1)
        echo_ready.set()
        ls.settimeout(1.0)
        while not echo_stop.is_set():
            try:
                conn, _ = ls.accept()
                conn.settimeout(20)
                while True:
                    try:
                        d = conn.recv(65536)
                        if not d: break
                        conn.sendall(d)
                    except: break
                conn.close()
            except socket.timeout:
                continue
            except:
                break
        ls.close()
    t = threading.Thread(target=echo_server, daemon=True)
    t.start()
    echo_ready.wait()

    svr, cli = _start_tunnel(svr_port, cli_port, tgt_port, chain_config)

    try:
        data = os.urandom(MCHAIN_SIZE)
        s = socket.socket()
        s.settimeout(15)
        s.connect((HOST, cli_port))
        s.sendall(data)
        total = b""
        while len(total) < len(data):
            d = s.recv(65536)
            if not d: break
            total += d
        s.close()
        ok = (total == data)
        print(f"  [{label}] recv={len(total)}/{MCHAIN_SIZE} ok={ok}", flush=True)
        return ok
    except Exception as e:
        print(f"  [{label}] exception: {e}", flush=True)
        return False
    finally:
        echo_stop.set()
        _stop_tunnel(svr, cli)


if __name__ == "__main__":
    killall()
    mods = discover_modules()
    print(f"Modules: {mods}", flush=True)

    results = {}

    print("\n--- Tunnel mode (no modules) ---", flush=True)
    tk = run_tunnel_test()
    print(f"  tunnel: {'PASS' if tk else 'FAIL'}", flush=True)
    results['tunnel'] = tk

    if mods:
        print(f"\n--- Module chain mode ({len(mods)} modules) ---", flush=True)
        for m in mods:
            killall()
            ok = run_module_chain_test(f"mod_{m}", m)
            print(f"  mod_{m}: {'PASS' if ok else 'FAIL'}", flush=True)
            results[f'mod_{m}'] = ok
    else:
        print("\n  No modules found, skipping module tests.", flush=True)

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} passed", flush=True)
    all_ok = all(results.values())
    print(f"{'ALL PASS' if all_ok else 'SOME FAILED'}", flush=True)
    sys.exit(0 if all_ok else 1)
