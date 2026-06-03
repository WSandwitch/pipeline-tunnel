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
MPATH = os.path.join(APP, "tests", "test_modules")

SHORT_COUNT = int(os.environ.get("INTEGRATION_SHORT", "50"))
LONG_COUNT = int(os.environ.get("INTEGRATION_LONG", "3"))
LONG_SIZE = int(os.environ.get("INTEGRATION_LONG_SIZE", str(256 * 1024)))
MCHAIN_SIZE = int(os.environ.get("INTEGRATION_MCHAIN_SIZE", "65536"))
BIDI_SIZE = int(os.environ.get("INTEGRATION_BIDI_SIZE", "262144"))
BLOCKING_SIZE = int(os.environ.get("INTEGRATION_BLOCKING_SIZE", "2097152"))
BLOCKING_CHUNK = int(os.environ.get("INTEGRATION_BLOCKING_CHUNK", "131072"))
TUNNEL_MIN_PCT = int(os.environ.get("INTEGRATION_MIN_PCT", "90"))
TEST_TIMEOUT = int(os.environ.get("INTEGRATION_TIMEOUT", "120"))
PER_TEST_TIMEOUT = int(os.environ.get("INTEGRATION_PER_TEST_TIMEOUT", str(TEST_TIMEOUT)))
BENCHMARK_TOTAL = int(os.environ.get("INTEGRATION_BENCHMARK_TOTAL", str(64 * 1024 * 1024)))
BENCHMARK_CHUNK = int(os.environ.get("INTEGRATION_BENCHMARK_CHUNK", str(256 * 1024)))


def _kill(proc):
    """Safely kill a subprocess: SIGTERM → wait 3s → SIGKILL."""
    if not proc or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

def killall():
    """Kill all tunnel processes. No sleep."""
    subprocess.run(["killall", "-9", "modtunnel-server", "modtunnel-client"],
                   capture_output=True, timeout=5)

def _wait_port_listen(port, timeout=5):
    """Wait until a process is LISTENing on port (using ss). Faster than connect()."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(["ss", "-tln", f"sport = {port}"],
                               capture_output=True, text=True, timeout=5)
            out = r.stdout
            if f"127.0.0.1:{port}" in out or f"0.0.0.0:{port}" in out:
                return
        except:
            pass
        time.sleep(0.05)
    raise TimeoutError(f"port {port} not ready after {timeout}s")


def _find_free_port(low=31000, high=34000):
    """Return a free port in [low, high] by trying to bind()."""
    for _ in range(50):
        port = random.randint(low, high)
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", port))
            s.close()
            return port
        except OSError:
            continue
    raise RuntimeError("no free port found")

MODULE_CONF_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "module_conf")


def discover_modules():
    r = subprocess.run([SERVER, "--module-list", f"-M{MPATH}"],
                       capture_output=True, text=True, cwd=APP)
    mods = []
    for line in r.stderr.split('\n'):
        if line.startswith("  "):
            name = line.strip().split()[0]
            mods.append(name)
    return mods


def read_module_configs(module_name):
    """Read config list for a module from module_conf/{module}.cfg.list.
    Returns list of config strings (empty if no config file found).
    Config is from line start to first space, '#' or end of line.
    Empty lines and lines starting with '#' are skipped.
    """
    path = os.path.join(MODULE_CONF_DIR, f"{module_name}.cfg.list")
    if not os.path.exists(path):
        return []
    configs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Strip from first space or #
            for sep in (' ', '#'):
                idx = line.find(sep)
                if idx >= 0:
                    line = line[:idx]
            if line:
                configs.append(line)
    return configs


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


def _bidi_worker(sock, data, results, key):
    """One direction of blocking bidi: partial send + interleaved recv."""
    sock.settimeout(30)
    pos = 0
    total = b""
    try:
        while pos < len(data):
            sock.settimeout(0.05)
            try:
                n = sock.send(data[pos:pos + BLOCKING_CHUNK])
                if n > 0:
                    pos += n
            except (socket.timeout, BlockingIOError):
                pass
            sock.settimeout(0.05)
            try:
                while True:
                    d = sock.recv(65536)
                    if not d:
                        results[key] = False; return
                    total += d
            except (socket.timeout, BlockingIOError):
                pass
        # All data sent — blocking recv; no more 50ms spin
        sock.settimeout(120)
        while len(total) < len(data):
            d = sock.recv(65536)
            if not d:
                results[key] = False; return
            total += d
        results[key] = (total == data)
    except:
        results[key] = False


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


def _thread_arg(threads):
    """Return '-t' list item: '-t' alone for auto (0), or ['-t', str(N)] otherwise."""
    if threads == 0:
        return ["-t"]
    return ["-t", str(threads)]


def _start_tunnel(svr_port, cli_port, tgt_port, chain_config=None, threads=1):
    """Start server+client pair, return (svr_proc, cli_proc).
    Retries with new ports on first failure.
    Returns (svr_proc, cli_proc, svr_port, cli_port).
    """
    for attempt in range(3):
        if attempt > 0:
            svr_port = _find_free_port(32001, 33000)
            cli_port = _find_free_port(33001, 34000)

        svr = subprocess.Popen([SERVER, f"-l{HOST}:{svr_port}", f"-A{PASS}",
                                f"-M{MPATH}"] + _thread_arg(threads),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               cwd=APP)
        try:
            _wait_port_listen(svr_port)
        except TimeoutError:
            _kill(svr)
            continue

        cli_args = [CLIENT, f"-L{HOST}:{cli_port}:{HOST}:{tgt_port}",
                    f"-M{MPATH}",
                    f"{HOST}:{svr_port},{PASS}"
                    + (f";{chain_config}" if chain_config else "")]
        # Put -t after positional to avoid it eating chain_config arg
        cli_args += _thread_arg(threads)
        cli = subprocess.Popen(cli_args,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               cwd=APP)
        try:
            _wait_port_listen(cli_port)
            return svr, cli, svr_port, cli_port
        except TimeoutError:
            _kill(cli)
            _kill(svr)
            continue

    raise RuntimeError(f"cannot start tunnel after 3 attempts")


def _stop_tunnel(svr, cli):
    _kill(cli)
    _kill(svr)


def run_tunnel_short_test(chain_config=None, threads=1):
    """Tunnel mode: short HTTP requests only."""
    label = chain_config or "tunnel"
    if threads:
        label += f" t{threads}"
    min_pct = 100 if chain_config else TUNNEL_MIN_PCT
    tgt_port = _find_free_port(31000, 32000)

    httpd_dir = tempfile.mkdtemp()
    httpd = subprocess.Popen(["python3", "-m", "http.server", str(tgt_port),
                              "-d", httpd_dir],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_port_listen(tgt_port)
        svr, cli, _, cli_port = _start_tunnel(
            _find_free_port(32001, 33000), _find_free_port(33001, 34000),
            tgt_port, chain_config, threads=threads)
    except:
        _kill(httpd)
        raise

    try:
        short_ok = short_http(cli_port, SHORT_COUNT)
        short_pct = short_ok * 100 // max(SHORT_COUNT, 1)
        print(f"  [{label}] short={short_ok}/{SHORT_COUNT} ({short_pct}%)", flush=True)
        return short_pct >= min_pct
    finally:
        _kill(httpd)
        _stop_tunnel(svr, cli)


def run_tunnel_long_test(chain_config=None, threads=1):
    """Tunnel mode: long echo data (own echo target)."""
    label = chain_config or "tunnel"
    min_pct = 100 if chain_config else TUNNEL_MIN_PCT
    tgt_port = _find_free_port(31000, 32000)

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

    try:
        svr, cli, _, cli_port = _start_tunnel(
            _find_free_port(32001, 33000), _find_free_port(33001, 34000),
            tgt_port, chain_config, threads=threads)
    except:
        echo_stop.set()
        raise

    try:
        long_ok = long_echo(cli_port, LONG_COUNT, LONG_SIZE)
        long_pct = long_ok * 100 // max(LONG_COUNT, 1)
        print(f"  [{label}] long={long_ok}/{LONG_COUNT} ({long_pct}%)", flush=True)
        return long_pct >= min_pct
    finally:
        echo_stop.set()
        _stop_tunnel(svr, cli)


def _long_bidi_once(tgt_port, size, chain_config=None, threads=1):
    """Single bidi transfer: own tunnel instance, 4 parallel threads."""
    try:
        svr, cli, _, cli_port = _start_tunnel(
            _find_free_port(32001, 33000), _find_free_port(33001, 34000),
            tgt_port, chain_config, threads=threads)
    except:
        return 0

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


def run_tunnel_bidi_test(chain_config=None, threads=1):
    """Tunnel mode: parallel bidirectional data (fresh tunnel per iteration)."""
    label = chain_config or "tunnel"
    ok = 0
    for i in range(LONG_COUNT):
        tgt_port = _find_free_port(31000, 32000)
        result = _long_bidi_once(tgt_port, BIDI_SIZE, chain_config, threads=threads)
        ok += result
        print(f"  [{label}] bidi iter {i}: {'OK' if result else 'FAIL'}", flush=True)
    bidi_pct = ok * 100 // max(LONG_COUNT, 1)
    print(f"  [{label}] bidi={ok}/{LONG_COUNT} ({bidi_pct}%)", flush=True)
    return bidi_pct >= TUNNEL_MIN_PCT


def run_tunnel_blocking_test(chain_config=None, threads=1):
    """Tunnel mode: blocking write (partial send), interleaved read."""
    label = chain_config or "tunnel"
    tgt_port = _find_free_port(31000, 32000)

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

    try:
        svr, cli, _, cli_port = _start_tunnel(
            _find_free_port(32001, 33000), _find_free_port(33001, 34000),
            tgt_port, chain_config, threads=threads)
    except:
        echo_stop.set()
        raise

    try:
        ok = blocking_echo(cli_port)
        print(f"  [{label}] blocking={'OK' if ok else 'FAIL'}", flush=True)
        return ok
    finally:
        echo_stop.set()
        _stop_tunnel(svr, cli)


def run_tunnel_blocking_bidi_test(chain_config=None, threads=1):
    """Blocking bidi: 2 directions in parallel, partial send + interleaved recv."""
    label = chain_config or "tunnel"
    tgt_port = _find_free_port(31000, 32000)

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
                t = threading.Thread(target=_echo_inner, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except:
                break
        ls.close()
    def _echo_inner(conn):
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

    try:
        svr, cli, _, cli_port = _start_tunnel(
            _find_free_port(32001, 33000), _find_free_port(33001, 34000),
            tgt_port, chain_config, threads=threads)
    except:
        echo_stop.set()
        raise

    try:
        data0 = os.urandom(BLOCKING_SIZE)
        data1 = os.urandom(BLOCKING_SIZE)

        s0 = socket.socket()
        s0.settimeout(10)
        s0.connect((HOST, cli_port))

        s1 = socket.socket()
        s1.settimeout(10)
        s1.connect((HOST, cli_port))

        results = {}

        t0 = threading.Thread(target=_bidi_worker, args=(s0, data0, results, 'a'), daemon=True)
        t1 = threading.Thread(target=_bidi_worker, args=(s1, data1, results, 'b'), daemon=True)
        t0.start()
        t1.start()
        t0.join(timeout=120)
        t1.join(timeout=120)

        s0.close()
        s1.close()

        ok = results.get('a') and results.get('b')
        print(f"  [{label}] blocking_bidi={'OK' if ok else 'FAIL'}", flush=True)
        return ok
    finally:
        echo_stop.set()
        _stop_tunnel(svr, cli)


def run_tunnel_test(chain_config=None, threads=1):
    """Tunnel mode: short HTTP + long echo + blocking + bidi + blocking_bidi."""
    ok = True
    for name, fn in [("short", run_tunnel_short_test),
                     ("long", run_tunnel_long_test),
                     ("blocking", run_tunnel_blocking_test),
                     ("blocking_bidi", run_tunnel_blocking_bidi_test),
                     ("bidi", run_tunnel_bidi_test)]:
        if not ok:
            break
        try:
            ok = fn(chain_config, threads=threads)
        except:
            ok = False
        killall()
    return ok


def run_tunnel_test_threads(chain_config=None, thread_list=None):
    """Run all tunnel tests with each thread count in thread_list.
    thread_list: iterable of ints (0 = auto). Default: [1,2,3,4,8,0].
    Returns dict {threads: ok_bool}.
    """
    if thread_list is None:
        thread_list = [1, 2, 3, 4, 8, 0]
    results = {}
    for tc in thread_list:
        label = f"t{tc}" if tc else "tauto"
        killall()
        print(f"\n--- threads={label} ---", flush=True)
        t0 = time.time()
        try:
            ok = run_tunnel_test(chain_config, threads=tc)
        except:
            ok = False
        elapsed = time.time() - t0
        print(f"  threads={label}: {'PASS' if ok else 'FAIL'} ({elapsed:.1f}s)", flush=True)
        results[tc] = ok
        if not ok:
            break
    return results


class Task:
    """Runs all 5 tunnel subtests for a given config and worker count."""

    def test(self, workers=1, config=None):
        """Run all 5 subtests. Returns True if all pass."""
        return run_tunnel_test(chain_config=config, threads=workers)

    def benchmark(self, workers=1, config=None):
        """Measure throughput: send BENCHMARK_TOTAL bytes in BENCHMARK_CHUNK chunks.
        Returns (ok, mbps, elapsed_sec)."""
        tgt_port = _find_free_port(31000, 32000)
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
                    conn.settimeout(60)
                    t = threading.Thread(target=_echo_inner, args=(conn,), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except:
                    break
            ls.close()
        def _echo_inner(conn):
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

        try:
            svr, cli, _, cli_port = _start_tunnel(
                _find_free_port(32001, 33000), _find_free_port(33001, 34000),
                tgt_port, config, threads=workers)
        except:
            echo_stop.set()
            return (False, 0.0, 0.0)

        chunk = BENCHMARK_CHUNK
        nchunks = max(1, BENCHMARK_TOTAL // chunk)
        try:
            data = os.urandom(chunk)
            s = socket.socket()
            s.settimeout(60)
            s.connect((HOST, cli_port))
            t0 = time.time()
            for _ in range(nchunks):
                s.sendall(data)
                resp = b""
                while len(resp) < len(data):
                    d = s.recv(65536)
                    if not d: break
                    resp += d
                if resp != data:
                    raise RuntimeError("data mismatch")
            elapsed = time.time() - t0
            s.close()
            mbps = (chunk * nchunks) / elapsed / 1_000_000
            return (True, mbps, elapsed)
        except Exception as e:
            return (False, 0.0, 0.0)
        finally:
            echo_stop.set()
            _stop_tunnel(svr, cli)
            killall()


_TEST_FUNCS = {
    "short": run_tunnel_short_test,
    "long": run_tunnel_long_test,
    "blocking": run_tunnel_blocking_test,
    "blocking_bidi": run_tunnel_blocking_bidi_test,
    "bidi": run_tunnel_bidi_test,
}

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--run-test":
        test_name = sys.argv[2]
        cfg = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
        fn = _TEST_FUNCS.get(test_name)
        if fn is None:
            sys.exit(1)
        ok = fn(cfg)
        sys.exit(0 if ok else 1)

    if len(sys.argv) > 1 and sys.argv[1] == "--run":
        cfg = sys.argv[2] if len(sys.argv) > 2 else None
        ok = run_tunnel_test(cfg)
        sys.exit(0 if ok else 1)

    if len(sys.argv) > 1 and sys.argv[1] == "--run-threads":
        cfg = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
        results = run_tunnel_test_threads(cfg)
        passed = sum(1 for v in results.values() if v)
        total = len(results)
        print(f"\n  {passed}/{total} passed", flush=True)
        for tc, ok in results.items():
            label = f"t{tc}" if tc else "tauto"
            print(f"    {label}: {'PASS' if ok else 'FAIL'}", flush=True)
        sys.exit(0 if all(results.values()) else 1)

    if len(sys.argv) > 2 and sys.argv[1] == "--task":
        workers = int(sys.argv[2])
        cfg = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
        ok = Task().test(workers=workers, config=cfg)
        sys.exit(0 if ok else 1)

    if len(sys.argv) > 1 and sys.argv[1] == "--benchmark":
        workers = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else 1
        cfg = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
        ok, mbps, elapsed = Task().benchmark(workers=workers, config=cfg)
        label = cfg or "tunnel"
        if ok:
            print(f"  [{label}] benchmark: {mbps:.2f} MB/s ({elapsed:.2f}s, {BENCHMARK_TOTAL // 1_000_000}MB)", flush=True)
        else:
            print(f"  [{label}] benchmark: FAIL", flush=True)
        sys.exit(0 if ok else 1)

    if len(sys.argv) > 1 and sys.argv[1] == "--benchmark-all":
        workers = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else 1
        from test_tester import Tester
        task = Task()
        tester = Tester(workers=[workers])
        results = tester.run_benchmark(task)
        passed = sum(1 for v in results.values() if v)
        total = len(results)
        print(f"\n  {passed}/{total} passed", flush=True)
        print(f"{'ALL PASS' if all(results.values()) else 'SOME FAILED'}", flush=True)
        sys.exit(0 if all(results.values()) else 1)

    from test_tester import Tester
    task = Task()
    tester = Tester()
    results = tester.run(task)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} passed", flush=True)
    print(f"{'ALL PASS' if all(results.values()) else 'SOME FAILED'}", flush=True)
    sys.exit(0 if all(results.values()) else 1)
