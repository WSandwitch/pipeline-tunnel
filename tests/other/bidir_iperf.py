#!/usr/bin/env python3
"""Bidirectional iperf3 benchmark through tunnel (forward + reverse runs)."""
import os, sys, subprocess, time, socket, json

DIR = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(DIR)
BUILD = os.path.join(os.path.dirname(APP), "build")
SERVER = os.path.join(BUILD, "server", "ppltunnel-server")
CLIENT = os.path.join(BUILD, "client", "ppltunnel-client")
MPATH = os.path.join(APP, "tests", "test_modules")
HOST = "127.0.0.1"
PASS = "testpass"

DURATION = int(os.environ.get("BENCHMARK_DURATION", "30"))

def find_free_port(lo=30000, hi=40000):
    for _ in range(100):
        port = int(os.urandom(2).hex(), 16) % (hi - lo) + lo
        s = socket.socket()
        try:
            s.bind((HOST, port))
            s.close()
            return port
        except:
            s.close()
    raise RuntimeError("no free port")

def wait_port(port, timeout=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = socket.socket()
        try:
            s.connect((HOST, port))
            s.close()
            return
        except:
            s.close()
            time.sleep(0.1)
    raise TimeoutError(f"port {port} not ready after {timeout}s")

def bidir_iperf(config):
    tgt_port = find_free_port()
    svr_port = find_free_port()
    cli_port = find_free_port()

    iperf_srv = subprocess.Popen(["iperf3", "-s", "-p", str(tgt_port), "-D"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_port(tgt_port)
    time.sleep(0.3)

    srv = subprocess.Popen([SERVER, f"-l{HOST}:{svr_port}", f"-A{PASS}",
                            f"-M{MPATH}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           cwd=APP)
    wait_port(svr_port)

    cli = subprocess.Popen([CLIENT, f"-L{HOST}:{cli_port}:{HOST}:{tgt_port}",
                            f"-M{MPATH}",
                            f"{HOST}:{svr_port},{PASS};{config}",
                            "-t1"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           cwd=APP)
    wait_port(cli_port)
    time.sleep(1)

    label = config
    try:
        fwd = subprocess.run(["iperf3", "-c", HOST, "-p", str(cli_port),
                              "-t", str(DURATION), "-J"],
                             capture_output=True, text=True, timeout=DURATION + 15)
        d = json.loads(fwd.stdout)
        fwd_bps = 0
        for key in ("sum", "sum_sent"):
            if key in d.get("end", {}):
                fwd_bps = d["end"][key].get("bits_per_second", 0)
                if fwd_bps:
                    break
        fwd_mbps = fwd_bps / 1_000_000
        print(f"  [{label}] forward: {fwd_mbps:.0f} Mbps", flush=True)

        rev = subprocess.run(["iperf3", "-c", HOST, "-p", str(cli_port),
                              "-t", str(DURATION), "-R", "-J"],
                             capture_output=True, text=True, timeout=DURATION + 15)
        d = json.loads(rev.stdout)
        rev_bps = 0
        for key in ("sum", "sum_received", "sum_sent"):
            if key in d.get("end", {}):
                rev_bps = d["end"][key].get("bits_per_second", 0)
                if rev_bps:
                    break
        rev_mbps = rev_bps / 1_000_000
        print(f"  [{label}] reverse: {rev_mbps:.0f} Mbps", flush=True)
    except Exception as e:
        print(f"  [{label}] FAIL: {e}", flush=True)
    finally:
        cli.kill(); srv.kill()

for cfg in ["split|n:3", "split|n:3;base64"]:
    subprocess.run(["killall", "iperf3"], capture_output=True)
    time.sleep(0.5)
    bidir_iperf(cfg)
