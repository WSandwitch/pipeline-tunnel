#!/usr/bin/env python3
"""
Benchmark: measure throughput through tunnel/module chain.
Time-based: runs for DURATION seconds, counts bytes transferred.
"""
import os, sys, subprocess, time, socket, select

DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DIR)

APP = os.path.dirname(DIR)
BUILD = os.path.join(os.path.dirname(APP), "build")
ECHO_SRV = os.path.join(BUILD, "examples", "echo", "echo_srv")
ECHO_CLI = os.path.join(BUILD, "examples", "echo", "echo_cli")

BENCHMARK_DURATION = int(os.environ.get("BENCHMARK_DURATION", "15"))
BENCHMARK_CHUNK = int(os.environ.get("BENCHMARK_CHUNK", "65536"))

from test_integration import (_find_free_port, _start_tunnel, _stop_tunnel,
                              _wait_port_listen, _kill, killall)


class Task:
    """Measure throughput: send data for BENCHMARK_DURATION seconds."""

    def __init__(self, workers=1, config=None):
        self.workers = workers
        self.config = config

    def run(self):
        if self.config == "ref":
            return self._benchmark_ref()
        return self._benchmark_tunnel()

    def _benchmark_ref(self):
        tgt_port = _find_free_port(31000, 32000)
        srv = subprocess.Popen([ECHO_SRV, str(tgt_port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _wait_port_listen(tgt_port)
            ok, mbps = self._time_benchmark("127.0.0.1", tgt_port)
            if ok:
                print(f"  [raw TCP] benchmark: {mbps:.2f} MB/s", flush=True)
            else:
                print(f"  [raw TCP] benchmark: FAIL", flush=True)
            return ok
        finally:
            _kill(srv)

    def _benchmark_tunnel(self):
        tgt_port = _find_free_port(31000, 32000)
        srv = subprocess.Popen([ECHO_SRV, str(tgt_port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _wait_port_listen(tgt_port)
            svr, cli, _, cli_port = _start_tunnel(
                _find_free_port(32001, 33000), _find_free_port(33001, 34000),
                tgt_port, self.config, threads=self.workers)
        except:
            _kill(srv)
            print(f"  [{self.config or 'tunnel'}] benchmark: FAIL (tunnel start)", flush=True)
            return False

        label = self.config or "tunnel"
        try:
            ok, mbps = self._time_benchmark("127.0.0.1", cli_port)
            if ok:
                print(f"  [{label}] benchmark: {mbps:.2f} MB/s", flush=True)
            else:
                print(f"  [{label}] benchmark: FAIL", flush=True)
            return ok
        finally:
            _stop_tunnel(svr, cli)
            killall()
            _kill(srv)

    def _time_benchmark(self, host, port, duration=BENCHMARK_DURATION):
        """Run echo benchmark for `duration` seconds. Returns (ok, mbps)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(duration + 5)
            s.connect((host, port))
            s.setblocking(False)

            chunk = BENCHMARK_CHUNK
            data = b'x' * chunk
            sent = 0
            recvd = 0
            t0 = time.time()
            deadline = t0 + duration

            while True:
                now = time.time()
                if now >= deadline:
                    break

                remaining = deadline - now
                r, w, x = select.select([s], [s], [s], min(0.1, remaining))

                if w:
                    try:
                        n = s.send(data)
                        if n > 0:
                            sent += n
                    except (BlockingIOError, OSError):
                        pass

                if r:
                    try:
                        d = s.recv(65536)
                        if not d:
                            break
                        recvd += len(d)
                    except (BlockingIOError, OSError):
                        pass

                if x:
                    break

            elapsed = time.time() - t0
            s.close()

            if elapsed <= 0 or recvd <= 0:
                return False, 0.0
            mbps = recvd / elapsed / 1_000_000
            return True, mbps
        except Exception as e:
            return False, 0.0


if __name__ == "__main__":
    from test_tester import Tester
    results = Tester(Task).run()
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} passed", flush=True)
    print(f"{'ALL PASS' if all(results.values()) else 'SOME FAILED'}", flush=True)
    sys.exit(0 if all(results.values()) else 1)
