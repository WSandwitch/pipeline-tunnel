#!/usr/bin/env python3
"""
Benchmark: measure throughput through tunnel/module chain.
Uses C echo server + client for accurate measurement.
"""
import os, sys, subprocess, time

DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DIR)

APP = os.path.dirname(DIR)
BUILD = os.path.join(os.path.dirname(APP), "build")
ECHO_SRV = os.path.join(BUILD, "examples", "echo", "echo_srv")
ECHO_CLI = os.path.join(BUILD, "examples", "echo", "echo_cli")

from test_integration import (BENCHMARK_TOTAL, BENCHMARK_CHUNK,
                              _find_free_port, _start_tunnel, _stop_tunnel,
                              _wait_port_listen, _kill, killall)


class Task:
    """Measure throughput: send BENCHMARK_TOTAL bytes through tunnel/module chain."""

    def __init__(self, workers=1, config=None):
        self.workers = workers
        self.config = config

    def run(self):
        """Run benchmark. Returns True on success."""
        if self.config == "ref":
            return self._benchmark_ref()
        return self._benchmark_tunnel()

    def _run_echo_cli(self, port):
        """Run echo_cli against given port, return (ok, mbps)."""
        try:
            r = subprocess.run(
                [ECHO_CLI, "127.0.0.1", str(port),
                 str(BENCHMARK_TOTAL), str(BENCHMARK_CHUNK)],
                capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return False, 0.0
            mbps = float(r.stdout.strip())
            return True, mbps
        except Exception:
            return False, 0.0

    def _benchmark_ref(self):
        """Raw TCP echo throughput (no proxy) as reference."""
        tgt_port = _find_free_port(31000, 32000)
        srv = subprocess.Popen([ECHO_SRV, str(tgt_port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _wait_port_listen(tgt_port)
            ok, mbps = self._run_echo_cli(tgt_port)
            if ok:
                print(f"  [raw TCP] benchmark: {mbps:.2f} MB/s", flush=True)
            else:
                print(f"  [raw TCP] benchmark: FAIL", flush=True)
            return ok
        finally:
            _kill(srv)

    def _benchmark_tunnel(self):
        """Throughput through tunnel/module chain."""
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
            ok, mbps = self._run_echo_cli(cli_port)
            if ok:
                print(f"  [{label}] benchmark: {mbps:.2f} MB/s", flush=True)
            else:
                print(f"  [{label}] benchmark: FAIL", flush=True)
            return ok
        finally:
            _stop_tunnel(svr, cli)
            killall()
            _kill(srv)


if __name__ == "__main__":
    from test_tester import Tester
    results = Tester(Task).run()
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} passed", flush=True)
    print(f"{'ALL PASS' if all(results.values()) else 'SOME FAILED'}", flush=True)
    sys.exit(0 if all(results.values()) else 1)
