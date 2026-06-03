import os, sys, subprocess, time

FILE = os.path.abspath(__file__)
DIR = os.path.dirname(FILE)
PER_TEST_TIMEOUT = int(os.environ.get("INTEGRATION_PER_TEST_TIMEOUT", "120"))


class Tester:
    """Orchestrates test runs: builds config × workers matrix, prints params,
    calls task.test() in a subprocess for isolation.
    Optional parameters may be added in the future.
    """

    def __init__(self, workers=None):
        self.workers = workers or [1]

    def _build_configs(self):
        """Discover modules and build config list."""
        import test_integration as ti
        mods = ti.discover_modules()
        configs = [None]
        for m in mods:
            cfgs = ti.read_module_configs(m)
            if cfgs:
                for c in cfgs:
                    configs.append(f"{m}|{c}")
            else:
                configs.append(m)
        return configs

    def _subprocess_test(self, workers, config):
        """Run task.test(workers, config) in a subprocess for isolation."""
        cfg_arg = config or ""
        p = subprocess.run(
            [sys.executable, os.path.join(DIR, "test_integration.py"),
             "--task", str(workers), cfg_arg],
            timeout=PER_TEST_TIMEOUT,
            capture_output=True, text=True,
            cwd=DIR,
        )
        if p.stdout:
            print(p.stdout, end="", flush=True)
        if p.stderr:
            print(p.stderr, end="", flush=True)
        return p.returncode == 0

    def _subprocess_benchmark(self, workers, config):
        """Run task.benchmark(workers, config) in a subprocess."""
        cfg_arg = config or ""
        p = subprocess.run(
            [sys.executable, os.path.join(DIR, "test_integration.py"),
             "--benchmark", str(workers), cfg_arg],
            timeout=PER_TEST_TIMEOUT,
            capture_output=True, text=True,
            cwd=DIR,
        )
        if p.stdout:
            print(p.stdout, end="", flush=True)
        if p.stderr:
            print(p.stderr, end="", flush=True)
        return p.returncode == 0

    def run(self, task):
        """Run tests for all configs × workers.
        Prints parameters and calls task.test() via subprocess.
        Returns dict {(config, workers): bool}.
        """
        configs = self._build_configs()
        results = {}
        for cfg in configs:
            for w in self.workers:
                label = cfg or "tunnel"
                if w:
                    label += f" t{w}"
                t0 = time.time()
                print(f"\n--- {label} ---", flush=True)
                ok = self._subprocess_test(w, cfg)
                elapsed = time.time() - t0
                print(f"  {label}: {'PASS' if ok else 'FAIL'} ({elapsed:.1f}s)", flush=True)
                results[(cfg, w)] = ok
                if not ok:
                    break
        return results

    def run_benchmark(self, task):
        """Run benchmarks for all configs × workers.
        Prints throughput and returns dict {(config, workers): mbps}.
        """
        configs = self._build_configs()
        results = {}
        for cfg in configs:
            for w in self.workers:
                label = cfg or "tunnel"
                if w:
                    label += f" t{w}"
                t0 = time.time()
                print(f"\n--- {label} ---", flush=True)
                ok = self._subprocess_benchmark(w, cfg)
                elapsed = time.time() - t0
                status = "OK" if ok else "FAIL"
                print(f"  {label}: {status} ({elapsed:.1f}s)", flush=True)
                results[(cfg, w)] = ok
                if not ok:
                    break
        return results
