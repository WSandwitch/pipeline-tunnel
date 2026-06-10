import os, time


class Tester:
    """Orchestrates test runs: builds config × workers matrix,
    instantiates task_cls(workers, config) and calls .run() for each.
    """

    def __init__(self, task_cls, workers=None):
        self.task_cls = task_cls
        self.workers = workers or [1]

    def _build_configs(self):
        """Build config list: ref (raw TCP) + tunnel + all module configs + combined chains."""
        import test_integration as ti
        mods = ti.discover_modules()
        configs = ["ref"]
        for m in mods:
            cfgs = ti.read_module_configs(m)
            if cfgs:
                for c in cfgs:
                    configs.append(f"{m}|{c}")
            else:
                configs.append(m)
        # Combined chains from chains.cfg.list
        chain_cfgs = ti.read_module_configs("chains")
        configs.extend(chain_cfgs)
        return configs

    def run(self):
        """For each config × workers: instantiate task_cls, call .run().
        Returns dict {(config, workers): bool}.
        """
        configs = self._build_configs()
        results = {}
        for cfg in configs:
            for w in self.workers:
                label = cfg or "tunnel"
                if w:
                    label += f" t{w}"
                print(f"\n--- {label} ---", flush=True)
                t0 = time.time()
                task = self.task_cls(workers=w, config=cfg)
                ok = task.run()
                elapsed = time.time() - t0
                print(f"  {label}: {'PASS' if ok else 'FAIL'} ({elapsed:.1f}s)", flush=True)
                results[(cfg, w)] = ok
                if not ok:
                    break
        return results
