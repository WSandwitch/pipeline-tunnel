#!/usr/bin/env python3
"""
Tests for module_tester: list modules, round-trip each module individually.
"""
import subprocess, os, sys, time

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = "/tmp/ppltunnel_build"
TESTER = os.path.join(BUILD, "module_tester", "ppltunnel-tester")
MOD_DIR = os.path.join(BUILD, "tests", "test_modules")

# Module params for round-trip test (dir=1 encodes, connecting to chain B which decodes)
MODULE_PARAMS = {
    "copy": "",
    "base64": "",
    "compress": "zstd:1",
    "crypt": "testkey",
    "split": "split:1",
}


def discover_modules():
    r = subprocess.run([TESTER, "-M", MOD_DIR], capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, f"module list failed:\n{r.stderr}"
    mods = []
    for line in r.stderr.split('\n'):
        if line.startswith('  '):
            name = line.strip().split()[0]
            mods.append(name)
    return mods


def test_module_list():
    """module_tester without chain config lists available modules."""
    print("  [+] Discovering modules...")
    mods = discover_modules()
    print(f"  [+] Found modules: {mods}")
    assert mods, "No modules discovered"
    assert "copy" in mods, "copy module should be in list"
    print("  [+] PASS: test_module_list")


def test_each_module():
    """Test each module individually with round-trip."""
    mods = discover_modules()
    results = {}
    for mod_name in mods:
        params = MODULE_PARAMS.get(mod_name)
        if params is None:
            print(f"  [!] Skipping {mod_name}: no test params")
            continue

        config = f"{mod_name}|{params}" if params else mod_name
        start = time.time()
        r = subprocess.run(
            [TESTER, "-M", MOD_DIR, "-s", "4096", config],
            capture_output=True, text=True, timeout=30,
        )
        elapsed = time.time() - start
        passed = r.returncode == 0

        print(f"  [{' ' if passed else '!'}] {mod_name}: {'PASS' if passed else 'FAIL'} ({elapsed:.1f}s)")

        results[mod_name] = passed

    failures = [n for n, ok in results.items() if not ok]
    assert not failures, f"Failed modules: {failures}"
    print(f"  [+] PASS: {len(results)} modules tested")


def test_invalid_module():
    """Nonexistent module should exit with non-zero status."""
    r = subprocess.run(
        [TESTER, "-M", MOD_DIR, "-s", "256", "nonexistent"],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode != 0, "nonexistent module should fail"
    print(f"  [+] PASS: test_invalid_module (exit={r.returncode})")


def test_data_sizes():
    """Test with different data sizes across all modules."""
    mods = discover_modules()
    for mod_name in mods:
        params = MODULE_PARAMS.get(mod_name)
        if params is None:
            continue
        config = f"{mod_name}|{params}" if params else mod_name
        for size in [128, 4096, 50000, 65536, 100000, 1048576]:
            to = 120 if size >= 1048576 else 30
            r = subprocess.run(
                [TESTER, "-M", MOD_DIR, "-s", str(size), config],
                capture_output=True, text=True, timeout=to,
            )
            assert r.returncode == 0, f"{mod_name} {size} failed:\n{r.stderr}"
            print(f"  [+] {mod_name} size={size}: PASS")

    print(f"  [+] PASS: test_data_sizes")


if __name__ == "__main__":
    tests = [
        ("test_module_list", test_module_list),
        ("test_each_module", test_each_module),
        ("test_invalid_module", test_invalid_module),
        ("test_data_sizes", test_data_sizes),
    ]
    for name, fn in tests:
        print(f"\n=== {name} ===")
        fn()
    print("\nAll module_tester tests PASSED!")
