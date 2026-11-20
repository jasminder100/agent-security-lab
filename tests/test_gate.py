"""Guard the guard: the benchmark gate must PASS on the real policy and must FAIL on the
deliberately weakened ones. If someone breaks the gate or the attack detection, these fail.

Each run writes its evidence into a temporary folder, so reports/results/ stays clean.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_gate(results_dir, *extra):
    cmd = [sys.executable, "-m", "runner.benchmark",
           "--model-mode", "scripted", "--modes", "secured",
           "--max-attack-success", "0", "--results-dir", str(results_dir), *extra]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)


def failed_tests(output: str) -> set:
    """IDs of attacks that succeeded against the secured agent (from the per-test table)."""
    return set(re.findall(r"(TC-\d+) .*secured: attack_succeeded", output))


def test_gate_passes_on_the_real_policy(tmp_path):
    r = run_gate(tmp_path)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    assert "GATE: PASS" in r.stdout
    assert failed_tests(r.stdout) == set()


@pytest.mark.parametrize("policy, must_fail", [
    ("no_taint", {"TC-016"}),
    ("no_redaction", {"TC-002", "TC-003", "TC-004", "TC-007"}),
])
def test_gate_catches_weakened_policy(tmp_path, policy, must_fail):
    r = run_gate(tmp_path, "--policy", f"config/regressions/{policy}.yaml")
    assert r.returncode == 1, r.stdout[-2000:] + r.stderr[-2000:]
    assert "GATE: FAIL" in r.stdout
    assert must_fail <= failed_tests(r.stdout)