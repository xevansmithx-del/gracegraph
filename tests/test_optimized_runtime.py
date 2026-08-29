from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_hostile_probe_is_identical_under_optimized_python():
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(root / "src")
    normal = subprocess.run(
        [sys.executable, str(root / "tests" / "optimized_runtime_probe.py")],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    optimized = subprocess.run(
        [sys.executable, "-O", str(root / "tests" / "optimized_runtime_probe.py")],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert normal.stdout == optimized.stdout
    assert '"status": "PASS"' in normal.stdout
