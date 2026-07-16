from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.ida_runtime
def test_aarch64_register_tracker_in_fresh_process() -> None:
    source = os.environ.get("IDAX_PYTHON_REGISTERS_RUNTIME_FIXTURE")
    if not source:
        pytest.skip("IDAX_PYTHON_REGISTERS_RUNTIME_FIXTURE is not configured")
    script = Path(__file__).with_name("registers_runtime_probe.py")
    result = subprocess.run(
        [sys.executable, str(script), source],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
