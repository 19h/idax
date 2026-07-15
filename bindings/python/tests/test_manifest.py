from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path


def test_api_manifest_is_consistent() -> None:
    root = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        [sys.executable, "scripts/check_python_api_manifest.py"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_public_module_has_documentation() -> None:
    root = Path(__file__).resolve().parents[3]
    manifest = json.loads(
        (root / "bindings/python/api_manifest.json").read_text(encoding="utf-8")
    )
    names = [entry["name"] for entry in manifest["shared"]]
    names.extend(entry["name"] for entry in manifest["domains"])
    for name in names:
        module = importlib.import_module(f"idax.{name}")
        assert module.__doc__ is not None and module.__doc__.strip(), name
