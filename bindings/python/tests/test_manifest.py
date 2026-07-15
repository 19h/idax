from __future__ import annotations

import importlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CHECKER_SPEC = importlib.util.spec_from_file_location(
    "idax_python_api_manifest_checker",
    ROOT / "scripts/check_python_api_manifest.py",
)
assert CHECKER_SPEC is not None and CHECKER_SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(CHECKER_SPEC)
CHECKER_SPEC.loader.exec_module(CHECKER)
source_digest = CHECKER.source_digest


def test_header_digest_is_checkout_line_ending_independent(tmp_path: Path) -> None:
    lf = tmp_path / "lf.hpp"
    crlf = tmp_path / "crlf.hpp"
    changed = tmp_path / "changed.hpp"
    lf.write_bytes(b"#pragma once\nint value();\n")
    crlf.write_bytes(b"#pragma once\r\nint value();\r\n")
    changed.write_bytes(b"#pragma once\nlong value();\n")

    assert source_digest(lf) == source_digest(crlf)
    assert source_digest(lf) != source_digest(changed)


def test_api_manifest_is_consistent() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_python_api_manifest.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_public_module_has_documentation() -> None:
    manifest = json.loads(
        (ROOT / "bindings/python/api_manifest.json").read_text(encoding="utf-8")
    )
    names = [entry["name"] for entry in manifest["shared"]]
    names.extend(entry["name"] for entry in manifest["domains"])
    for name in names:
        module = importlib.import_module(f"idax.{name}")
        assert module.__doc__ is not None and module.__doc__.strip(), name
