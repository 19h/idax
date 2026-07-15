from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


def _audit_module() -> ModuleType:
    root = Path(__file__).resolve().parents[3]
    path = root / "scripts/check_python_distribution.py"
    spec = importlib.util.spec_from_file_location("check_python_distribution", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_distribution_privacy_patterns_and_safe_members() -> None:
    audit = _audit_module()
    audit.safe_member_name("idax/module.py")
    audit.scan_payload("safe", b"<repo-root>/bindings/python")

    with pytest.raises(AssertionError, match="unsafe archive member"):
        audit.safe_member_name("../outside")
    with pytest.raises(AssertionError, match="identity-bearing absolute path"):
        unix_path = b"/" + b"home" + b"/" + b"example/private/file.cpp"
        audit.scan_payload("unix", unix_path)
    with pytest.raises(AssertionError, match="identity-bearing absolute path"):
        windows_path = b"C:" + b"\\" + b"Users\\example\\private\\file.cpp"
        audit.scan_payload("windows", windows_path)
