#!/usr/bin/env python3
"""Fail-closed structural checks for the IDAX Python API manifest."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "bindings/python/api_manifest.json"
HEADER_AUDIT_PATH = ROOT / "bindings/python/header_audit.json"
NATIVE_ROOT = ROOT / "bindings/python/src/native"
PACKAGE_ROOT = ROOT / "bindings/python/src/idax"


def fail(message: str) -> None:
    raise AssertionError(message)


def umbrella_domains() -> set[str]:
    text = (ROOT / "include/ida/idax.hpp").read_text(encoding="utf-8")
    includes = set(re.findall(r"#include <ida/([a-z_]+)\.hpp>", text))
    includes -= {"core", "error"}
    return includes


def static_all(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for statement in tree.body:
        if not isinstance(statement, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "__all__"
                   for target in statement.targets):
            continue
        if not isinstance(statement.value, (ast.List, ast.Tuple)):
            fail(f"{path}: __all__ must be a static list or tuple")
        values: set[str] = set()
        for element in statement.value.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                fail(f"{path}: __all__ must contain string literals only")
            values.add(element.value)
        return values
    fail(f"{path}: missing static __all__")


def stub_symbols(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        statement.name
        for statement in tree.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def native_functions(domain: str, path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    functions = set(
        re.findall(
            rf"\b{re.escape(domain)}(?:_module)?\.def\(\"([a-z_][a-z0-9_]*)\"",
            text,
        )
    )
    functions.update(
        name
        for name in re.findall(
            r"IDAX_PY_[A-Z_]+\(([a-z_][a-z0-9_]*)(?:,[^;\n]*)?\);", text
        )
        if name != "name"
    )
    functions.update(
        re.findall(
            rf"\bbind_[a-z_]+\(\s*{re.escape(domain)}(?:_module)?\s*,\s*"
            r'"([a-z_][a-z0-9_]*)"',
            text,
        )
    )
    return functions


def native_types(domain: str, path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    types = set(
        re.findall(
            rf"py::(?:class_|native_enum)<[^;]+?>\(\s*"
            rf"{re.escape(domain)}(?:_module)?\s*,\s*\"([A-Z][A-Za-z0-9_]*)\"",
            text,
        )
    )
    types.update(
        re.findall(
            r"IDAX_PY_[A-Z_]*VALUE\(([A-Z][A-Za-z0-9_]*)(?:,[^;\n]*)?\);",
            text,
        )
    )
    types.update(
        re.findall(r"IDAX_PY_[A-Z_]*VALUE\(([A-Z][A-Za-z0-9_]*)\)", text)
    )
    types.update(
        re.findall(r"IDAX_PY_[A-Z_]*ENUM\(([A-Z][A-Za-z0-9_]*)\)", text)
    )
    types.update(
        re.findall(r"IDAX_PY_SEARCH_OPTIONS\(([A-Z][A-Za-z0-9_]*)\);", text)
    )
    types.update(
        re.findall(
            rf"create_exception_type\(\s*{re.escape(domain)}\s*,\s*"
            r'"([A-Z][A-Za-z0-9_]*)"',
            text,
        )
    )
    return types


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    header_audit = json.loads(HEADER_AUDIT_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        fail("unsupported Python API manifest schema")
    if header_audit.get("schema_version") != 1:
        fail("unsupported Python header-audit schema")
    umbrella_path = ROOT / header_audit.get("authoritative_umbrella", "")
    if umbrella_path != ROOT / manifest.get("authoritative_umbrella", ""):
        fail("header audit and API manifest use different umbrella headers")
    if hashlib.sha256(umbrella_path.read_bytes()).hexdigest() != header_audit.get(
        "umbrella_sha256"
    ):
        fail("authoritative umbrella changed; repeat the declaration audit")

    states = set(manifest.get("completion_states", []))
    expected_states = {"planned", "partial", "implemented", "validated"}
    if states != expected_states:
        fail(f"completion states differ: {sorted(states)}")

    domains = manifest.get("domains")
    if not isinstance(domains, list):
        fail("domains must be a list")
    names = [entry.get("name") for entry in domains]
    if len(names) != len(set(names)):
        fail("duplicate domain names in Python API manifest")

    expected = umbrella_domains()
    actual = set(names)
    if actual != expected:
        fail(
            "manifest/domain drift: missing="
            f"{sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )

    audited_headers = header_audit.get("headers")
    if not isinstance(audited_headers, list):
        fail("header audit entries must be a list")
    audited_domains = {entry.get("domain") for entry in audited_headers}
    expected_audited = actual | {entry["name"] for entry in manifest.get("shared", [])}
    if audited_domains != expected_audited or len(audited_headers) != len(audited_domains):
        fail("header audit does not cover each domain exactly once")
    for entry in audited_headers:
        path = ROOT / entry.get("path", "")
        if not path.is_file():
            fail(f"{entry.get('domain')}: audited header is missing")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry.get("sha256"):
            fail(
                f"{entry.get('domain')}: public header changed; repeat the "
                "declaration-level binding audit"
            )

    checked_symbols = 0
    shared = manifest.get("shared")
    if not isinstance(shared, list):
        fail("shared declarations must be a list")
    for entry in shared:
        name = entry["name"]
        status = entry.get("status")
        if status not in states or status == "planned":
            fail(f"{name}: shared declaration inventory is not implemented")
        source_name = entry.get("native_source")
        types = entry.get("bound_types", [])
        if not isinstance(source_name, str) or types != sorted(set(types)) or not types:
            fail(f"{name}: shared declaration lacks a sorted native type inventory")
        native_path = NATIVE_ROOT / source_name
        public_path = PACKAGE_ROOT / f"{name}.py"
        stub_path = PACKAGE_ROOT / f"{name}.pyi"
        for path in (native_path, public_path, stub_path):
            if not path.is_file():
                fail(f"{name}: missing shared implementation artifact {path}")
        binding_module = entry.get("binding_module", name)
        native = native_types(binding_module, native_path)
        declared = set(types)
        if native != declared:
            fail(
                f"{name}: shared native type drift: missing="
                f"{sorted(declared - native)}, extra={sorted(native - declared)}"
            )
        public = static_all(public_path)
        stubs = stub_symbols(stub_path)
        if not declared <= public:
            fail(f"{name}: shared public exports missing {sorted(declared - public)}")
        if not declared <= stubs:
            fail(f"{name}: shared stub declarations missing {sorted(declared - stubs)}")
        checked_symbols += len(declared)

    for entry in domains:
        name = entry["name"]
        status = entry.get("status")
        if status not in states:
            fail(f"{name}: invalid status {status!r}")

        header = ROOT / entry["header"]
        if not header.is_file():
            fail(f"{name}: missing authoritative header {header}")

        if status == "planned":
            if (entry.get("native_source") or entry.get("native_sources")
                    or entry.get("bound_functions")):
                fail(f"{name}: planned domain advertises implementation artifacts")
            continue

        source_name = entry.get("native_source")
        source_names = entry.get("native_sources")
        if source_names is None:
            source_names = [source_name] if isinstance(source_name, str) else []
        functions = entry.get("bound_functions", [])
        types = entry.get("bound_types", [])
        if (not isinstance(source_names, list) or not source_names
                or not all(isinstance(value, str) for value in source_names)
                or not isinstance(functions, list)
                or not isinstance(types, list) or not (functions or types)):
            fail(f"{name}: active domain lacks source or bound symbol inventory")
        if source_names != sorted(set(source_names)):
            fail(f"{name}: native_sources must be unique and sorted")
        if functions != sorted(set(functions)):
            fail(f"{name}: bound_functions must be unique and sorted")
        if types != sorted(set(types)):
            fail(f"{name}: bound_types must be unique and sorted")

        native_paths = [NATIVE_ROOT / value for value in source_names]
        public_path = PACKAGE_ROOT / f"{name}.py"
        stub_path = PACKAGE_ROOT / f"{name}.pyi"
        for path in (*native_paths, public_path, stub_path):
            if not path.is_file():
                fail(f"{name}: missing implementation artifact {path}")

        native: set[str] = set()
        registered_types: set[str] = set()
        for native_path in native_paths:
            native.update(native_functions(name, native_path))
            if types:
                registered_types.update(native_types(name, native_path))
        public = static_all(public_path)
        stubs = stub_symbols(stub_path)
        declared = set(functions)
        if native != declared:
            fail(
                f"{name}: native function drift: missing={sorted(declared - native)}, "
                f"extra={sorted(native - declared)}"
            )
        declared_types = set(types)
        if registered_types != declared_types:
            fail(
                f"{name}: native type drift: missing="
                f"{sorted(declared_types - registered_types)}, "
                f"extra={sorted(registered_types - declared_types)}"
            )
        symbols = declared | declared_types
        if not symbols <= public:
            fail(f"{name}: public exports missing {sorted(symbols - public)}")
        if not symbols <= stubs:
            fail(f"{name}: stub declarations missing {sorted(symbols - stubs)}")
        checked_symbols += len(symbols)

    print(
        f"Python API manifest: PASS ({len(actual)} domains; "
        f"{checked_symbols} bound functions/types checked)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"Python API manifest: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
