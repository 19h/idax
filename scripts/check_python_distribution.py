#!/usr/bin/env python3
"""Inspect IDAX Python wheel/sdist contents and privacy boundaries."""

from __future__ import annotations

import argparse
import json
import re
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
MANIFEST = ROOT / "bindings/python/api_manifest.json"
IDENTITY_PATHS = (
    re.compile(rb"/(?:Users|home)/[^/\x00\r\n\t ]+/"),
    re.compile(rb"[A-Za-z]:[\\/]Users[\\/][^\\/\x00\r\n\t ]+[\\/]"),
)
FORBIDDEN_RUNTIME_NAMES = re.compile(
    r"(?:^|/)(?:libida(?:lib)?\.(?:so|dylib)|ida(?:64|t)?(?:\.exe)?|[^/]*\.hexlic)$",
    re.IGNORECASE,
)


def fail(message: str) -> None:
    raise AssertionError(message)


def safe_member_name(name: str) -> None:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        fail(f"unsafe archive member: {name!r}")


def scan_payload(label: str, payload: bytes) -> None:
    for pattern in IDENTITY_PATHS:
        if pattern.search(payload):
            fail(f"identity-bearing absolute path found in {label}")


def expected_domains() -> list[str]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return sorted(entry["name"] for entry in manifest["domains"])


def check_wheel(path: Path, domains: Iterable[str]) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        for name in names:
            safe_member_name(name)
            if FORBIDDEN_RUNTIME_NAMES.search(name):
                fail(f"wheel bundles an IDA runtime/license artifact: {name}")
            scan_payload(f"{path.name}:{name}", archive.read(name))

        name_set = set(names)
        for domain in domains:
            for suffix in (".py", ".pyi"):
                required = f"idax/{domain}{suffix}"
                if required not in name_set:
                    fail(f"wheel is missing {required}")
        for required in ("idax/__init__.py", "idax/__init__.pyi", "idax/py.typed"):
            if required not in name_set:
                fail(f"wheel is missing {required}")
        if not any(
            re.fullmatch(r"idax/_native(?:\.[^/]+)?\.(?:so|pyd|dylib)", name)
            for name in names
        ):
            fail("wheel is missing the private native extension")
        if not any(".dist-info/licenses/" in name for name in names):
            fail("wheel is missing license metadata")


def check_sdist(path: Path, domains: Iterable[str]) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        relative_names: set[str] = set()
        for member in members:
            safe_member_name(member.name)
            parts = PurePosixPath(member.name).parts
            relative = "/".join(parts[1:]) if len(parts) > 1 else ""
            relative_names.add(relative)
            if FORBIDDEN_RUNTIME_NAMES.search(relative):
                fail(f"sdist bundles an IDA runtime/license artifact: {relative}")
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    fail(f"unable to inspect sdist member: {relative}")
                scan_payload(f"{path.name}:{relative}", extracted.read())

        required = {
            "CMakeLists.txt",
            "pyproject.toml",
            "bindings/python/API.md",
            "bindings/python/DECLARATION_AUDIT.md",
            "bindings/python/LICENSE",
            "bindings/python/README.md",
            "bindings/python/TUTORIAL.md",
            "bindings/python/api_manifest.json",
            "bindings/python/header_audit.json",
            "bindings/python/examples/action.py",
            "bindings/python/examples/decompile.py",
            "bindings/python/examples/inventory.py",
        }
        for domain in domains:
            required.add(f"bindings/python/src/idax/{domain}.py")
            required.add(f"bindings/python/src/idax/{domain}.pyi")
        missing = sorted(required - relative_names)
        if missing:
            fail(f"sdist is missing required files: {missing}")
        if not any(name.startswith("bindings/python/src/native/") for name in relative_names):
            fail("sdist is missing native binding sources")


def resolve_artifacts(arguments: list[str]) -> tuple[Path, Path]:
    paths = [Path(value) for value in arguments]
    if not paths:
        paths = sorted(DIST.glob("idax-*"))
    wheels = [path for path in paths if path.suffix == ".whl"]
    sdists = [path for path in paths if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1:
        fail("expected exactly one IDAX wheel and one IDAX .tar.gz sdist")
    if not wheels[0].is_file() or not sdists[0].is_file():
        fail("distribution artifact does not exist")
    return wheels[0], sdists[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="*")
    args = parser.parse_args()
    wheel, sdist = resolve_artifacts(args.artifacts)
    domains = expected_domains()
    check_wheel(wheel, domains)
    check_sdist(sdist, domains)
    print(
        "Python distribution audit: PASS "
        f"({len(domains)} domains; wheel={wheel.name}; sdist={sdist.name})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"Python distribution audit: FAIL: {error}")
        raise SystemExit(1) from error
