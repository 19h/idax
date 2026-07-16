#!/usr/bin/env python3
"""Verify that every idax example processor module exports IDA's LPH symbol."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


PROCESSOR_MODULES = ("idaxmini", "xrisc32", "jbc")
MODULE_SUFFIXES = {".dll", ".dylib", ".so"}
LPH_PATTERN = re.compile(r"(?:^|\s)_?LPH(?:\s|$)", re.MULTILINE)
LICENSE_ID_PATTERN = re.compile(
    r"[0-9A-F]{2}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}"
)


class ValidationError(RuntimeError):
    """A deterministic processor-module validation failure."""


def _redact(text: str, roots: tuple[Path, ...]) -> str:
    result = LICENSE_ID_PATTERN.sub("[REDACTED]", text)
    for root in roots:
        try:
            value = str(root.resolve())
        except OSError:
            value = str(root)
        if value:
            result = result.replace(value, "<PATH>")
    return result


def find_module(build_dir: Path, module_name: str) -> Path:
    preferred = []
    fallback = []
    for candidate in build_dir.rglob(f"{module_name}.*"):
        if not candidate.is_file() or candidate.suffix.lower() not in MODULE_SUFFIXES:
            continue
        if "idabin" in candidate.parts and "procs" in candidate.parts:
            preferred.append(candidate)
        else:
            fallback.append(candidate)

    matches = sorted(preferred or fallback)
    if not matches:
        raise ValidationError(f"processor artifact not found: {module_name}")
    if len(matches) > 1:
        names = ", ".join(path.name for path in matches)
        raise ValidationError(f"ambiguous processor artifacts for {module_name}: {names}")
    return matches[0]


def _symbol_command(module: Path) -> list[str]:
    if module.suffix.lower() == ".dll" or os.name == "nt":
        tool = shutil.which("dumpbin")
        if tool is None:
            raise ValidationError("dumpbin is required to validate Windows exports")
        return [tool, "/nologo", "/exports", str(module)]

    tool = shutil.which("nm")
    if tool is None:
        raise ValidationError("nm is required to validate processor exports")
    if sys.platform == "darwin":
        return [tool, "-gU", str(module)]
    return [tool, "-D", "--defined-only", str(module)]


def read_exported_symbols(module: Path) -> str:
    command = _symbol_command(module)
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        errors="replace",
    )
    if completed.returncode != 0:
        detail = _redact(
            (completed.stderr or completed.stdout).strip(),
            (module.parent, Path.home()),
        )
        raise ValidationError(
            f"symbol inspection failed for {module.name}: {detail or 'unknown error'}"
        )
    return completed.stdout


def validate_exports(build_dir: Path) -> None:
    if not build_dir.is_dir():
        raise ValidationError("build directory does not exist")

    for module_name in PROCESSOR_MODULES:
        module = find_module(build_dir, module_name)
        symbols = read_exported_symbols(module)
        if LPH_PATTERN.search(symbols) is None:
            raise ValidationError(f"{module.name} does not export LPH")
        print(f"processor export: PASS ({module.name}: LPH)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    args = parser.parse_args()
    try:
        validate_exports(args.build_dir)
    except ValidationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
