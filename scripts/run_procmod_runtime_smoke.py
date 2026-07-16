#!/usr/bin/env python3
"""Load and exercise the minimal idax processor through a real IDA runtime."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from check_procmod_exports import ValidationError, _redact, find_module


MNEMONIC_PATTERN = re.compile(r"\bnop\b", re.IGNORECASE)


def _ida_console(ida_dir: Path) -> Path:
    candidates = (ida_dir / "idat.exe", ida_dir / "idat")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ValidationError("IDA console executable was not found under IDADIR")


def _assembly_output(run_dir: Path) -> Path:
    matches = sorted(run_dir.rglob("*.asm"))
    if not matches:
        raise ValidationError("IDA did not produce batch assembly output")
    return matches[0]


def _seed_installed_user_state(user_dir: Path) -> list[Path]:
    """Copy only HCLI-installed license/EULA state into a disposable IDAUSR."""
    source_roots = [Path.home() / ".idapro"]
    appdata = os.environ.get("APPDATA")
    if appdata:
        source_roots.insert(0, Path(appdata) / "Hex-Rays" / "IDA Pro")

    copied: list[Path] = []
    copied_names: set[str] = set()
    for source_root in source_roots:
        candidates = [source_root / "ida.reg"]
        if source_root.is_dir():
            candidates.extend(sorted(source_root.glob("*.hexlic")))
        for source in candidates:
            if not source.is_file() or source.name in copied_names:
                continue
            destination = user_dir / source.name
            shutil.copy2(source, destination)
            copied.append(destination)
            copied_names.add(source.name)
    return copied


def run_smoke(build_dir: Path, ida_dir: Path, fixture: Path) -> None:
    module = find_module(build_dir, "idaxmini")
    console = _ida_console(ida_dir)
    if not fixture.is_file():
        raise ValidationError("processor smoke fixture does not exist")

    with tempfile.TemporaryDirectory(prefix="idax-procmod-smoke-") as raw_run_dir:
        run_dir = Path(raw_run_dir)
        user_processors = run_dir / "user" / "procs"
        user_processors.mkdir(parents=True)
        _seed_installed_user_state(user_processors.parent)
        installed_module = user_processors / module.name
        shutil.copy2(module, installed_module)
        installed_fixture = run_dir / fixture.name
        shutil.copy2(fixture, installed_fixture)

        output_database = run_dir / "minimal.i64"
        log_file = run_dir / "ida.log"
        environment = os.environ.copy()
        environment["IDAUSR"] = str(run_dir / "user")

        command = [
            str(console),
            "-A",
            "-B",
            "-c",
            "-TBinary",
            "-pidaxmini",
            f"-L{log_file}",
            f"-o{output_database}",
            str(installed_fixture),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            env=environment,
            cwd=run_dir,
            timeout=120,
        )
        if completed.returncode != 0:
            diagnostic_parts = [completed.stdout, completed.stderr]
            if log_file.is_file():
                diagnostic_parts.append(
                    log_file.read_text(encoding="utf-8", errors="replace")
                )
            detail = _redact(
                "\n".join(diagnostic_parts).strip(),
                (run_dir, build_dir, ida_dir, fixture.parent, Path.home()),
            )
            raise ValidationError(
                f"IDA processor smoke exited {completed.returncode}: "
                f"{detail[-4000:] or 'no diagnostic output'}"
            )

        assembly = _assembly_output(run_dir)
        rendered = assembly.read_text(encoding="utf-8", errors="replace")
        if MNEMONIC_PATTERN.search(rendered) is None:
            raise ValidationError("processor smoke output contains no rendered nop mnemonic")

        log_text = log_file.read_text(encoding="utf-8", errors="replace")
        if "[idax processor]" in log_text and "failed:" in log_text:
            detail = _redact(
                log_text[-4000:],
                (run_dir, build_dir, ida_dir, fixture.parent, Path.home()),
            )
            raise ValidationError(f"processor bridge reported an error: {detail}")

    print("processor runtime smoke: PASS (idaxmini analyze/output through IDA)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("--ida-dir", type=Path, default=os.environ.get("IDADIR"))
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "tests"
        / "fixtures"
        / "procmod"
        / "minimal_procmod.bin",
    )
    args = parser.parse_args()
    if args.ida_dir is None:
        print("error: IDADIR is required for processor runtime validation", file=sys.stderr)
        return 1
    try:
        run_smoke(args.build_dir, args.ida_dir, args.fixture)
    except (OSError, subprocess.SubprocessError, ValidationError) as error:
        detail = _redact(
            str(error),
            (args.build_dir, args.ida_dir, args.fixture.parent, Path.home()),
        )
        print(f"error: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
