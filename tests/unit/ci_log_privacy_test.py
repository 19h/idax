#!/usr/bin/env python3
"""Regression tests for the GitHub Actions complete-log privacy scanner."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts" / "check_ci_log_privacy.py"


def write_archive(path: Path, entries: list[bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, data in enumerate(entries):
            archive.writestr(f"job-{index}.txt", data)


def run_scanner(
    path: Path, *, github_actions: bool = False
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("GITHUB_ACTIONS", None)
    if github_actions:
        environment["GITHUB_ACTIONS"] = "true"
    return subprocess.run(
        [sys.executable, str(SCANNER), str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def posix_home(root: bytes, username: bytes, suffix: bytes = b"") -> bytes:
    return b"/" + root + b"/" + username + suffix


def windows_home(username: bytes, suffix: bytes = b"") -> bytes:
    return b"C:" + b"\\" + b"Users" + b"\\" + username + suffix


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="idax-ci-log-privacy-") as raw_tmp:
        tmp = Path(raw_tmp)

        safe = tmp / "safe.zip"
        write_archive(
            safe,
            [
                b"workspace="
                + posix_home(b"home", b"runner", b"/work/idax/idax")
                + b"\nlicense=***\n",
                b"workspace="
                + posix_home(b"Users", b"runner", b"/work/idax/idax")
                + b"\n",
                b"workspace="
                + windows_home(b"runneradmin", b"\\AppData\\Local")
                + b"\n",
                b"workspace="
                + windows_home(b"RUNNER~1", b"\\AppData\\Local")
                + b"\n",
                b"normalized-workspace="
                + posix_home(b"Users", b"RUNNER", b"/work/idax/idax")
                + b"\n",
            ],
        )
        safe_result = run_scanner(safe)
        require(safe_result.returncode == 0, safe_result.stderr)
        require("CI log privacy: PASS" in safe_result.stdout, safe_result.stdout)

        cases = {
            "license": b"selected " + b"96-" + b"1234-" + b"ABCD-" + b"7F\n",
            "lowercase-license": (
                b"selected " + b"96-" + b"1234-" + b"abcd-" + b"7f\n"
            ),
            "posix-home": (
                b"workspace="
                + posix_home(b"home", b"privateuser", b"/project")
                + b"\n"
            ),
            "mac-home": (
                b"workspace="
                + posix_home(b"Users", b"privateuser", b"/project")
                + b"\n"
            ),
            "uppercase-mac-home": (
                b"workspace="
                + posix_home(b"Users", b"PRIVATEUSER", b"/project")
                + b"\n"
            ),
            "windows-home": (
                b"workspace="
                + windows_home(b"privateuser", b"\\project")
                + b"\n"
            ),
        }
        for name, payload in cases.items():
            archive = tmp / f"{name}.zip"
            write_archive(archive, [payload])
            result = run_scanner(
                archive, github_actions=name == "lowercase-license"
            )
            require(result.returncode == 1, f"{name}: expected rejection")
            if name == "lowercase-license":
                require(
                    "::error title=CI log privacy::log entry 1:" in result.stderr,
                    result.stderr,
                )
            else:
                require("error: log entry 1:" in result.stderr, result.stderr)
            require(payload.decode().strip() not in result.stderr, result.stderr)

        empty = tmp / "empty.zip"
        write_archive(empty, [])
        empty_result = run_scanner(empty)
        require(empty_result.returncode == 1, "empty archive was accepted")

        malformed = tmp / "malformed.zip"
        malformed.write_bytes(b"not a ZIP")
        malformed_result = run_scanner(malformed)
        require(malformed_result.returncode == 1, "malformed archive was accepted")

    print("ci log privacy tests: PASS (5 safe entries, 8 rejection paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
