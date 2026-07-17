#!/usr/bin/env python3
"""Reject identity-bearing home paths and canonical license IDs in CI logs."""

from __future__ import annotations

import argparse
import os
import re
import sys
import zipfile
from pathlib import Path


MAX_LOG_ENTRIES = 1_000
MAX_UNCOMPRESSED_BYTES = 1 << 30

LICENSE_PATTERN = re.compile(
    rb"(?<![0-9A-Fa-f])[0-9A-F]{2}-[0-9A-F]{4}-"
    rb"[0-9A-F]{4}-[0-9A-F]{2}(?![0-9A-Fa-f])",
    re.IGNORECASE,
)
POSIX_HOME_PATTERN = re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+")
WINDOWS_HOME_PATTERN = re.compile(
    rb"[A-Za-z]:\\Users\\[A-Za-z0-9._~-]+", re.IGNORECASE
)

ALLOWED_POSIX_HOMES = {
    b"/" + root + b"/" + b"runner" for root in (b"home", b"Users")
}
ALLOWED_WINDOWS_USERS = {b"runner", b"runneradmin", b"runner~1"}


def report_error(message: str) -> None:
    """Report only sanitized diagnostics, including a public Actions annotation."""

    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::error title=CI log privacy::{message}", file=sys.stderr)
    else:
        print(f"error: {message}", file=sys.stderr)


def sensitive_categories(data: bytes) -> set[str]:
    """Return privacy categories without echoing matched sensitive values."""

    categories: set[str] = set()
    if LICENSE_PATTERN.search(data):
        categories.add("canonical license identifier")

    if any(
        match.group(0) not in ALLOWED_POSIX_HOMES
        for match in POSIX_HOME_PATTERN.finditer(data)
    ):
        categories.add("non-runner POSIX home path")

    for match in WINDOWS_HOME_PATTERN.finditer(data):
        username = match.group(0).rsplit(b"\\", 1)[-1].lower()
        if username not in ALLOWED_WINDOWS_USERS:
            categories.add("non-runner Windows home path")
            break
    return categories


def scan_archive(path: Path) -> tuple[list[tuple[int, str]], int, int]:
    """Scan one GitHub Actions log archive without extracting it."""

    failures: list[tuple[int, str]] = []
    total_bytes = 0
    with zipfile.ZipFile(path) as archive:
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        if not entries:
            raise ValueError("archive contains no log entries")
        if len(entries) > MAX_LOG_ENTRIES:
            raise ValueError("archive contains too many log entries")

        for ordinal, entry in enumerate(entries, start=1):
            if entry.flag_bits & 0x1:
                raise ValueError("archive contains an encrypted log entry")
            total_bytes += entry.file_size
            if total_bytes > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("archive exceeds the uncompressed size limit")
            data = archive.read(entry)
            if len(data) != entry.file_size:
                raise ValueError("archive returned a truncated log entry")
            for category in sorted(sensitive_categories(data)):
                failures.append((ordinal, category))
    return failures, len(entries), total_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="GitHub Actions run-log ZIP")
    args = parser.parse_args()

    try:
        failures, entry_count, total_bytes = scan_archive(args.archive)
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        report_error(f"scan failed: {error}")
        return 1

    if failures:
        for ordinal, category in failures:
            report_error(f"log entry {ordinal}: {category}")
        return 1

    print(
        "CI log privacy: PASS "
        f"({entry_count} entries, {total_bytes} uncompressed bytes)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
