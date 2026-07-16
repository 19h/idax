#!/usr/bin/env python3
"""Remove fixed-width identity and license metadata from an IDA fixture."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


LICENSE_PATTERN = re.compile(
    rb"(?<![0-9A-Fa-f])([0-9A-F]{2})-([0-9A-F]{4})-"
    rb"([0-9A-F]{4})-([0-9A-F]{2})(?![0-9A-Fa-f])"
)
EMAIL_PATTERN = re.compile(
    rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
POSIX_HOME_PATTERN = re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+")
WINDOWS_HOME_PATTERN = re.compile(
    rb"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+", re.IGNORECASE
)


def is_synthetic_license(identifier: bytes) -> bool:
    match = LICENSE_PATTERN.fullmatch(identifier)
    return bool(match and match.group(2) == b"0000" and match.group(3) == b"0000")


def _fixed_width(marker: bytes, size: int) -> bytes:
    if len(marker) >= size:
        return marker[:size]
    return marker + (b"_" * (size - len(marker)))


def sensitive_categories(data: bytes, *, binary: bool = True) -> set[str]:
    categories: set[str] = set()
    if POSIX_HOME_PATTERN.search(data) or WINDOWS_HOME_PATTERN.search(data):
        categories.add("identity-bearing absolute path")
    if any(not is_synthetic_license(match.group(0))
           for match in LICENSE_PATTERN.finditer(data)):
        categories.add("non-synthetic canonical license identifier")
    if binary and EMAIL_PATTERN.search(data):
        categories.add("email address embedded in binary data")
    return categories


def sanitize_bytes(data: bytes) -> tuple[bytes, dict[str, int]]:
    counts = {"paths": 0, "licenses": 0, "emails": 0}

    def replace_path(match: re.Match[bytes]) -> bytes:
        counts["paths"] += 1
        return _fixed_width(b"/REDACTED", len(match.group(0)))

    data = POSIX_HOME_PATTERN.sub(replace_path, data)

    def replace_windows_path(match: re.Match[bytes]) -> bytes:
        counts["paths"] += 1
        return _fixed_width(b"X:\\REDACTED", len(match.group(0)))

    data = WINDOWS_HOME_PATTERN.sub(replace_windows_path, data)

    replacements: dict[bytes, bytes] = {}

    def replace_license(match: re.Match[bytes]) -> bytes:
        identifier = match.group(0)
        if is_synthetic_license(identifier):
            return identifier
        replacement = replacements.get(identifier)
        if replacement is None:
            ordinal = len(replacements) + 1
            replacement = match.group(1) + b"-0000-0000-" + f"{ordinal:02X}".encode()
            replacements[identifier] = replacement
        counts["licenses"] += 1
        return replacement

    data = LICENSE_PATTERN.sub(replace_license, data)

    def replace_email(match: re.Match[bytes]) -> bytes:
        counts["emails"] += 1
        return _fixed_width(b"[REDACTED]", len(match.group(0)))

    data = EMAIL_PATTERN.sub(replace_email, data)
    return data, counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument(
        "--check", action="store_true", help="fail if sensitive metadata remains"
    )
    args = parser.parse_args()
    try:
        original = args.fixture.read_bytes()
    except OSError as error:
        print(f"error: unable to read fixture: {error.strerror}", file=sys.stderr)
        return 1

    if args.check:
        categories = sensitive_categories(original)
        if categories:
            print(
                "error: fixture contains " + ", ".join(sorted(categories)),
                file=sys.stderr,
            )
            return 1
        print(f"IDA fixture privacy: PASS ({args.fixture.name})")
        return 0

    sanitized, counts = sanitize_bytes(original)
    if sensitive_categories(sanitized):
        print("error: sanitizer left prohibited metadata", file=sys.stderr)
        return 1
    if len(sanitized) != len(original):
        print("error: sanitizer changed fixture length", file=sys.stderr)
        return 1
    if sanitized != original:
        try:
            args.fixture.write_bytes(sanitized)
        except OSError as error:
            print(f"error: unable to write fixture: {error.strerror}", file=sys.stderr)
            return 1
    print(
        f"IDA fixture sanitized: {args.fixture.name} "
        f"({counts['paths']} paths, {counts['licenses']} license references, "
        f"{counts['emails']} emails)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
