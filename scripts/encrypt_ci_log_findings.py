#!/usr/bin/env python3
"""Encrypt matched CI-log privacy prefixes for one-shot private diagnosis."""

from __future__ import annotations

import argparse
import base64
import subprocess
import sys
import zipfile
from pathlib import Path

from check_ci_log_privacy import (
    ALLOWED_POSIX_HOMES,
    ALLOWED_WINDOWS_USERS,
    LICENSE_PATTERN,
    POSIX_HOME_PATTERN,
    WINDOWS_HOME_PATTERN,
)


def matched_values(data: bytes) -> set[tuple[str, bytes]]:
    matches = {
        ("canonical-license", match.group(0))
        for match in LICENSE_PATTERN.finditer(data)
    }
    matches.update(
        ("posix-home", match.group(0))
        for match in POSIX_HOME_PATTERN.finditer(data)
        if match.group(0) not in ALLOWED_POSIX_HOMES
    )
    for match in WINDOWS_HOME_PATTERN.finditer(data):
        value = match.group(0)
        username = value.rsplit(b"\\", 1)[-1].lower()
        if username not in ALLOWED_WINDOWS_USERS:
            matches.add(("windows-home", value))
    return matches


def encrypt(public_key: Path, value: bytes) -> str:
    if len(value) > 128:
        raise ValueError("matched prefix exceeds diagnostic plaintext bound")
    completed = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            str(public_key),
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            "rsa_oaep_md:sha256",
            "-pkeyopt",
            "rsa_mgf1_md:sha256",
        ],
        input=value,
        check=True,
        capture_output=True,
    )
    return base64.b64encode(completed.stdout).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("public_key", type=Path)
    args = parser.parse_args()

    findings: set[tuple[str, bytes]] = set()
    try:
        with zipfile.ZipFile(args.archive) as archive:
            for entry in archive.infolist():
                if not entry.is_dir():
                    findings.update(matched_values(archive.read(entry)))
        if not findings:
            raise ValueError("no encryptable sensitive prefix was found")
        for ordinal, (category, value) in enumerate(sorted(findings), start=1):
            ciphertext = encrypt(args.public_key, value)
            print(
                "::notice title=Encrypted CI privacy finding "
                f"{ordinal} ({category})::{ciphertext}"
            )
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f"::error title=Encrypted CI privacy diagnosis::{error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
