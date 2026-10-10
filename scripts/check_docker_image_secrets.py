#!/usr/bin/env python3
"""Scan a docker-save stream, including compressed layers, for build secrets."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import sys
import tarfile
from typing import BinaryIO


BLOCK_SIZE = 1 << 20


def contains_secret(stream: BinaryIO, secrets: tuple[bytes, ...]) -> tuple[bool, int]:
    overlap = max(map(len, secrets)) - 1
    tail = b""
    scanned = 0
    while block := stream.read(BLOCK_SIZE):
        scanned += len(block)
        window = tail + block
        if any(secret in window for secret in secrets):
            return True, scanned
        tail = window[-overlap:] if overlap else b""
    return False, scanned


def scan_image(stream: BinaryIO, secrets: tuple[bytes, ...]) -> tuple[int, int]:
    if not secrets or any(not secret for secret in secrets):
        raise ValueError("all requested secret values must be present and nonempty")
    members = total = 0
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("image member is unreadable")
            # BufferedReader provides lookahead without seeking a streaming tar.
            buffered = io.BufferedReader(extracted)
            magic = buffered.peek(4)[:4]
            if magic == b"\x28\xb5\x2f\xfd":
                raise ValueError("zstd image layers require conversion to gzip before audit")
            decoded = gzip.GzipFile(fileobj=buffered) if magic[:2] == b"\x1f\x8b" else buffered
            found, count = contains_secret(decoded, secrets)
            members += 1
            total += count
            if found:
                raise ValueError("build credential found in saved image content")
    if not members:
        raise ValueError("image archive contains no regular files")
    return members, total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-env", action="append", required=True)
    options = parser.parse_args()
    secrets = tuple(os.environ.get(name, "").encode() for name in options.secret_env)
    try:
        members, size = scan_image(sys.stdin.buffer, secrets)
    except (OSError, ValueError, tarfile.TarError, EOFError) as error:
        print(f"Docker image secret audit: FAIL ({error})", file=sys.stderr)
        return 1
    print(f"Docker image secret audit: PASS ({members} members, {size} decoded bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
