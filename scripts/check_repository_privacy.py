#!/usr/bin/env python3
"""Reject identity-bearing paths and credentials in project-owned Git files."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from sanitize_ida_fixture import sensitive_categories


ROOT = Path(__file__).resolve().parents[1]


def candidate_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        ROOT / raw.decode("utf-8", errors="surrogateescape")
        for raw in completed.stdout.split(b"\0")
        if raw
    ]


def read_candidate(path: Path) -> tuple[bytes, bool] | None:
    if path.is_symlink():
        return os.readlink(path).encode("utf-8", errors="surrogateescape"), False
    # A submodule appears as a Git path but is a directory in the worktree;
    # its independently versioned contents are outside this repository tree.
    if not path.is_file():
        return None
    data = path.read_bytes()
    return data, b"\0" in data


def scan_candidates() -> tuple[list[tuple[str, str]], int]:
    failures: list[tuple[str, str]] = []
    scanned = 0
    for path in candidate_files():
        try:
            candidate = read_candidate(path)
        except OSError as error:
            failures.append((str(path.relative_to(ROOT)), f"read error: {error.strerror}"))
            continue
        if candidate is None:
            continue
        data, binary = candidate
        scanned += 1
        for category in sensitive_categories(data, binary=binary):
            failures.append((str(path.relative_to(ROOT)), category))
    return failures, scanned


def scan_history(reference: str) -> tuple[list[tuple[str, str]], int]:
    listed = subprocess.run(
        ["git", "rev-list", "--objects", reference],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths: dict[bytes, set[str]] = defaultdict(set)
    object_order: list[bytes] = []
    seen: set[bytes] = set()
    for line in listed.stdout.splitlines():
        object_id, separator, raw_path = line.partition(b" ")
        if object_id not in seen:
            seen.add(object_id)
            object_order.append(object_id)
        if separator:
            paths[object_id].add(
                raw_path.decode("utf-8", errors="surrogateescape")
            )

    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("unable to open git cat-file batch streams")

    failures: set[tuple[str, str]] = set()
    scanned = 0
    try:
        for object_id in object_order:
            process.stdin.write(object_id + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n").split()
            if len(header) != 3:
                raise RuntimeError("unexpected git cat-file batch response")
            object_type = header[1]
            size = int(header[2])
            data = process.stdout.read(size)
            trailer = process.stdout.read(1)
            if len(data) != size or trailer != b"\n":
                raise RuntimeError("truncated git cat-file batch response")
            if object_type not in {b"blob", b"commit", b"tag"}:
                continue
            scanned += 1
            binary = object_type == b"blob" and b"\0" in data
            categories = sensitive_categories(data, binary=binary)
            if not categories:
                continue
            labels = paths.get(object_id) or {"<commit-or-tag-metadata>"}
            for label in labels:
                for category in categories:
                    failures.add((label, f"historical {category}"))
    finally:
        process.stdin.close()
        process.wait(timeout=10)
    return sorted(failures), scanned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--history-ref",
        help="also scan every blob, commit, and tag reachable from this ref",
    )
    args = parser.parse_args()

    try:
        failures, scanned = scan_candidates()
        history_scanned = 0
        if args.history_ref:
            history_failures, history_scanned = scan_history(args.history_ref)
            failures.extend(history_failures)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: repository privacy scan failed: {error}", file=sys.stderr)
        return 1

    if failures:
        for relative, category in failures:
            print(f"error: {relative}: {category}", file=sys.stderr)
        return 1
    detail = f"{scanned} project-owned files byte-scanned"
    if args.history_ref:
        detail += f", {history_scanned} reachable blobs/commits/tags"
    print(f"Repository privacy: PASS ({detail})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
