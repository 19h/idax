#!/usr/bin/env python3
"""Require the reviewed immutable action inventory in every GitHub workflow."""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
LOCAL_MSVC_ACTION = "./.github/actions/setup-msvc"

EXPECTED_EXTERNAL_ACTIONS = {
    "actions/checkout": (
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        15,
    ),
    "actions/setup-node": (
        "820762786026740c76f36085b0efc47a31fe5020",
        3,
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        2,
    ),
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        1,
    ),
    "astral-sh/setup-uv": (
        "11f9893b081a58869d3b5fccaea48c9e9e46f990",
        6,
    ),
    "dtolnay/rust-toolchain": (
        "4cda84d5c5c54efe2404f9d843567869ab1699d4",
        1,
    ),
    "softprops/action-gh-release": (
        "1c214ab373197cfdedb8c44482a8faf4608192d7",
        1,
    ),
}
EXPECTED_LOCAL_ACTIONS = {LOCAL_MSVC_ACTION: 6}
USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")


def workflow_paths() -> list[Path]:
    return sorted((*WORKFLOW_ROOT.glob("*.yml"), *WORKFLOW_ROOT.glob("*.yaml")))


def scan_text(text: str, label: str) -> tuple[list[str], Counter[str]]:
    failures: list[str] = []
    counts: Counter[str] = Counter()
    for target in USES_PATTERN.findall(text):
        if target.startswith("./"):
            counts[target] += 1
            if target not in EXPECTED_LOCAL_ACTIONS:
                failures.append(f"{label}: unreviewed local action {target}")
            continue
        repository, separator, reference = target.rpartition("@")
        if not separator or not repository:
            failures.append(f"{label}: malformed external action {target}")
            continue
        counts[repository] += 1
        expected = EXPECTED_EXTERNAL_ACTIONS.get(repository)
        if expected is None:
            failures.append(f"{label}: unreviewed external action {repository}")
            continue
        expected_reference, _ = expected
        if not COMMIT_PATTERN.fullmatch(reference):
            failures.append(f"{label}: mutable action reference for {repository}")
        elif reference != expected_reference:
            failures.append(f"{label}: unreviewed commit for {repository}")
    return failures, counts


def scan_repository() -> tuple[list[str], Counter[str]]:
    failures: list[str] = []
    counts: Counter[str] = Counter()
    for path in workflow_paths():
        relative = path.relative_to(ROOT).as_posix()
        path_failures, path_counts = scan_text(
            path.read_text(encoding="utf-8"), relative
        )
        failures.extend(path_failures)
        counts.update(path_counts)

    for repository, (_, expected_count) in EXPECTED_EXTERNAL_ACTIONS.items():
        if counts[repository] != expected_count:
            failures.append(
                f"action count for {repository}: "
                f"expected {expected_count}, found {counts[repository]}"
            )
    for target, expected_count in EXPECTED_LOCAL_ACTIONS.items():
        if counts[target] != expected_count:
            failures.append(
                f"action count for {target}: "
                f"expected {expected_count}, found {counts[target]}"
            )
    return failures, counts


def main() -> int:
    failures, counts = scan_repository()
    if failures:
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
        return 1
    print(
        "CI action pins: PASS "
        f"({sum(counts.values())} uses, "
        f"{len(EXPECTED_EXTERNAL_ACTIONS)} external actions, "
        f"{len(EXPECTED_LOCAL_ACTIONS)} local action)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
