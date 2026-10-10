#!/usr/bin/env python3
"""Require every source-registered native test in a full CTest run."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def expected_tests() -> set[str]:
    unit = (ROOT / "tests/unit/CMakeLists.txt").read_text(encoding="utf-8")
    integration = (ROOT / "tests/integration/CMakeLists.txt").read_text(encoding="utf-8")
    names = re.findall(r"add_test\(\s*NAME\s+(\w+)", unit)
    names += re.findall(r"^idax_add_integration_test\(\s*(\w+)", integration, re.M)
    if not names or len(names) != len(set(names)):
        raise ValueError("source test registration is empty or duplicated")
    if len(re.findall(r"\badd_test\(", unit)) != len(re.findall(r"add_test\(\s*NAME\s+(\w+)", unit)):
        raise ValueError("unit test registration grammar requires inventory review")
    return set(names)


def check_names(names: list[str], expected: set[str], label: str) -> None:
    if len(names) != len(set(names)):
        raise ValueError(f"{label} contains duplicate test identities")
    missing, extra = expected - set(names), set(names) - expected
    if missing or extra:
        raise ValueError(f"{label} mismatch: missing={sorted(missing)}, extra={sorted(extra)}")


def check_inventory(inventory: dict, expected: set[str]) -> None:
    check_names([test["name"] for test in inventory["tests"]], expected, "configured roster")


def check_results(results: ET.Element, expected: set[str]) -> None:
    cases = list(results.iter("testcase"))
    check_names([case.attrib["name"] for case in cases], expected, "JUnit results")
    failed = [case.attrib["name"] for case in cases if
              any(child.tag in {"failure", "error", "skipped"} for child in case)
              or case.get("status") in {"notrun", "disabled"}]
    if failed:
        raise ValueError(f"full suite contains failed or unexecuted cases: {sorted(failed)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--results", type=Path)
    options = parser.parse_args()
    try:
        expected = expected_tests()
        check_inventory(json.loads(options.inventory.read_text(encoding="utf-8")), expected)
        if options.results:
            check_results(ET.parse(options.results).getroot(), expected)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        print(f"Native full-suite inventory: FAIL ({error})", file=sys.stderr)
        return 1
    evidence = "configured and executed" if options.results else "configured"
    print(f"Native full-suite inventory: PASS ({len(expected)} {evidence} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
