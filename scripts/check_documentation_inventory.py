#!/usr/bin/env python3
"""Check current documentation indexes against the public IDAX header inventory."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    headers = {path.name for path in (ROOT / "include/ida").glob("*.hpp")}
    domains = {name.removesuffix(".hpp") for name in headers
               if name not in {"idax.hpp", "core.hpp", "error.hpp"}}
    failures: list[str] = []
    reference = (ROOT / "docs/api_reference.md").read_text()
    listed = re.findall(r"\| `include/ida/(\w+\.hpp)` \|", reference)
    if set(listed) != headers or len(listed) != len(headers):
        failures.append(f"API index mismatch: missing={sorted(headers-set(listed))}, "
                        f"extra={sorted(set(listed)-headers)}, rows={len(listed)}")
    for filename in ("README.md", "docs/namespace_topology.md",
                     "docs/sdk_domain_coverage_matrix.md"):
        text = (ROOT / filename).read_text()
        missing = sorted(domain for domain in domains
                         if not re.search(r"\bida::" + re.escape(domain) + r"\b", text))
        if missing:
            failures.append(f"{filename}: missing public domains {missing}")
    readme = (ROOT / "README.md").read_text()
    expected = f"{len(headers)} public headers cover {len(domains)} concept domains"
    if expected not in readme:
        failures.append(f"README inventory must state: {expected}")
    selection = (ROOT / "docs/surface_selection_guide.md").read_text()
    for path in ("include/ida/*.hpp", "bindings/rust/idax", "bindings/rust/idax-sys",
                 "bindings/node", "bindings/python", "bindings/swift"):
        if f"| `{path}` |" not in selection:
            failures.append(f"Surface-selection table missing {path}")
    if failures:
        print("Documentation inventory: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Documentation inventory: PASS ({len(headers)} headers, "
          f"{len(domains)} concept domains, all language surfaces)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
