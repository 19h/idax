#!/usr/bin/env python3
"""Select an active named IDA product license from HCLI rich-table output."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date


LICENSE_ID_PATTERN = re.compile(
    r"^[0-9A-F]{2}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{2}$"
)
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
EDITION_PRIORITIES = (
    ("IDA Ultimate", 0),
    ("IDA Professional", 1),
    ("IDA Pro", 1),
    ("IDA Essential", 2),
)
MAX_PLAUSIBLE_EXPIRATION_YEAR = 2100


@dataclass(frozen=True)
class LicenseRow:
    license_id: str
    edition: str
    license_type: str
    status: str
    expiration: str
    source_index: int


def _parse_rows(output: str) -> list[LicenseRow]:
    rows: list[LicenseRow] = []
    pending_columns: list[str] | None = None
    pending_source_index = 0

    def finish_pending() -> None:
        nonlocal pending_columns
        if pending_columns is None:
            return
        license_id, edition, license_type, status, expiration = pending_columns
        rows.append(
            LicenseRow(
                license_id=license_id,
                edition=edition,
                license_type=license_type,
                status=status,
                expiration=expiration,
                source_index=pending_source_index,
            )
        )
        pending_columns = None

    for source_index, raw_line in enumerate(output.splitlines()):
        line = ANSI_ESCAPE_PATTERN.sub("", raw_line)
        delimiter = "│" if "│" in line else "|" if "|" in line else None
        if delimiter is None:
            finish_pending()
            continue

        columns = [column.strip() for column in line.split(delimiter)]
        if len(columns) < 6:
            finish_pending()
            continue

        row_columns = columns[1:6]
        license_id = row_columns[0]
        if LICENSE_ID_PATTERN.fullmatch(license_id):
            finish_pending()
            pending_columns = row_columns
            pending_source_index = source_index
            continue

        if license_id:
            finish_pending()
            continue

        if pending_columns is not None:
            for column_index, fragment in enumerate(row_columns[1:], start=1):
                if fragment:
                    pending_columns[column_index] = (
                        f"{pending_columns[column_index]} {fragment}".strip()
                    )

    finish_pending()
    return rows


def _edition_priority(edition: str) -> int | None:
    for prefix, priority in EDITION_PRIORITIES:
        if edition == prefix or edition.startswith(f"{prefix} "):
            return priority
    return None


def select_license_id(output: str) -> str | None:
    candidates: list[tuple[int, int, int, str]] = []
    for row in _parse_rows(output):
        priority = _edition_priority(row.edition)
        if priority is None or row.license_type != "named" or row.status != "Active":
            continue
        try:
            expiration = date.fromisoformat(row.expiration)
        except ValueError:
            continue
        if expiration.year > MAX_PLAUSIBLE_EXPIRATION_YEAR:
            continue
        candidates.append(
            (priority, -expiration.toordinal(), row.source_index, row.license_id)
        )

    if not candidates:
        return None
    candidates.sort()
    return candidates[0][3]


def main() -> int:
    output = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    license_id = select_license_id(output)
    if license_id is None:
        print(
            "error: HCLI returned no active named installable IDA product license",
            file=sys.stderr,
        )
        return 2
    print(license_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
