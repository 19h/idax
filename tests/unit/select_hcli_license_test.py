#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "select_hcli_license.py"
sys.path.insert(0, str(SCRIPT_PATH.parent))

from select_hcli_license import select_license_id  # noqa: E402


class SelectHcliLicenseTests(unittest.TestCase):
    def test_server_first_table_selects_active_ultimate(self) -> None:
        output = """
│ 96-0000-0000-01 │ IDA Teams Server  │ computer │ To_Activate │ Never      │ None │
│ 96-0000-0000-02 │ IDA Lumina Server │ computer │ Active      │ Never      │ None │
│ 96-0000-0000-03 │ IDA Free PC       │ named    │ Active      │ 2027-04-22 │ None │
│ 96-0000-0000-04 │ IDA Ultimate      │ named    │ Active      │ 2027-02-06 │ None │
"""
        self.assertEqual(select_license_id(output), "96-0000-0000-04")

    def test_prefers_ultimate_over_earlier_supported_editions(self) -> None:
        output = """
| 96-0000-0000-10 | IDA Essential PC | named | Active | 2027-01-01 | None |
| 96-0000-0000-11 | IDA Essential PC | named | Active | 2027-01-01 | None |
| 96-0000-0000-12 | IDA Ultimate     | named | Active | 2027-01-01 | None |
"""
        self.assertEqual(select_license_id(output), "96-0000-0000-12")

    def test_preserves_table_order_within_priority(self) -> None:
        output = """
│ 96-0000-0000-20 │ IDA Ultimate │ named │ Active │ 2030-01-01 │ None │
│ 96-0000-0000-21 │ IDA Ultimate │ named │ Active │ 2040-01-01 │ None │
"""
        self.assertEqual(select_license_id(output), "96-0000-0000-20")

    def test_strips_ansi_decoration(self) -> None:
        output = (
            "\x1b[32m│ 96-0000-0000-30 │ IDA Professional │ named │ Active │ "
            "2030-01-01 │ None │\x1b[0m"
        )
        self.assertEqual(select_license_id(output), "96-0000-0000-30")

    def test_reconstructs_wrapped_rich_rows(self) -> None:
        output = """
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ ID              ┃ Edition    ┃ Type     ┃ Status    ┃ Expiration ┃ Addons    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ 96-0000-0000-31 │ IDA Teams  │ computer │ To_Activ… │ Never      │ None      │
│                 │ Server     │          │           │            │           │
│ 96-0000-0000-32 │ IDA        │ named    │ Active    │ 2027-02-06 │ 12        │
│                 │ Ultimate   │          │           │            │ decompil… │
│                 │            │          │           │            │ + TEAMS   │
└─────────────────┴────────────┴──────────┴───────────┴────────────┴───────────┘
"""
        self.assertEqual(select_license_id(output), "96-0000-0000-32")

    def test_rejects_inactive_non_named_free_and_malformed_rows(self) -> None:
        output = """
│ not-an-id        │ IDA Ultimate     │ named    │ Active      │ Never │ None │
│ 96-0000-0000-40 │ IDA Ultimate     │ named    │ Expired     │ Never │ None │
│ 96-0000-0000-41 │ IDA Ultimate     │ computer │ Active      │ Never │ None │
│ 96-0000-0000-42 │ IDA Free PC      │ named    │ Active      │ Never │ None │
│ 96-0000-0000-43 │ IDA Teams Server │ named    │ Active      │ Never │ None │
│ 96-0000-0000-44 │ IDA Home PC      │ named    │ Active      │ Never │ None │
"""
        self.assertIsNone(select_license_id(output))

    def test_cli_fails_closed_without_echoing_input(self) -> None:
        rejected_id = "96-0000-0000-50"
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            input=(
                f"│ {rejected_id} │ IDA Teams Server │ computer │ "
                "To_Activate │ Never │ None │\n"
            ),
            encoding="utf-8",
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("no active named installable IDA product license", result.stderr)
        self.assertNotIn(rejected_id, result.stderr)

    def test_cli_reads_utf8_rich_table_independent_of_parent_locale(self) -> None:
        selected_id = "96-0000-0000-51"
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            input=(
                f"│ {selected_id} │ IDA Ultimate │ named │ Active │ "
                "2030-01-01 │ None │\n"
            ),
            encoding="utf-8",
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), selected_id)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
