#!/usr/bin/env python3
"""Check omissions, duplicates, and unexecuted full-suite evidence."""

import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import check_native_test_inventory as inventory


class NativeInventoryTests(unittest.TestCase):
    def test_current_registration_includes_both_test_families(self):
        expected = inventory.expected_tests()
        self.assertIn("idax_unit_test", expected)
        self.assertIn("decompiler_semantic_metadata", expected)
        self.assertIn("loader_initialization_order", expected)

    def test_complete_inventory_and_results(self):
        expected = {"unit", "runtime"}
        inventory.check_inventory({"tests": [{"name": name} for name in expected]}, expected)
        inventory.check_results(ET.fromstring(
            '<testsuite><testcase name="unit"/><testcase name="runtime"/></testsuite>'), expected)

    def test_unit_only_roster_is_rejected(self):
        with self.assertRaises(ValueError):
            inventory.check_inventory({"tests": [{"name": "unit"}]}, {"unit", "runtime"})

    def test_duplicate_case_is_rejected(self):
        with self.assertRaises(ValueError):
            inventory.check_results(ET.fromstring(
                '<testsuite><testcase name="unit"/><testcase name="unit"/></testsuite>'), {"unit"})

    def test_missing_or_extra_results_are_rejected(self):
        for name in ("", "extra"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inventory.check_results(ET.fromstring(
                    f'<testsuite><testcase name="{name}"/></testsuite>'), {"unit"})

    def test_failed_skipped_and_disabled_cases_are_rejected(self):
        for child in ("failure", "error", "skipped"):
            with self.subTest(child=child), self.assertRaises(ValueError):
                inventory.check_results(ET.fromstring(
                    f'<testsuite><testcase name="unit"><{child}/></testcase></testsuite>'), {"unit"})
        with self.assertRaises(ValueError):
            inventory.check_results(ET.fromstring(
                '<testsuite><testcase name="unit" status="notrun"/></testsuite>'), {"unit"})


if __name__ == "__main__":
    unittest.main()
