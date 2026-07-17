#!/usr/bin/env python3
"""Offline regression tests for immutable GitHub action inventory policy."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import check_ci_action_pins as pins  # noqa: E402


class CiActionPinTests(unittest.TestCase):
    def test_repository_inventory_is_exact(self) -> None:
        failures, counts = pins.scan_repository()
        self.assertEqual(failures, [])
        self.assertEqual(sum(counts.values()), 35)

    def test_mutable_reference_is_rejected(self) -> None:
        failures, _ = pins.scan_text(
            "steps:\n  - uses: actions/checkout@v7\n", "fixture.yml"
        )
        self.assertIn("mutable action reference", failures[0])

    def test_unknown_external_action_is_rejected(self) -> None:
        failures, _ = pins.scan_text(
            "steps:\n  - uses: example/action@" + "a" * 40 + "\n",
            "fixture.yml",
        )
        self.assertIn("unreviewed external action", failures[0])

    def test_unreviewed_commit_is_rejected(self) -> None:
        failures, _ = pins.scan_text(
            "steps:\n  - uses: actions/checkout@" + "a" * 40 + "\n",
            "fixture.yml",
        )
        self.assertIn("unreviewed commit", failures[0])

    def test_unreviewed_local_action_is_rejected(self) -> None:
        failures, _ = pins.scan_text(
            "steps:\n  - uses: ./.github/actions/unknown\n", "fixture.yml"
        )
        self.assertIn("unreviewed local action", failures[0])

    def test_local_msvc_action_is_composite_and_node_free(self) -> None:
        action = (ROOT / ".github/actions/setup-msvc/action.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("using: composite", action)
        self.assertIn("setup-msvc.ps1", action)
        self.assertNotIn("node20", action)

    def test_node_setup_disables_new_automatic_cache(self) -> None:
        for relative in (
            ".github/workflows/bindings-ci.yml",
            ".github/workflows/node-plugin-release.yml",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            setup_count = text.count("actions/setup-node@")
            self.assertGreater(setup_count, 0)
            self.assertEqual(
                text.count("package-manager-cache: false"), setup_count
            )

    def test_homebrew_and_node20_action_references_are_absent(self) -> None:
        workflow_text = "\n".join(
            path.read_text(encoding="utf-8") for path in pins.workflow_paths()
        )
        self.assertNotIn("brew install llvm", workflow_text)
        self.assertNotIn("ilammy/msvc-dev-cmd", workflow_text)
        self.assertNotRegex(workflow_text, r"uses:\s+[^\s#]+@v\d")


if __name__ == "__main__":
    unittest.main()
