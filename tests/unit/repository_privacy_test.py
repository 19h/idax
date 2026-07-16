#!/usr/bin/env python3
"""Regression tests for repository and binary-fixture privacy checks."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import sanitize_ida_fixture as privacy  # noqa: E402
import check_repository_privacy as repository_privacy  # noqa: E402


class RepositoryPrivacyTests(unittest.TestCase):
    def test_sanitizer_preserves_length_and_repeated_owner_mapping(self) -> None:
        original = (
            b'{"email":"person@example.com","id":"96-'
            + b'1234-ABCD-00","owner":"96-'
            + b'1234-ABCD-00","path":"/'
            + b'home/person/project"}'
        )
        sanitized, counts = privacy.sanitize_bytes(original)
        self.assertEqual(len(sanitized), len(original))
        self.assertEqual(counts, {"paths": 1, "licenses": 2, "emails": 1})
        self.assertNotIn(b"person", sanitized)
        self.assertEqual(sanitized.count(b"96-0000-0000-01"), 2)
        self.assertFalse(privacy.sensitive_categories(sanitized))

    def test_scanner_accepts_reserved_synthetic_identifiers(self) -> None:
        self.assertFalse(
            privacy.sensitive_categories(b"96-0000-0000-01 97-0000-0000-FF")
        )

    def test_scanner_rejects_posix_windows_and_license_material(self) -> None:
        sample = (
            b"/" + b"Users/private/work C:\\" + b"Users\\private\\work "
            + b"96-" + b"1234-ABCD-00"
        )
        categories = privacy.sensitive_categories(sample, binary=False)
        self.assertIn("identity-bearing absolute path", categories)
        self.assertIn("non-synthetic canonical license identifier", categories)

    def test_binary_email_detection_does_not_police_source_attribution(self) -> None:
        sample = b"contact@example.com"
        self.assertFalse(privacy.sensitive_categories(sample, binary=False))
        self.assertIn(
            "email address embedded in binary data",
            privacy.sensitive_categories(sample, binary=True),
        )

    def test_candidate_reader_scans_symlink_text_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            target = root / "target.bin"
            target.write_bytes(b"unrelated target contents")
            link = root / "fixture-link"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable on this host")
            data, binary = repository_privacy.read_candidate(link) or (b"", True)
            self.assertEqual(
                data,
                os.readlink(link).encode("utf-8", errors="surrogateescape"),
            )
            self.assertNotEqual(data, target.read_bytes())
            self.assertFalse(binary)

    def test_workflow_acquisition_roots_are_not_repository_candidates(self) -> None:
        candidates = b"ida-installer/installer.run\nida-sdk/src/include/pro.h\n"
        completed = subprocess.run(
            ["git", "check-ignore", "--stdin"],
            cwd=ROOT,
            input=candidates,
            check=True,
            capture_output=True,
        )
        self.assertEqual(
            set(completed.stdout.splitlines()),
            set(candidates.splitlines()),
        )


if __name__ == "__main__":
    unittest.main()
