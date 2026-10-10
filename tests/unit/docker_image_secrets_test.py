#!/usr/bin/env python3
"""Behavioral probes for saved-image credential detection."""

import gzip
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "image_secrets", ROOT / "scripts/check_docker_image_secrets.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def archive(payload: bytes, compressed: bool = False) -> io.BytesIO:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as tar:
        data = gzip.compress(payload) if compressed else payload
        member = tarfile.TarInfo("layer.tar.gz" if compressed else "layer.tar")
        member.size = len(data)
        tar.addfile(member, io.BytesIO(data))
    result.seek(0)
    return result


class ImageSecretTests(unittest.TestCase):
    def test_clean_plain_and_compressed(self):
        for compressed in (False, True):
            self.assertEqual(AUDIT.scan_image(archive(b"credential-free", compressed),
                                              (b"placeholder-token",)), (1, 15))

    def test_persisted_credentials_plain_and_compressed(self):
        for compressed in (False, True):
            with self.assertRaisesRegex(ValueError, "build credential found"):
                AUDIT.scan_image(archive(b"config=placeholder-token", compressed),
                                 (b"placeholder-token",))

    def test_block_boundary(self):
        data = b"x" * (AUDIT.BLOCK_SIZE - 5) + b"placeholder-token"
        with self.assertRaisesRegex(ValueError, "build credential found"):
            AUDIT.scan_image(archive(data, True), (b"placeholder-token",))

    def test_missing_secret(self):
        with self.assertRaisesRegex(ValueError, "nonempty"):
            AUDIT.scan_image(archive(b"clean"), (b"",))

    def test_unknown_compression(self):
        with self.assertRaisesRegex(ValueError, "zstd"):
            AUDIT.scan_image(archive(b"\x28\xb5\x2f\xfdpayload"), (b"token",))


if __name__ == "__main__":
    unittest.main()
