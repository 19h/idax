"""Resolve user-supplied IDA runtime libraries before loading ``_native``."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

_handles: list[object] = []


def _candidate_directories() -> list[Path]:
    candidates: list[Path] = []
    configured = os.environ.get("IDADIR")
    if configured:
        candidates.append(Path(configured))

    if sys.platform == "darwin":
        candidates.append(
            Path("/Applications")
            / "IDA Professional 9.4.app"
            / "Contents"
            / "MacOS"
        )

    return candidates


def prepare() -> None:
    """Make an installed IDA runtime visible to the native extension loader."""
    if os.name == "nt":
        add_dll_directory = getattr(os, "add_dll_directory", None)
        if add_dll_directory is None:
            return
        for directory in _candidate_directories():
            if directory.is_dir():
                _handles.append(add_dll_directory(str(directory)))
                return
        return

    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    for directory in _candidate_directories():
        try:
            _handles.append(
                ctypes.CDLL(str(directory / f"libida{suffix}"), mode=ctypes.RTLD_GLOBAL)
            )
            _handles.append(
                ctypes.CDLL(
                    str(directory / f"libidalib{suffix}"), mode=ctypes.RTLD_GLOBAL
                )
            )
        except OSError:
            _handles.clear()
            continue
        return
