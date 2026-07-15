"""Python bindings for the opaque, concept-oriented IDAX API.

The public package is split into domain modules that mirror the C++ namespace
layout while following Python's snake-case naming and exception conventions.
"""

from __future__ import annotations

from typing import Final, TypeAlias

from . import _runtime

_runtime.prepare()

from . import (
    address,
    analysis,
    comment,
    core,
    data,
    database,
    debugger,
    decompiler,
    diagnostics,
    entry,
    error,
    event,
    fixup,
    function,
    graph,
    instruction,
    lines,
    lumina,
    name,
    path,
    plugin,
    loader,
    processor,
    search,
    segment,
    storage,
    type,
    ui,
    xref,
)
from ._native import __version__
from .error import (
    ConflictError,
    ErrorCategory,
    ErrorInfo,
    IdaxError,
    InternalError,
    NotFoundError,
    SdkError,
    UnsupportedError,
    ValidationError,
)

Address: TypeAlias = int
AddressDelta: TypeAlias = int
AddressSize: TypeAlias = int

BAD_ADDRESS: Final[int] = (1 << 64) - 1

__all__ = [
    "Address",
    "AddressDelta",
    "AddressSize",
    "BAD_ADDRESS",
    "ConflictError",
    "ErrorCategory",
    "ErrorInfo",
    "IdaxError",
    "InternalError",
    "NotFoundError",
    "SdkError",
    "UnsupportedError",
    "ValidationError",
    "__version__",
    "address",
    "analysis",
    "comment",
    "core",
    "data",
    "database",
    "debugger",
    "decompiler",
    "diagnostics",
    "entry",
    "error",
    "event",
    "fixup",
    "function",
    "graph",
    "instruction",
    "lines",
    "lumina",
    "name",
    "path",
    "plugin",
    "loader",
    "processor",
    "search",
    "segment",
    "storage",
    "type",
    "ui",
    "xref",
]
