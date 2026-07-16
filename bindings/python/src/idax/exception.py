"""Architecture-independent C++ and structured-exception regions."""

from ._native.exception import (
    Block,
    BlockDefinition,
    CatchHandler,
    CatchSelector,
    CatchSelectorKind,
    CppHandlers,
    HandlerMetadata,
    Location,
    SehDisposition,
    SehHandler,
    add,
    contains,
    list,
    remove,
    system_region_start,
)

__all__ = [
    "Block",
    "BlockDefinition",
    "CatchHandler",
    "CatchSelector",
    "CatchSelectorKind",
    "CppHandlers",
    "HandlerMetadata",
    "Location",
    "SehDisposition",
    "SehHandler",
    "add",
    "contains",
    "list",
    "remove",
    "system_region_start",
]
