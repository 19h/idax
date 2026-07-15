"""Relocation descriptors, traversal, and custom handlers."""

from ._native.fixup import (
    CustomHandler,
    Descriptor,
    FixupRange,
    HandlerProperty,
    Type,
    all,
    at,
    contains,
    exists,
    find_custom,
    first,
    in_range,
    next,
    prev,
    register_custom,
    remove,
    set,
    unregister_custom,
)

__all__ = [
    "CustomHandler", "Descriptor", "FixupRange", "HandlerProperty", "Type",
    "all", "at", "contains", "exists", "find_custom", "first", "in_range",
    "next", "prev", "register_custom", "remove", "set", "unregister_custom",
]
