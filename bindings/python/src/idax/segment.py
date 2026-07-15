"""Segment snapshots, mutation, lookup, and traversal."""

from ._native.segment import (
    Permissions,
    Segment,
    SegmentRange,
    Type,
    all,
    at,
    by_index,
    by_name,
    comment,
    count,
    create,
    first,
    last,
    move,
    next,
    prev,
    remove,
    resize,
    set_bitness,
    set_class,
    set_comment,
    set_default_segment_register,
    set_default_segment_register_for_all,
    set_name,
    set_permissions,
    set_type,
)

__all__ = [
    "Permissions", "Segment", "SegmentRange", "Type", "all", "at",
    "by_index", "by_name", "comment", "count", "create", "first",
    "last", "move", "next", "prev", "remove", "resize", "set_bitness",
    "set_class", "set_comment", "set_default_segment_register",
    "set_default_segment_register_for_all", "set_name", "set_permissions",
    "set_type",
]
