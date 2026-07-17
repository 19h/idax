"""Opaque address bookmark management."""

from ._native.bookmark import MAX_SLOTS, Bookmark, all, at, at_slot, remove, remove_slot, set

__all__ = [
    "MAX_SLOTS",
    "Bookmark",
    "all",
    "at",
    "at_slot",
    "remove",
    "remove_slot",
    "set",
]
