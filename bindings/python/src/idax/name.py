"""Naming, demangling, inventory, and name properties."""

from ._native.name import (
    DemangleForm,
    Entry,
    ListOptions,
    all,
    all_user_defined,
    demangled,
    force_set,
    get,
    is_auto_generated,
    is_public,
    is_user_defined,
    is_valid_identifier,
    is_weak,
    remove,
    resolve,
    sanitize_identifier,
    set,
    set_public,
    set_weak,
)

__all__ = [
    "DemangleForm", "Entry", "ListOptions", "all", "all_user_defined",
    "demangled", "force_set", "get", "is_auto_generated", "is_public",
    "is_user_defined", "is_valid_identifier", "is_weak", "remove",
    "resolve", "sanitize_identifier", "set", "set_public", "set_weak",
]
