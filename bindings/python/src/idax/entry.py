"""Program entry points."""

from ._native.entry import (
    EntryPoint,
    add,
    by_index,
    by_ordinal,
    clear_forwarder,
    count,
    forwarder,
    rename,
    set_forwarder,
)

__all__ = [
    "EntryPoint", "add", "by_index", "by_ordinal", "clear_forwarder",
    "count", "forwarder", "rename", "set_forwarder",
]
