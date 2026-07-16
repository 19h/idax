"""Opaque scoped access to persistent IDA plugin configuration."""

from ._native.registry import Store, StringListUpdate, ValueKind

__all__ = ["Store", "StringListUpdate", "ValueKind"]
