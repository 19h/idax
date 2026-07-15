"""Text, immediate, binary-pattern, and item searches."""

from ._native.search import (
    BinaryPatternOptions,
    Direction,
    ImmediateOptions,
    TextOptions,
    binary_pattern,
    immediate,
    next_code,
    next_data,
    next_defined,
    next_error,
    next_unknown,
    text,
)

__all__ = [
    "BinaryPatternOptions", "Direction", "ImmediateOptions", "TextOptions",
    "binary_pattern", "immediate", "next_code", "next_data",
    "next_defined", "next_error", "next_unknown", "text",
]
