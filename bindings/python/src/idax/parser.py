"""Third-party source-parser selection and type ingestion."""

from ._native.parser import (
    InputKind,
    Language,
    ParseOptions,
    ParseReport,
    option,
    parse_for,
    parse_with,
    parse_with_options,
    select,
    select_for,
    selected_name,
    set_arguments,
    set_option,
)

__all__ = [
    "InputKind",
    "Language",
    "ParseOptions",
    "ParseReport",
    "option",
    "parse_for",
    "parse_with",
    "parse_with_options",
    "select",
    "select_for",
    "selected_name",
    "set_arguments",
    "set_option",
]
