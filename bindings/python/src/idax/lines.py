"""Source mappings and IDA tagged-text manipulation."""

from ._native.lines import (
    COLOR_ADDR,
    COLOR_ADDR_SIZE,
    COLOR_ESC,
    COLOR_INV,
    COLOR_OFF,
    COLOR_ON,
    Color,
    SourceFile,
    add_source_file,
    colstr,
    decode_addr_tag,
    make_addr_tag,
    remove_source_file,
    source_file_at,
    tag_advance,
    tag_remove,
    tag_strlen,
)

__all__ = [
    "COLOR_ADDR", "COLOR_ADDR_SIZE", "COLOR_ESC", "COLOR_INV", "COLOR_OFF",
    "COLOR_ON", "Color", "SourceFile", "add_source_file", "colstr",
    "decode_addr_tag", "make_addr_tag", "remove_source_file",
    "source_file_at", "tag_advance", "tag_remove", "tag_strlen",
]
