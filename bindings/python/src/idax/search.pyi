from enum import Enum
from typing import overload

class Direction(Enum):
    FORWARD = ...
    BACKWARD = ...

class TextOptions:
    direction: Direction
    case_sensitive: bool
    regex: bool
    identifier: bool
    skip_start: bool
    no_break: bool
    no_show: bool
    break_on_cancel: bool
    def __init__(self) -> None: ...

class ImmediateOptions:
    direction: Direction
    skip_start: bool
    no_break: bool
    no_show: bool
    break_on_cancel: bool
    def __init__(self) -> None: ...

class BinaryPatternOptions:
    direction: Direction
    skip_start: bool
    no_break: bool
    no_show: bool
    break_on_cancel: bool
    def __init__(self) -> None: ...

@overload
def text(query: str, start: int, direction: Direction = ...,
         case_sensitive: bool = ...) -> int: ...
@overload
def text(query: str, start: int, options: TextOptions) -> int: ...
@overload
def immediate(value: int, start: int, direction: Direction = ...) -> int: ...
@overload
def immediate(value: int, start: int, options: ImmediateOptions) -> int: ...
@overload
def binary_pattern(hex_pattern: str, start: int,
                   direction: Direction = ...) -> int: ...
@overload
def binary_pattern(hex_pattern: str, start: int,
                   options: BinaryPatternOptions) -> int: ...
def next_code(address: int) -> int: ...
def next_data(address: int) -> int: ...
def next_unknown(address: int) -> int: ...
def next_error(address: int) -> int: ...
def next_defined(address: int) -> int: ...
