from enum import IntEnum

class Kind(IntEnum):
    MISSING_OFFSET_BASE = 1
    MISSING_NAME = 2
    MISSING_FORCED_OPERAND = 3
    MISSING_COMMENT = 4
    MISSING_REFERENCES = 5
    IGNORED_JUMP_TABLE = 6
    DISASSEMBLY_FAILURE = 7
    ALREADY_ITEM_HEAD = 8
    FLOW_BEYOND_LIMITS = 9
    TOO_MANY_LINES = 10
    STACK_TRACE_FAILURE = 11
    ATTENTION = 12
    ANALYSIS_DECISION = 13
    ROLLED_BACK_DECISION = 14
    FLAIR_COLLISION = 15
    FLAIR_INDECISION = 16

def description(kind: Kind, address: int) -> str | None: ...
def remember(kind: Kind, address: int, message: str | None = ...) -> None: ...
def next(kind: Kind, at_or_after: int = ...) -> int | None: ...
def remove(kind: Kind, address: int) -> bool: ...
def name(kind: Kind, long_form: bool = ...) -> str: ...
def contains(kind: Kind, address: int) -> bool: ...
