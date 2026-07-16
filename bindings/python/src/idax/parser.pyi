from collections.abc import Iterable
from enum import Enum

class Language(Enum):
    C = 1
    CPP = 2
    OBJECTIVE_C = 4
    SWIFT = 8
    GO = 16
    OBJECTIVE_CPP = 32

class InputKind(Enum):
    SOURCE_TEXT = 0
    FILE_PATH = 1

class ParseOptions:
    def __init__(self) -> None: ...
    input_kind: InputKind
    discard_result: bool
    define_base_macros: bool
    suppress_warnings: bool
    ignore_errors: bool
    allow_redeclarations: bool
    no_decorate: bool
    assume_high_level: bool
    lower_prototypes: bool
    raw_argument_names: bool
    relaxed_namespaces: bool
    exclude_base_types: bool
    allow_missing_semicolon: bool
    standalone_declaration: bool
    allow_void: bool
    no_mangle: bool
    pack_alignment: int

class ParseReport:
    def __init__(self) -> None: ...
    error_count: int
    @property
    def ok(self) -> bool: ...
    def __bool__(self) -> bool: ...

LanguageSet = Language | Iterable[Language]

def select(name: str | None = ...) -> None: ...
def select_for(languages: LanguageSet) -> None: ...
def selected_name() -> str | None: ...
def set_arguments(parser_name: str, arguments: str) -> None: ...
def parse_for(
    languages: LanguageSet,
    input: str,
    input_kind: InputKind = ...,
) -> ParseReport: ...
def parse_with(
    parser_name: str,
    input: str,
    input_kind: InputKind = ...,
) -> ParseReport: ...
def parse_with_options(
    parser_name: str,
    input: str,
    options: ParseOptions = ...,
) -> ParseReport: ...
def option(parser_name: str, option_name: str) -> str: ...
def set_option(parser_name: str, option_name: str, value: str) -> None: ...
