from typing import Final, TypeAlias
from . import address as address, analysis as analysis, core as core
from . import bookmark as bookmark
from . import navigation as navigation
from . import data as data, event as event
from . import exception as exception
from . import debugger as debugger, graph as graph
from . import decompiler as decompiler
from . import database as database, diagnostics as diagnostics
from . import directory as directory
from . import registry as registry
from . import registers as registers
from . import error as error, path as path
from . import parser as parser
from . import comment as comment, entry as entry, lines as lines
from . import lumina as lumina, name as name, search as search
from . import segment as segment, xref as xref
from . import type as type
from . import fixup as fixup, function as function, instruction as instruction
from . import storage as storage
from . import undo as undo
from . import loader as loader, plugin as plugin, processor as processor, ui as ui
from . import problem as problem
from .error import (
    ConflictError as ConflictError,
    ErrorCategory as ErrorCategory,
    ErrorInfo as ErrorInfo,
    IdaxError as IdaxError,
    InternalError as InternalError,
    NotFoundError as NotFoundError,
    SdkError as SdkError,
    UnsupportedError as UnsupportedError,
    ValidationError as ValidationError,
)

Address: TypeAlias = int
AddressDelta: TypeAlias = int
AddressSize: TypeAlias = int
BAD_ADDRESS: Final[int]
__version__: str
