"""IDA runtime lifecycle, database metadata, and snapshot management."""

from __future__ import annotations

from os import PathLike
from types import TracebackType
from ._native.database import (
    CompilerInfo,
    ImportModule,
    ImportSymbol,
    LoadIntent,
    OpenMode,
    PluginLoadPolicy,
    ProcessorId,
    ProcessorProfile,
    RuntimeOptions,
    Snapshot,
    abi_name,
    address_bitness,
    address_bounds,
    address_span,
    close,
    compiler_info,
    file_to_database,
    file_type_name,
    idb_path,
    image_base,
    import_modules,
    init,
    input_file_path,
    input_md5,
    is_big_endian,
    is_snapshot_database,
    loader_format_name,
    max_address,
    memory_to_database,
    min_address,
    open,
    open_binary,
    open_non_binary,
    processor,
    processor_id,
    processor_id_from_raw,
    processor_name,
    processor_profile,
    save,
    set_address_bitness,
    set_snapshot_description,
    snapshots,
)


class DatabaseSession:
    """Own one database-open/close interval.

    The session does not initialize or terminate the IDA library. Call
    :func:`init` once on the process main thread before constructing sessions
    in an external idalib process. Inside IDAPython, the host already owns the
    runtime lifecycle.
    """

    __slots__ = (
        "_intent",
        "_mode",
        "_opened",
        "_path",
        "_save_on_error",
        "_save_on_exit",
    )

    def __init__(
        self,
        path: str | bytes | PathLike[str] | PathLike[bytes],
        *,
        mode: OpenMode | bool = OpenMode.ANALYZE,
        intent: LoadIntent = LoadIntent.AUTO_DETECT,
        save_on_exit: bool = False,
        save_on_error: bool = False,
    ) -> None:
        self._path = path
        self._mode = mode
        self._intent = intent
        self._save_on_exit = save_on_exit
        self._save_on_error = save_on_error
        self._opened = False

    @property
    def is_open(self) -> bool:
        """Whether this object currently owns an open database."""

        return self._opened

    def __enter__(self) -> DatabaseSession:
        if self._opened:
            raise RuntimeError("database session is already open")
        open(self._path, self._mode, self._intent)
        self._opened = True
        return self

    def close(self, *, save: bool | None = None) -> None:
        """Close the owned database once; repeated calls are no-ops."""

        if not self._opened:
            return
        should_save = self._save_on_exit if save is None else save
        close(should_save)
        self._opened = False

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        del exception, traceback
        if self._opened:
            close(self._save_on_exit if exception_type is None else self._save_on_error)
            self._opened = False
        return False

    def __repr__(self) -> str:
        return (
            f"DatabaseSession(path={self._path!r}, mode={self._mode!r}, "
            f"intent={self._intent!r}, is_open={self._opened!r})"
        )


def opened(
    path: str | bytes | PathLike[str] | PathLike[bytes],
    *,
    mode: OpenMode | bool = OpenMode.ANALYZE,
    intent: LoadIntent = LoadIntent.AUTO_DETECT,
    save_on_exit: bool = False,
    save_on_error: bool = False,
) -> DatabaseSession:
    """Create a context-managed database session."""

    return DatabaseSession(
        path,
        mode=mode,
        intent=intent,
        save_on_exit=save_on_exit,
        save_on_error=save_on_error,
    )


__all__ = [
    "CompilerInfo",
    "DatabaseSession",
    "ImportModule",
    "ImportSymbol",
    "LoadIntent",
    "OpenMode",
    "PluginLoadPolicy",
    "ProcessorId",
    "ProcessorProfile",
    "RuntimeOptions",
    "Snapshot",
    "abi_name",
    "address_bitness",
    "address_bounds",
    "address_span",
    "close",
    "compiler_info",
    "file_to_database",
    "file_type_name",
    "idb_path",
    "image_base",
    "import_modules",
    "init",
    "input_file_path",
    "input_md5",
    "is_big_endian",
    "is_snapshot_database",
    "loader_format_name",
    "max_address",
    "memory_to_database",
    "min_address",
    "open",
    "open_binary",
    "open_non_binary",
    "opened",
    "processor",
    "processor_id",
    "processor_id_from_raw",
    "processor_name",
    "processor_profile",
    "save",
    "set_address_bitness",
    "set_snapshot_description",
    "snapshots",
]
