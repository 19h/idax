"""Custom loader extension interfaces and database ingestion."""

from ._native import loader as _native

AcceptResult = _native.AcceptResult
ArchiveMemberRequest = _native.ArchiveMemberRequest
ArchiveMemberResult = _native.ArchiveMemberResult
InputFile = _native.InputFile
LoadFlags = _native.LoadFlags
LoadRequest = _native.LoadRequest
Loader = _native.Loader
LoaderOptions = _native.LoaderOptions
MoveSegmentRequest = _native.MoveSegmentRequest
OutputFile = _native.OutputFile
SaveRequest = _native.SaveRequest
abort_load = _native.abort_load
create_filename_comment = _native.create_filename_comment
decode_load_flags = _native.decode_load_flags
encode_load_flags = _native.encode_load_flags
file_to_database = _native.file_to_database
memory_to_database = _native.memory_to_database
set_processor = _native.set_processor

__all__ = [
    "AcceptResult", "ArchiveMemberRequest", "ArchiveMemberResult", "InputFile",
    "LoadFlags", "LoadRequest", "Loader", "LoaderOptions", "MoveSegmentRequest",
    "OutputFile", "SaveRequest", "abort_load", "create_filename_comment",
    "decode_load_flags", "encode_load_flags", "file_to_database",
    "memory_to_database", "set_processor",
]
