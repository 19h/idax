"""Native Diaphora metadata import through opaque IDAX host operations."""
from __future__ import annotations

import difflib
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace

import idax
from idax import analysis, comment, decompiler, function, instruction, name, type as types

from .backend import load_backend, read_results, upstream_definitions
from .host import _function, _idc, _optional, host_engine


_IMPORT_METHODS = {"import_til", "import_definitions", "import_instruction",
    "row_is_importable", "do_import_instruction_level_item", "import_instruction_level",
    "do_import_one"}


def _position(value):
    value = int(value)
    if value & 0x40000000:
        magnitude = value & 0x1FFFFFFF
        return decompiler.CommentPosition.switch_case(-magnitude if value & 0x20000000 else magnitude)
    if 1 <= value <= 64:
        return decompiler.CommentPosition.argument(value - 1)
    names = {0: "DEFAULT", 65: "PARENTHESIS_OPEN", 66: "ASSEMBLY", 67: "ELSE_LINE",
        68: "DO_LINE", 69: "SEMICOLON", 70: "OPEN_BRACE", 71: "CLOSE_BRACE",
        72: "PARENTHESIS_CLOSE", 73: "LABEL_COLON", 74: "BLOCK_BEFORE",
        75: "BLOCK_AFTER", 76: "TRY_LINE"}
    if value not in names:
        raise ValueError("Unknown native pseudocode comment position")
    return getattr(decompiler.CommentPosition, names[value])


class _PseudocodeComments:
    """Owned pending comment operation; native host objects never cross this API."""
    def __init__(self, address):
        self.address, self.pending, self.remove_orphans = address, None, False

    def set_user_cmt(self, location, text):
        self.pending = (location.ea, text, _position(location.itp))

    def del_orphan_cmts(self):
        self.remove_orphans = True

    def save_user_cmts(self):
        with decompiler.decompile(self.address) as value:
            if self.pending is not None:
                value.set_comment(*self.pending)
            if self.remove_orphans:
                value.refresh()
                value.lines()
                value.remove_orphan_comments()
            value.save_comments()


def _structure_id(value):
    result = _optional(types.TypeInfo.by_name, value)
    return 0 if result is not None and (result.is_struct or result.is_union) else idax.BAD_ADDRESS


def _parse(value):
    return types.parse_declarations(value).error_count


def _is_offset(flags, index):
    # SDK 940 bytes.hpp: get_operand_type_shift, MS_N_TYPE and FF_N_OFF.
    indices = range(8) if index == 15 else (index,)
    return any(((flags >> (20 + 4 * (item + (item > 1)))) & 0xF) == 5
               for item in indices if 0 <= item < 8)


def _set_name(ea, text, flags):
    # Native IDAPython accepts a null name and returns false without mutation.
    return False if text is None else bool(_idc("set_name", ea, text, flags))


def import_engine(root, primary, secondary):
    value, namespace = host_engine(root, primary)
    engine = load_backend(root)
    namespace.update(diaphora=engine, difflib=difflib, SN_NOWARN=0x100,
        SN_NOCHECK=1, SN_CHECK=0, OPND_ALL=15,
        set_name=_set_name,
        SetType=lambda ea, declaration: types.TypeInfo.from_declaration(declaration).apply(ea),
        set_func_cmt=lambda fn, text, repeatable: function.set_comment(fn.start_ea, text, bool(repeatable)),
        set_func_attr=lambda ea, attribute, number: _idc("set_func_attr", ea, attribute, number),
        get_cmt=lambda ea, repeatable: _optional(comment.get, ea, bool(repeatable)),
        set_cmt=lambda ea, text, repeatable: comment.set(ea, text, bool(repeatable)),
        get_ea_name=lambda ea: _optional(name.get, ea) or "",
        get_full_flags=lambda ea: _idc("get_full_flags", ea), is_off=_is_offset,
        add_default_til=types.load_type_library, get_struc_id=_structure_id,
        auto_wait=analysis.wait,
        decompile=lambda ea: _PseudocodeComments(ea) if _function(ea) and decompiler.available() else None,
        idaapi=SimpleNamespace(treeloc_t=lambda: SimpleNamespace(ea=idax.BAD_ADDRESS, itp=0)))
    namespace["idc"].parse_decls = _parse
    namespace["ida_bytes"].set_forced_operand = instruction.set_forced_operand
    methods = upstream_definitions(root, "diaphora_ida.py", _IMPORT_METHODS,
                                   namespace, class_name="CIDABinDiff")
    for key, method in methods.items():
        setattr(type(value), key, method)
    import_item = methods["do_import_instruction_level_item"]
    def monitored_item(self, *arguments):
        try:
            return import_item(self, *arguments)
        except Exception as failure:
            self._import_failure = failure
            raise
    type(value).do_import_instruction_level_item = monitored_item
    value._import_failure = None
    value.attach_database(str(secondary))
    return value


def import_matches(root, primary, secondary, pairs, *, definitions=True, force=False):
    """Import explicit native address pairs into the current open IDB.

    SQLite inputs remain read-only. Save the IDB through database.save_to after
    applying metadata to retain it across sessions. The unchanged upstream
    instruction alignment preserves existing comments and imports names/types,
    repeatable comments, forced operands and precise pseudocode comments.
    """
    with tempfile.TemporaryDirectory(prefix="idax-diaphora-import-") as temporary:
        work = Path(temporary)
        for source, target in ((primary, work / "primary.sqlite"),
                               (secondary, work / "secondary.sqlite")):
            path = Path(source).resolve(strict=True)
            with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as one, sqlite3.connect(target) as two:
                one.backup(two)
        value = import_engine(root, work / "primary.sqlite", work / "secondary.sqlite")
        try:
            if definitions:
                value.import_til()
                value.import_definitions()
            total = 0
            for first, second in pairs:
                value.do_import_one(str(int(first)), str(int(second)), force=force)
                if value._import_failure is not None:
                    raise RuntimeError("Diaphora instruction import failed; current IDB may contain partial metadata") from value._import_failure
                total += 1
            analysis.wait()
            return total
        finally:
            value.db_close()


def import_results(root, results, *, categories=("best",), definitions=True, force=False):
    results = Path(results).resolve(strict=True)
    with sqlite3.connect(f"{results.as_uri()}?mode=ro", uri=True) as db:
        primary, secondary = db.execute("SELECT main_db,diff_db FROM config").fetchone()
    rows = read_results(results)
    pairs = [(int(row["address"], 16), int(row["address2"], 16))
             for category in categories for row in rows[category]]
    return import_matches(root, primary, secondary, pairs, definitions=definitions, force=force)
