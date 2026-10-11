"""Persist imported native Diaphora metadata through an actual IDB reopen."""
import builtins
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import shutil
import sqlite3
import tempfile
from unittest.mock import patch

import idax
from idax import address, comment, database, decompiler, function, instruction, name, type as types
from examples.diaphora.host import _idc, export_current_database
from examples.diaphora.metadata import _is_offset, _set_name, import_matches


def main(upstream, fixture):
    database.init()
    with tempfile.TemporaryDirectory(prefix="idax-diaphora-metadata-") as temporary:
        work = Path(temporary)
        outputs = {}
        witness = {}
        for label in ("primary", "secondary"):
            binary = work / label
            shutil.copyfile(fixture, binary)
            output = work / (label + ".sqlite")
            with database.opened(binary, save_on_exit=False):
                target = next(value for value in function.all() if value.name.endswith("idax_diaphora_a0"))
                head = target.start
                if label == "secondary":
                    report = types.parse_declarations("#pragma pack(push, 1)\n"
                        "struct idax_import_packed { char tag; int value; };\n#pragma pack(pop)\n"
                        "enum idax_import_enum { idax_import_negative=-3, idax_import_positive=12 };\n")
                    assert report.ok, report.error_count
                    name.set(head, "idax_imported_entry")
                    function.apply_decl(head, "unsigned int idax_imported_entry(unsigned int metadata_value);")
                    function.set_comment(head, "native function metadata witness", True)
                    flags = _idc("get_func_attr", head, "flags")
                    assert _idc("set_func_attr", head, "flags", flags | 0x40)
                    comment.set(head, "native ordinary instruction witness", False)
                    comment.set(head, "native repeatable instruction witness", True)
                    instruction.set_forced_operand(head, 0, "metadata_operand")
                    with decompiler.decompile(head) as value:
                        class ReturnVisitor(decompiler.CtreeVisitor):
                            def __init__(self):
                                super().__init__()
                                self.address = None
                            def visit_statement(self, item):
                                if item.type == decompiler.ItemType.STMT_RETURN:
                                    self.address = item.address
                                return decompiler.VisitAction.CONTINUE
                        visitor = ReturnVisitor()
                        value.visit(visitor)
                        assert visitor.address is not None
                        value.set_comment(visitor.address, "native precise pseudocode witness",
                                          decompiler.CommentPosition.SEMICOLON)
                        value.save_comments()
                        assert any(entry.text == "native precise pseudocode witness" for entry in value.comments())
                    witness.update(address=head, flags=flags | 0x40,
                                   pseudo_address=visitor.address,
                                   prototype=_idc("get_type", head))
                export_current_database(upstream, output, include_library_thunks=True)
                if label == "secondary":
                    with sqlite3.connect(output) as db:
                        print("EXPORTED_PSEUDOCOMMENTS", db.execute(
                            "SELECT address,pseudocomment,pseudoitp FROM instructions WHERE pseudocomment LIKE '%precise pseudocode%'").fetchall())
                if label == "primary":
                    database.save_to(work / "primary.i64")
            outputs[label] = output
        with database.opened(work / "primary.i64", save_on_exit=False):
            assert name.get(witness["address"]) != "idax_imported_entry"
            import ida_bytes
            import ida_name
            original_name = name.get(witness["address"])
            assert ida_name.set_name(witness["address"], None, 0) is False
            assert _set_name(witness["address"], None, 0) is False
            assert name.get(witness["address"]) == original_name
            for fn in function.all():
                for ea in address.items(fn.start, fn.end):
                    flags = _idc("get_full_flags", ea)
                    for index in (*range(8), 15):
                        assert _is_offset(flags, index) == ida_bytes.is_off(flags, index)
            original = builtins.__import__
            def opaque_import(name, *args, **kwargs):
                if name in {"idc", "idaapi", "idautils"} or name.startswith("ida_"):
                    raise AssertionError("Production importer used an SDK module: " + name)
                return original(name, *args, **kwargs)
            builtins.__import__ = opaque_import
            try:
                captured = io.StringIO()
                with patch.object(instruction, "set_forced_operand",
                                  side_effect=RuntimeError("forced import failure witness")), \
                     redirect_stdout(captured), redirect_stderr(captured):
                    try:
                        import_matches(upstream, outputs["primary"], outputs["secondary"],
                                       [(witness["address"], witness["address"])])
                    except RuntimeError as failure:
                        assert isinstance(failure.__cause__, RuntimeError)
                        assert str(failure.__cause__) == "forced import failure witness"
                    else:
                        raise AssertionError("Swallowed instruction import failure returned success")
                count = import_matches(upstream, outputs["primary"], outputs["secondary"],
                                       [(witness["address"], witness["address"])])
            finally:
                builtins.__import__ = original
            assert count == 1
            database.save_to(work / "imported.i64")
        with database.opened(work / "imported.i64", save_on_exit=False):
            ea = witness["address"]
            assert name.get(ea) == "idax_imported_entry"
            assert _idc("get_type", ea) == witness["prototype"]
            assert _idc("get_func_attr", ea, "flags") == witness["flags"]
            assert function.comment(ea, True) == "native function metadata witness"
            assert comment.get(ea, False) == "native ordinary instruction witness"
            assert comment.get(ea, True) == "native repeatable instruction witness"
            assert instruction.get_forced_operand(ea, 0) == "metadata_operand"
            assert types.TypeInfo.by_name("idax_import_packed").size == 5
            assert types.TypeInfo.by_name("idax_import_enum").is_enum
            with decompiler.decompile(ea) as value:
                print("REOPENED_PSEUDOCOMMENTS", [(entry.address, entry.text, entry.position.kind)
                                                 for entry in value.comments()])
                assert any(entry.text == "native precise pseudocode witness"
                           and entry.address == witness["pseudo_address"]
                           and entry.position.kind == decompiler.CommentPositionKind.SEMICOLON
                           for entry in value.comments())
        print("METADATA_REOPEN_PASS: names, prototypes, flags, function/instruction comments, forced operand, packed/enum definitions, precise pseudocode")
