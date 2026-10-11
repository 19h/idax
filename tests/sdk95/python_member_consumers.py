"""Actual SDK 950 consumer evidence; requires the native producer's saved IDB."""
import shutil
import sys
import tempfile
from pathlib import Path
from idax import IdaxError, analysis, database, decompiler as dc, name, type as types
from idax.error import ErrorCategory

CASES = (
    ("read_wide", "IDAXHuge950", "wide", 2147483664, False, False),
    ("read_bits", "IDAXSmallBits950", "target", 3, True, False),
    ("read_big_bits", "IDAXBigBits950", "target", 4294967299, True, False),
    ("read_union", "IDAXChoice950", "real", 1, False, True),
)

def invalid(call):
    try:
        call()
    except IdaxError as exc:
        assert exc.category == ErrorCategory.VALIDATION
    else:
        raise AssertionError("Expected Validation")

class Visitor(dc.CtreeVisitor):
    def __init__(self, case):
        super().__init__()
        self.case, self.matches, self.failure = case, 0, None

    def visit_expression(self, expr):
        try:
            return self.check_expression(expr)
        except BaseException as exc:
            self.failure = exc
            return dc.VisitAction.STOP

    def check_expression(self, expr):
        if expr.type not in (dc.ItemType.EXPR_MEMBER_REF, dc.ItemType.EXPR_MEMBER_PTR):
            return dc.VisitAction.CONTINUE
        function, _, field, value, bitfield, union = self.case
        assert expr.member_name() == field
        assert expr.member_is_bitfield() == bitfield
        if union:
            assert expr.member_index() == value
            invalid(expr.member_offset)
            invalid(expr.member_bit_offset)
        else:
            assert expr.member_offset() == (value // 8 if bitfield else value)
            assert expr.member_bit_offset() == (value if bitfield else value * 8)
            invalid(expr.member_index)
        if function == "read_wide":
            assert expr.left().pointed_type_byte_width() == 2147483668
        self.matches += 1
        return dc.VisitAction.CONTINUE

def main():
    with tempfile.TemporaryDirectory(prefix="idax-sdk95-python-") as directory:
        fixture = Path(directory) / "fixture.i64"
        shutil.copyfile(sys.argv[1], fixture)
        options = database.RuntimeOptions(quiet=True, plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True))
        database.init(["idax-sdk95-python"], options)
        database.open(fixture, database.OpenMode.SKIP_ANALYSIS)
        try:
            analysis.wait()
            for case in CASES:
                function, type_name, field, value, bitfield, union = case
                try:
                    address = name.resolve(function)
                except IdaxError:
                    address = name.resolve("_" + function)
                visitor = Visitor(case)
                dc.decompile(address).visit_expressions(visitor)
                if visitor.failure is not None:
                    raise visitor.failure
                assert visitor.matches > 0
                collection = dc.collect_referenced_types(address)
                offsets = next(entry for entry in collection.used_offsets if entry.type_name == type_name)
                assert offsets.byte_offsets == ([] if bitfield or union else [value])
                assert offsets.bit_offsets == ([value] if bitfield else [])
                assert offsets.member_indices == ([value] if union else [])
                options = types.TypeRenderOptions()
                options.trim_unreferenced = True
                options.used_offsets = collection.used_offsets
                rendered = types.render_named_declarations([type_name], -1, options)
                assert field in rendered
                if not union:
                    assert "before" not in rendered and "padding[" not in rendered
                parsed = types.TypeInfo.from_declaration(rendered.replace(type_name, type_name + "PythonTrimmed"))
                original = types.TypeInfo.by_name(type_name)
                assert parsed.size == original.size
                if not union:
                    assert parsed.member_by_name(field).bit_offset == (value if bitfield else value * 8)
                print(f"PASS: Python {function} exact getter/name/unit/collection/render")
        finally:
            database.close(False)

if __name__ == "__main__":
    main()
