"""Native call-predicate equality, including an unresolved indirect call."""
from pathlib import Path
import shutil
import tempfile

from idax import address, database, function, instruction, xref


def main(fixture):
    database.init()
    calls = unresolved = checked = 0
    with tempfile.TemporaryDirectory(prefix="idax-call-predicate-") as directory:
        binary = Path(directory) / "fixture"
        shutil.copyfile(fixture, binary)
        with database.opened(binary, save_on_exit=False):
            import ida_idp
            import ida_ua

            for fn in function.all():
                for chunk in function.chunks(fn.start):
                    for ea in address.items(chunk.start, chunk.end):
                        native = ida_ua.insn_t()
                        if ida_ua.decode_insn(native, ea) == 0:
                            continue
                        expected = bool(ida_idp.is_call_insn(native))
                        assert instruction.is_call(ea) == expected, hex(ea)
                        checked += 1
                        if expected:
                            calls += 1
                            targets = [entry for entry in xref.refs_from(ea)
                                if entry.type in (xref.ReferenceType.CALL_NEAR,
                                                  xref.ReferenceType.CALL_FAR)]
                            unresolved += not targets
    assert checked > 0 and calls > 0 and unresolved > 0
    print(f"native_call_predicate_equal={checked} calls={calls} "
          f"unresolved_indirect_calls={unresolved}")
