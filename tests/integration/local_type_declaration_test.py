"""Compare opaque local declarations with native IDAPython on an owned fixture."""

from pathlib import Path
import shutil
import tempfile

import idax
from idax import database, type as types


def main(fixture):
    database.init()
    copied = []
    with tempfile.TemporaryDirectory(prefix="idax-local-declarations-") as directory:
        binary = Path(directory) / "fixture"
        shutil.copyfile(fixture, binary)
        with database.opened(binary, save_on_exit=False):
            # Reference imports are confined to the independent verification.
            import idc
            import idaapi

            module_name = database.processor_module_name()
            assert module_name == idaapi.get_idp_name()

            report = types.parse_declarations(
                "#pragma pack(push, 1)\n"
                "struct idax_diaphora_packed { char tag; int value; };\n"
                "#pragma pack(pop)\n"
                "typedef struct idax_diaphora_packed idax_diaphora_alias;\n"
                "union idax_diaphora_union { int integer; char text[8]; };\n"
                "enum idax_diaphora_enum { idax_negative = -3, idax_positive = 12 };\n")
            assert report.ok, report.error_count
            packed = None
            packed_ordinal = None
            for ordinal in range(1, types.local_type_count() + 1):
                if idc.get_local_tinfo(ordinal) is None:
                    continue
                expected = idc.GetLocalType(ordinal, 15)
                actual = types.local_type_declaration(ordinal)
                assert actual == expected, (ordinal, actual, expected)
                copied.append(actual)
                if types.local_type_name(ordinal) == "idax_diaphora_packed":
                    packed = actual
                    packed_ordinal = ordinal
            assert packed is not None and "#pragma pack" in packed, packed
            assert idc.sizeof(idc.get_local_tinfo(packed_ordinal)) == 5
            for ordinal in (0, 0x100000000, types.local_type_count() + 512):
                try:
                    types.local_type_declaration(ordinal)
                except idax.NotFoundError:
                    pass
                else:
                    raise AssertionError(f"Missing ordinal accepted: {ordinal}")
    assert all(isinstance(value, str) for value in copied)
    assert packed in copied
    assert module_name
    print(f"native_declarations_equal={len(copied)} packed_size_bytes=5 "
          "absent_ordinals_rejected=True copies_survive_close=True")
