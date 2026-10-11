"""Real checkpoint failure/resume and SDK-import boundary verification."""
import builtins
from pathlib import Path
import shutil
import sqlite3
import tempfile

from idax import database
from examples.diaphora.host import export_current_database
from tests.integration.diaphora_export_parity_test import compare_tables


def main(upstream, fixture, *, base_zero=False):
    database.init()
    with tempfile.TemporaryDirectory(prefix="idax-export-lifecycle-") as temporary:
        work = Path(temporary)
        failing_hook = work / "failure_hook.py"
        failing_hook.write_text('''class Hooks:
    def __init__(self, value):
        self.value, self.count = value, 0
    def before_export_function(self, address, name):
        self.count += 1
        if self.count == 4:
            self.value.commit_and_start_transaction()
            raise RuntimeError("retained checkpoint witness")
        return True
HOOKS = {"DiaphoraHooks": Hooks}
''')
        for label in ("resumed", "fresh"):
            binary = work / label
            shutil.copyfile(fixture, binary)
            output = work / (label + ".sqlite")
            with database.opened(binary, save_on_exit=False):
                if base_zero:
                    import ida_segment, idaapi
                    assert ida_segment.rebase_program(-idaapi.get_imagebase(), ida_segment.MSF_FIXONCE) == 0
                original = builtins.__import__
                def opaque_import(name, *args, **kwargs):
                    if name in {"idc", "idaapi", "idautils"} or name.startswith("ida_"):
                        raise AssertionError("Production exporter imported an SDK module: " + name)
                    return original(name, *args, **kwargs)
                builtins.__import__ = opaque_import
                try:
                    if label == "resumed":
                        try:
                            export_current_database(upstream, output, include_library_thunks=True,
                                                    project_script=failing_hook)
                            raise AssertionError("Swallowed export failure")
                        except RuntimeError as failure:
                            assert isinstance(failure.__cause__, RuntimeError)
                            assert "retained checkpoint" in str(failure.__cause__)
                        assert Path(str(output) + "-crash").is_file()
                        with sqlite3.connect(output) as db:
                            assert db.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 3
                        try:
                            export_current_database(upstream, output)
                            raise AssertionError("Overwrote a partial export")
                        except FileExistsError:
                            pass
                    result = export_current_database(upstream, output, include_library_thunks=True,
                                                     resume=label == "resumed")
                    assert result["functions"] == 23 and result["compilation_units"] > 0
                    assert not Path(str(output) + "-crash").exists()
                finally:
                    builtins.__import__ = original
        compare_tables(work / "resumed.sqlite", work / "fresh.sqlite", positive_units=True)
        print("CHECKPOINT_RESUME_EQUAL: three persisted functions, explicit failure, all tables, no SDK imports")
