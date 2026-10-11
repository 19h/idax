"""Positive native matching categories from independently compiled inputs."""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import shutil
import sqlite3
import tempfile

from idax import database
from examples.diaphora.backend import diff_databases, load_backend, read_results
from examples.diaphora.host import export_current_database
from tests.integration.diaphora_export_parity_test import compare_tables, native_engine


@contextmanager
def _workspace(path):
    if path is None:
        with tempfile.TemporaryDirectory(prefix="idax-diaphora-categories-") as temporary:
            yield Path(temporary)
    else:
        work = Path(path).resolve()
        work.mkdir(parents=True)
        yield work


def main(upstream, primary, secondary, *, work_directory=None):
    engine = load_backend(upstream)
    database.init()
    with _workspace(work_directory) as work:
        inputs = {}
        for index, source in enumerate((primary, secondary)):
            for label in ("native", "idax"):
                binary = work / f"{label}-{index}"
                shutil.copyfile(source, binary)
                output = work / f"{label}-{index}.sqlite"
                with database.opened(binary, save_on_exit=False):
                    if label == "native":
                        value = native_engine(Path(upstream).resolve(), output)
                        value.exclude_library_thunk = False
                        value.ida_subs = value.use_decompiler = value.export_microcode = True
                        try:
                            value.export()
                        finally:
                            value.db_close()
                    else:
                        export_current_database(upstream, output, include_library_thunks=True)
                inputs[label, index] = output
            counts = compare_tables(inputs["native", index], inputs["idax", index], positive_units=True)
            print("ALL_CATEGORY_EXPORT_TABLES_EQUAL", index, counts)
        function_sets = []
        for index in (0, 1):
            with sqlite3.connect(inputs["native", index]) as original:
                function_sets.append({(int(address), name) for address, name in original.execute(
                    "SELECT address,name FROM functions")})
        hashes = {path: sha256(path.read_bytes()).hexdigest() for path in inputs.values()}
        for all_heuristics in (False, True):
            actual = diff_databases(upstream, inputs["idax", 0], inputs["idax", 1],
                work / f"actual-{all_heuristics}.results", all_heuristics=all_heuristics)
            reference_file = work / f"reference-{all_heuristics}.sqlite"
            with sqlite3.connect(inputs["native", 0]) as one, sqlite3.connect(reference_file) as two:
                one.backup(two)
            reference = engine.CBinDiff(str(reference_file))
            reference.cpu_count = 1
            reference.imp_load_source = lambda name, path: engine.load_source(name, path)
            reference.relaxed_ratio = reference.use_trained_model = False
            if all_heuristics:
                reference.unreliable = reference.experimental = reference.slow_heuristics = True
            try:
                assert reference.diff(str(inputs["native", 1]))
                reference.save_results(str(work / f"reference-{all_heuristics}.results"))
            finally:
                reference.db_close()
            assert actual == read_results(work / f"reference-{all_heuristics}.results")
            with sqlite3.connect(work / f"actual-{all_heuristics}.results") as one, \
                 sqlite3.connect(work / f"reference-{all_heuristics}.results") as two:
                for table, ordering in (("results", "type,address,address2"),
                                        ("unmatched", "type,address")):
                    query = f"SELECT * FROM {table} ORDER BY {ordering}"
                    assert one.execute(query).fetchall() == two.execute(query).fetchall()
            for index, category in enumerate(("primary", "secondary")):
                for row in actual[category]:
                    assert row["type"] == category
                    assert (int(row["address"], 16), row["name"]) in function_sets[index]
            for category in ("best", "partial", "unreliable", "multimatch"):
                for row in actual[category]:
                    for index, address, name in ((0, "address", "name"), (1, "address2", "name2")):
                        assert (int(row[address], 16), row[name]) in function_sets[index]
            print("NATIVE_CATEGORY_EQUAL", all_heuristics,
                  {key: len(rows) for key, rows in actual.items()})
            for category in ("partial", "unreliable", "multimatch", "primary", "secondary"):
                print("CATEGORY_WITNESS", category, actual[category])
            for category in ("best", "partial", "primary", "secondary"):
                assert actual[category], "Missing positive category: " + category
            if all_heuristics:
                assert actual["unreliable"], "Missing positive unreliable category"
                assert len(actual["multimatch"]) >= 2
                assert len({row["address"] for row in actual["multimatch"]}) == 1
                assert len({row["address2"] for row in actual["multimatch"]}) == 2
                for row in actual["unreliable"] + actual["multimatch"]:
                    assert 0.0 < float(row["ratio"]) < 1.0
        assert hashes == {path: sha256(path.read_bytes()).hexdigest() for path in inputs.values()}
        print("CATEGORY_PARITY_PASS")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("primary", type=Path)
    parser.add_argument("secondary", type=Path)
    parser.add_argument("--work-directory", type=Path)
    arguments = parser.parse_args()
    main(arguments.upstream, arguments.primary, arguments.secondary,
         work_directory=arguments.work_directory)
