"""Actual changed-code native export interchange and full-engine comparisons."""
from hashlib import sha256
from itertools import product
from pathlib import Path
import shutil
import sqlite3
import tempfile

from idax import database
from examples.diaphora.backend import diff_databases, load_backend, read_results
from examples.diaphora.host import export_current_database
from tests.integration.diaphora_export_parity_test import compare_tables, native_engine


def main(upstream, primary, secondary, *, model=False):
    engine = load_backend(upstream)
    database.init()
    with tempfile.TemporaryDirectory(prefix="idax-changed-binary-") as temporary:
        work = Path(temporary)
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
            compare_tables(inputs["native", index], inputs["idax", index], positive_units=True)
        with sqlite3.connect(inputs["idax", 0]) as first, sqlite3.connect(inputs["idax", 1]) as second:
            assert first.execute("SELECT bytes_hash FROM functions ORDER BY address").fetchall() != second.execute(
                "SELECT bytes_hash FROM functions ORDER BY address").fetchall(), "Inputs must contain actual changed code"
        hashes = {path: sha256(path.read_bytes()).hexdigest() for path in inputs.values()}
        for number, (all_heuristics, relaxed, use_model) in enumerate(product(
                (False, True), (False, True), (False, True) if model else (False,))):
            actual = diff_databases(upstream, inputs["idax", 0], inputs["idax", 1],
                work / f"actual-{number}.results", all_heuristics=all_heuristics,
                relaxed_ratio=relaxed, use_model=use_model)
            reference_file = work / f"reference-{number}.sqlite"
            with sqlite3.connect(inputs["native", 0]) as one, sqlite3.connect(reference_file) as two:
                one.backup(two)
            reference = engine.CBinDiff(str(reference_file))
            reference.cpu_count = 1
            reference.imp_load_source = lambda name, path: engine.load_source(name, path)
            reference.relaxed_ratio = relaxed
            reference.use_trained_model = use_model
            if all_heuristics:
                reference.unreliable = reference.experimental = reference.slow_heuristics = True
            try:
                assert reference.diff(str(inputs["native", 1]))
                if use_model:
                    reference.apply_machine_learning()
                    assert reference.classifier is not None
                    row = next(iter(actual["partial"] or actual["best"]))
                    # An actual persisted function pair exercises model prediction
                    # even if earlier exact matching resolves every candidate.
                    prediction = reference.get_model_ratio(
                        dict(ea=str(int(row["address"], 16)), name=row["name"]),
                        dict(ea=str(int(row["address2"], 16)), name=row["name2"]))
                    assert prediction in (0, 1)
                    print("MODEL_PREDICTION", int(prediction))
                reference.save_results(str(work / f"reference-{number}.results"))
            finally:
                reference.db_close()
            assert actual == read_results(work / f"reference-{number}.results")
            assert actual["best"]
            if number == 0:
                assert actual["partial"], "Default matching needs a changed-function ratio witness"
            print("CHANGED_BINARY_EQUAL", all_heuristics, relaxed, use_model,
                  {key: len(rows) for key, rows in actual.items()})
        assert hashes == {path: sha256(path.read_bytes()).hexdigest() for path in inputs.values()}
