"""Independent upstream interchange checks; requires the pinned source checkout."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import shutil
import sys
import tempfile
import types
import unittest

from examples.diaphora.backend import diff_databases, load_backend, read_results


class BackendInterchange(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.upstream = Path(sys.argv[1]).resolve()
        cls.engine = load_backend(cls.upstream)

    def export(self, output: Path, *, edited: bool) -> None:
        """Use upstream's real schema/serializer, including block relations."""
        engine = self.engine.CBinDiff(str(output))
        try:
            for index in range(6):
                assembly = f"mov eax, {index + 100}\nadd eax, 3\nret"
                pseudo = f"return input + {index + 100};"
                if edited and index == 1:
                    assembly = assembly.replace("add eax, 3", "add eax, 4")
                    pseudo = pseudo.replace("return", "return 1 +")
                address = 0x1000 + 0x100 * index + (0x4000 if edited else 0)
                row = dict.fromkeys(engine.FUNCTION_FIELDS)
                row.update(name=f"named_{index}", true_name=f"named_{index}", f=address,
                           nodes=1, edges=0, indegree=0, outdegree=0, size=8,
                           instructions=3, mnems=["mov", "add", "ret"], names=[],
                           proto="int(int input)", proto2="int(int input)", cc=1,
                           prime="3", comment="", bytes_hash=hashlib.md5(assembly.encode()).hexdigest(),
                           pseudo=pseudo, pseudo_lines=1, pseudo_hash1=None,
                           pseudocode_primes=str(index + 29), function_flags=0,
                           asm=assembly, pseudo_hash2=None, pseudo_hash3=None,
                           strongly_connected_size=1, loops=0, rva=index * 0x100,
                           bb_topological="[[0]]", strongly_connected_spp="1",
                           clean_assembly=assembly, clean_pseudo=pseudo,
                           mnemonics_spp="30", switches=[],
                           function_hash=hashlib.md5(assembly.encode()).hexdigest(),
                           bytes_sum=index + 100, md_index=str(index + 1),
                           constants=[4097 + index], constants_size=1, seg_rva=index * 0x100,
                           assembly_addrs=[index * 0x100 + offset for offset in (0, 3, 7)],
                           kgh_hash=str(7 + index), microcode=assembly,
                           clean_microcode=assembly, microcode_spp="30", export_time=0.0,
                           microcode_bblocks={}, microcode_bbrelations={}, callers=[], callees=[],
                           basic_blocks_data={index * 0x100: [[index * 0x100, "mov", assembly,
                                                             None, None, [], None, None]]},
                           bb_relations={index * 0x100: []})
                engine.save_function(engine.get_function_from_dictionary(row))
            engine.db.execute("INSERT INTO program(callgraph_primes,callgraph_all_primes,processor,md5sum) VALUES(?,?,?,?)",
                              ("729", '{"3": 6}', "metapc64", "controlled-corpus"))
            engine.create_indices()
            engine.db.commit()
        finally:
            engine.db_close()

    def test_native_results_equal_independent_upstream_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary = root / 'primary "quoted".sqlite'
            secondary = root / 'secondary "quoted".sqlite'
            self.export(primary, edited=False)
            self.export(secondary, edited=True)
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (primary, secondary)}
            actual = diff_databases(self.upstream, primary, secondary, root / "actual.results",
                                    all_heuristics=True)
            # The reference independently initializes upstream and runs its
            # complete matching state machine on the original database files.
            reference_primary = root / "reference-primary.sqlite"
            reference_secondary = root / "reference-secondary.sqlite"
            for original, copied in ((primary, reference_primary), (secondary, reference_secondary)):
                with sqlite3.connect(original) as source, sqlite3.connect(copied) as destination:
                    source.backup(destination)
            reference = self.engine.CBinDiff(str(reference_primary))
            # Independently repair the audited import boundary with the
            # upstream loader; all matching/feature methods stay untouched.
            backend = self.engine
            reference.imp_load_source = types.MethodType(
                lambda owner, name, pathname: backend.load_source(name, pathname), reference)
            try:
                reference.cpu_count = 1
                reference.unreliable = reference.experimental = reference.slow_heuristics = True
                reference.relaxed_ratio = reference.use_trained_model = False
                self.assertTrue(reference.diff(str(reference_secondary)))
                reference.save_results(str(root / "reference.results"))
            finally:
                reference.db_close()
            self.assertEqual(actual, read_results(root / "reference.results"))
            self.assertTrue(actual["best"])
            self.assertTrue(actual["partial"])
            self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in before})
            with sqlite3.connect(root / "actual.results") as db:
                self.assertEqual(db.execute("SELECT main_db,diff_db,version FROM config").fetchone(),
                                 (str(primary.resolve()), str(secondary.resolve()), "3.4"))
            with self.assertRaises(FileExistsError):
                diff_databases(self.upstream, primary, secondary, root / "actual.results")
            if not self.engine.ML_AVAILABLE:
                with self.assertRaisesRegex(RuntimeError, "model dependencies"):
                    diff_databases(self.upstream, primary, secondary, root / "model.results",
                                    use_model=True)

    def test_changed_source_is_rejected_before_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "upstream"
            shutil.copytree(self.upstream, copied, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            source = copied / "diaphora.py"
            source.write_bytes(source.read_bytes() + b"\n# changed source\n")
            with self.assertRaisesRegex(ValueError, "diaphora.py"):
                load_backend(copied)


if __name__ == "__main__":
    # Preserve the source argument for setUpClass while excluding it from unittest.
    unittest.main(argv=[sys.argv[0]])
