"""Load the audited Diaphora engine without replacing its matching algorithms."""

from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import ModuleType
from typing import Any

UPSTREAM_COMMIT = "84aa7dd83fd45d13ae4e5cbe10b12effb97b9b99"
_MANIFEST = Path(__file__).with_name("upstream.json")


def verify_upstream(root: str | Path) -> Path:
    """Require the exact audited source/model bytes before importing any code."""
    root = Path(root).resolve(strict=True)
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    if manifest["commit"] != UPSTREAM_COMMIT:
        raise ValueError("Diaphora provenance manifest has an unexpected revision")
    for relative, expected in manifest["files"].items():
        path = root / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Diaphora source/model verification failed: {relative}")
    return root


def load_backend(root: str | Path) -> ModuleType:
    root = verify_upstream(root)
    loaded = sys.modules.get("diaphora")
    if loaded is not None:
        if Path(loaded.__file__).resolve() != root / "diaphora.py":
            raise RuntimeError("A different Diaphora checkout is already imported")
        return loaded
    for name in ("diaphora_config", "diaphora_heuristics", "ml", "db_support", "jkutils"):
        helper = sys.modules.get(name)
        if helper is not None and not Path(helper.__file__).resolve().is_relative_to(root):
            raise RuntimeError(f"A conflicting upstream helper is already imported: {name}")
    # Upstream deliberately uses top-level imports and reloads its helpers.
    # Preserve that package structure; do not install fake idaapi/idc modules.
    sys.path.insert(0, str(root))
    try:
        path = root / "diaphora.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename="diaphora.py")
        probes = [index for index, node in enumerate(tree.body)
                  if isinstance(node, ast.Try) and any(
                      isinstance(statement, ast.Import) and any(
                          alias.name == "idaapi" for alias in statement.names)
                      for statement in node.body)]
        if len(probes) != 1:
            raise RuntimeError("Unexpected upstream optional SDK probe")
        # The backend only probes SDK availability; no matching body uses it.
        # Bind the documented standalone mode without importing an SDK module.
        tree.body[probes[0]] = ast.Assign(targets=[ast.Name(id="IS_IDA", ctx=ast.Store())],
                                         value=ast.Constant(False))
        module = ModuleType("diaphora")
        module.__file__ = str(path)
        module.__package__ = ""
        sys.modules["diaphora"] = module
        exec(compile(ast.fix_missing_locations(tree), "diaphora.py", "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop("diaphora", None)
        sys.path.remove(str(root))
        raise
    if module.VERSION_VALUE != "3.4" or len(module.HEURISTICS) != 50:
        raise RuntimeError("Unexpected audited Diaphora engine surface")
    return module


def engine_class(engine: ModuleType) -> type:
    """Retain the engine, correcting its broken project-script loader boundary.

    The audited method imp_load_source(name, pathname) refers to undefined
    modname/filename. Upstream's existing load_source helper accepts exactly
    these arguments and preserves project/automatic patch-diff hooks.
    """
    class BinDiff(engine.CBinDiff):
        def imp_load_source(self, name: str, pathname: str) -> ModuleType:
            return engine.load_source(name, pathname)

    return BinDiff


def upstream_definitions(
    root: str | Path, relative: str, names: set[str], namespace: dict[str, Any],
    *, class_name: str | None = None,
) -> dict[str, Any]:
    """Compile selected, unchanged upstream bodies with an IDAX host namespace.

    Imports and top-level host/UI initialization are excluded. Every selected
    body comes from a byte-verified file, and a missing definition is an error.
    This permits reuse of feature algorithms without loading IDAPython's SDK.
    """
    root = verify_upstream(root)
    path = root / relative
    if relative not in json.loads(_MANIFEST.read_text(encoding="utf-8"))["files"]:
        raise ValueError(f"Definition source is outside the audit: {relative}")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    scope = tree.body
    if class_name is not None:
        scope = next(node.body for node in scope
                     if isinstance(node, ast.ClassDef) and node.name == class_name)
    selected = [node for node in scope
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    found = {node.name for node in selected}
    if found != names:
        raise ValueError(f"Missing audited definitions in {relative}: {sorted(names - found)}")
    module = ast.Module(body=selected, type_ignores=[])
    definitions = namespace if class_name is None else {}
    # Class methods bind in the class scope. Keep a method named guess_type
    # from replacing its native/global guess_type dependency.
    exec(compile(ast.fix_missing_locations(module), relative, "exec"), namespace, definitions)
    return {name: definitions[name] for name in names}


def read_results(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Read all categories, normalizing the audited native unmatched side reversal.

    Pinned 3.4.0 saves unmatched main functions under secondary and vice versa.
    The SQLite file is unchanged; returned categories/types name the input side.
    """
    result: dict[str, list[dict[str, Any]]] = {
        "best": [], "partial": [], "unreliable": [], "multimatch": [],
        "primary": [], "secondary": [],
    }
    with sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        for row in db.execute("SELECT * FROM results ORDER BY type, address, address2"):
            result[row["type"]].append(dict(row))
        for row in db.execute("SELECT * FROM unmatched ORDER BY type, address"):
            category = {"primary": "secondary", "secondary": "primary"}[row["type"]]
            result[category].append(dict(row, type=category))
    return result


def diff_databases(
    root: str | Path, primary: str | Path, secondary: str | Path,
    output: str | Path, *, all_heuristics: bool = False,
    relaxed_ratio: bool = False, use_model: bool = False,
) -> dict[str, list[dict[str, Any]]]:
    """Run the complete upstream state machine on a private primary DB copy.

    Inputs are opened read-only and never modified. The result is Diaphora's
    native SQLite results format; no IDA runtime is needed for this operation.
    """
    engine = load_backend(root)
    primary = Path(primary).resolve(strict=True)
    secondary = Path(secondary).resolve(strict=True)
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(output)
    if use_model and not engine.ML_AVAILABLE:
        raise RuntimeError("The upstream trained model dependencies are unavailable")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="idax-diaphora-") as temporary:
        copy = Path(temporary) / "primary.sqlite"
        secondary_copy = Path(temporary) / "secondary.sqlite"
        for original, copied in ((primary, copy), (secondary, secondary_copy)):
            with sqlite3.connect(f"{original.as_uri()}?mode=ro", uri=True) as source:
                if source.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 0:
                    raise ValueError("Diaphora matching requires nonempty function exports")
                with sqlite3.connect(copied) as destination:
                    source.backup(destination)
        diff = engine_class(engine)(str(copy))
        try:
            diff.cpu_count = 1  # Upstream's documented non-IDA execution model.
            diff.relaxed_ratio = relaxed_ratio
            diff.use_trained_model = use_model
            if use_model:
                # Resolve the pinned model independently of the caller's cwd.
                engine.config.ML_TRAINED_MODEL = str(
                    Path(root).resolve() / engine.config.ML_TRAINED_MODEL)
            if all_heuristics:
                diff.unreliable = True
                diff.experimental = True
                diff.slow_heuristics = True
            if not diff.diff(str(secondary_copy)):
                raise RuntimeError("Diaphora rejected the secondary database")
            diff.save_results(str(output))
        finally:
            diff.db_close()
    with sqlite3.connect(output) as db:
        db.execute("UPDATE config SET main_db=?, diff_db=?", (str(primary), str(secondary)))
    return read_results(output)
