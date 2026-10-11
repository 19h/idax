"""Compare actual export presentation with native SDK-based upstream objects."""
from __future__ import annotations

import builtins
from contextlib import contextmanager
import difflib
from hashlib import sha256
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile

from idax import database, decompiler, name as naming
from examples.diaphora.backend import load_backend, read_results, upstream_definitions
from examples.diaphora.presentation import callgraph_pair, graph_pair, render_diff, render_source
from examples.diaphora.graph_view import build_graph
from tests.integration.diaphora_export_parity_test import native_engine


@contextmanager
def opaque_imports():
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name in {"idc", "idaapi", "idautils"} or name.startswith("ida_"):
            raise AssertionError("Production presentation used an SDK module: " + name)
        return original(name, *args, **kwargs)
    builtins.__import__ = guarded
    try:
        yield
    finally:
        builtins.__import__ = original


def current_pseudo(address):
    with decompiler.decompile(address) as value:
        lines = [line for line in value.lines() if not line.startswith("//")]
    return None if not lines else (lines[0], lines[1:])


def reference(root, primary, secondary, captures):
    import idaapi
    from pygments import highlight
    from pygments.formatters import HtmlFormatter
    from pygments.lexers import CppLexer, DiffLexer, NasmLexer

    class HtmlSink:
        def Show(self, text, title):
            captures.append((title, text))

    value = native_engine(root, primary)
    namespace = dict(config=load_backend(root).config, re=re, difflib=difflib,
        highlight=highlight, HtmlFormatter=HtmlFormatter, CppLexer=CppLexer,
        DiffLexer=DiffLexer, NasmLexer=NasmLexer, log=print, warning=print,
        CHtmlViewer=HtmlSink, GraphViewer=idaapi.GraphViewer, sys=sys)
    classes = upstream_definitions(root, "diaphora_ida.py",
        {"CHtmlDiff", "CDiffGraphViewer", "CCallGraphViewer"}, namespace)
    namespace.update(classes)
    methods = upstream_definitions(root, "diaphora_ida.py", {
        "get_sources_diff_data", "generate_asm_diff_internal", "generate_asm_diff",
        "generate_pseudo_diff", "show_asm", "show_pseudo", "get_calls_graph"},
        namespace, class_name="CIDABinDiff")
    for key, method in methods.items():
        setattr(type(value), key, method)
    value.attach_database(str(secondary))
    return value, classes


def materialized(model):
    with opaque_imports():
        value, callback = build_graph(model)
        assert value.total_node_count == len(model.nodes)
        assert [(edge.source, edge.target) for edge in value.edges()] == model.edges
        for node, (_, text, color) in enumerate(model.nodes):
            assert callback.on_node_text(node) == text
            assert callback.on_node_color(node) == color


def main(upstream, fixture, category_directory):
    upstream = Path(upstream).resolve()
    category_directory = Path(category_directory).resolve()
    inputs = {(label, index): category_directory / f"{label}-{index}.sqlite"
              for label in ("native", "idax") for index in (0, 1)}
    hashes = {path: sha256(path.read_bytes()).hexdigest() for path in inputs.values()}
    results = read_results(category_directory / "actual-True.results")
    load_backend(upstream)
    database.init()
    with tempfile.TemporaryDirectory(prefix="idax-diaphora-presentation-test-") as temporary:
        work = Path(temporary)
        binary = work / "primary"
        shutil.copyfile(fixture, binary)
        with database.opened(binary, save_on_exit=False):
            primary, secondary = work / "primary.sqlite", work / "secondary.sqlite"
            for index, target in enumerate((primary, secondary)):
                with sqlite3.connect(inputs["native", index]) as one, sqlite3.connect(target) as two:
                    one.backup(two)
            captures = []
            native, classes = reference(upstream, primary, secondary, captures)
            native_decompile = native.decompile_and_get
            native.decompile_and_get = lambda _: False
            try:
                counts = dict(html=0, graphs=0, callgraphs=0, previews=0, live=0)
                for category in ("best", "partial", "unreliable", "multimatch"):
                    assert results[category], "Missing positive native category: " + category
                    item = results[category][0]
                    first, second = int(item["address"], 16), int(item["address2"], 16)
                    for field in ("assembly", "microcode", "pseudocode"):
                        for html in (True, False):
                            if field == "pseudocode":
                                content, title = native.generate_pseudo_diff(item["address"], item["address2"], html=html)
                            else:
                                title_format = "Diff assembly %s - %s" if field == "assembly" else "Diff microcode %s - %s"
                                content, title = native.generate_asm_diff_internal(item["address"], item["address2"], field, title_format, html=html)
                            with opaque_imports():
                                actual = render_diff(upstream, inputs["idax", 0], inputs["idax", 1], first, second, field=field, html=html)
                            assert (actual.title, actual.content) == (title, content)
                            counts["html"] += 1
                    for microcode in (False, True):
                        kind = "microcode" if microcode else "native"
                        data = (native.get_graph(str(first), True, kind), native.get_graph(str(second), False, kind))
                        colors = native.compare_graphs(*data)
                        with opaque_imports():
                            actual = graph_pair(upstream, inputs["idax", 0], inputs["idax", 1], first, second, microcode=microcode)
                        for index, model in enumerate(actual):
                            graph = classes["CDiffGraphViewer"](model.title, data[index], colors[index])
                            assert graph.OnRefresh()
                            expected = [(graph[node][0], *graph.OnGetText(node)) for node in range(len(graph._nodes))]
                            assert sorted(model.nodes) == sorted(expected)
                            expected_edges = {(graph[source][0], graph[target][0]) for source, target in graph._edges}
                            actual_edges = {(model.nodes[source][0], model.nodes[target][0]) for source, target in model.edges}
                            assert actual_edges == expected_edges
                            materialized(model)
                            counts["graphs"] += 1
                    with opaque_imports():
                        actual = callgraph_pair(upstream, inputs["idax", 0], inputs["idax", 1], first, second)
                    for index, db in enumerate(("main", "diff")):
                        name = item["name" if index == 0 else "name2"]
                        graph = classes["CCallGraphViewer"](actual[index].title,
                            native.get_calls_graph(name, "caller", db), native.get_calls_graph(name, "callee", db), name)
                        assert graph.OnRefresh()
                        expected = [(graph[node], *graph.OnGetText(node)) for node in range(len(graph._nodes))]
                        assert actual[index].nodes == expected
                        assert actual[index].edges == graph._edges
                        materialized(actual[index])
                        counts["callgraphs"] += 1
                assert any(callgraph_pair(upstream, inputs["idax", 0], inputs["idax", 1],
                    int(item["address"], 16), int(item["address2"], 16))[0].edges
                    for item in results["partial"])
                for index, category in enumerate(("primary", "secondary")):
                    assert results[category]
                    item = results[category][0]
                    for field in ("assembly", "pseudocode"):
                        captures.clear()
                        method = native.show_asm if field == "assembly" else native.show_pseudo
                        method([0, item["address"]], index == 0)
                        with opaque_imports():
                            actual = render_source(upstream, inputs["idax", 0], inputs["idax", 1],
                                int(item["address"], 16), primary_side=index == 0, field=field)
                        assert [(actual.title, actual.content)] == captures
                        counts["previews"] += 1
                witness = results["partial"][0]
                ea = int(witness["address"], 16)
                witness_name = "idax_live_primary_pseudocode_witness"
                naming.set(ea, witness_name)
                native.decompile_and_get = native_decompile
                for html in (True, False):
                    content, title = native.generate_pseudo_diff(witness["address"], witness["address2"], html=html)
                    with opaque_imports():
                        actual = render_diff(upstream, inputs["idax", 0], inputs["idax", 1], ea,
                            int(witness["address2"], 16), field="pseudocode", html=html, decompile=current_pseudo)
                    assert (actual.title, actual.content) == (title, content)
                    assert witness_name in actual.content
                    counts["live"] += 1
                assert hashes == {path: sha256(path.read_bytes()).hexdigest() for path in inputs.values()}
                print("NATIVE_PRESENTATION_EQUAL", counts)
            finally:
                native.db_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("category_directory", type=Path)
    arguments = parser.parse_args()
    main(arguments.upstream, arguments.fixture, arguments.category_directory)
