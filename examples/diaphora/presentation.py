"""Audited native HTML generation and copied graph presentation data."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import difflib
from pathlib import Path
import re
import sqlite3
import tempfile

from .backend import engine_class, load_backend, upstream_definitions


@dataclass
class RenderedDiff:
    title: str
    content: str


@dataclass
class GraphModel:
    title: str
    # (native key/name, displayed text, native 0xBBGGRR color)
    nodes: list[tuple[str, str, int]]
    edges: list[tuple[int, int]]


def _renderer_class(root, backend, decompile, captures):
    try:
        from pygments import highlight
        from pygments.formatters import HtmlFormatter
        from pygments.lexers import CppLexer, DiffLexer, NasmLexer
    except ImportError as error:
        raise RuntimeError("Diaphora HTML rendering requires Pygments") from error

    class HtmlSink:
        def Show(self, text, title):
            captures.append(RenderedDiff(title, text))

    namespace = dict(config=backend.config, re=re, difflib=difflib,
        highlight=highlight, HtmlFormatter=HtmlFormatter, CppLexer=CppLexer,
        DiffLexer=DiffLexer, NasmLexer=NasmLexer, log=backend.log,
        warning=backend.log, CHtmlViewer=HtmlSink)
    namespace.update(upstream_definitions(root, "diaphora_ida.py", {"CHtmlDiff"}, namespace))
    methods = upstream_definitions(root, "diaphora_ida.py", {
        "get_sources_diff_data", "generate_asm_diff_internal", "generate_asm_diff",
        "generate_pseudo_diff", "show_asm", "show_pseudo"}, namespace,
        class_name="CIDABinDiff")

    class Renderer(engine_class(backend)):
        def decompile_and_get(self, address):
            if decompile is None:
                return False
            value = decompile(address)
            if value is None:
                return False
            prototype, lines = value
            self.pseudo[address] = list(lines)
            return prototype

    for key, method in methods.items():
        setattr(Renderer, key, method)
    return Renderer


@contextmanager
def _session(root, primary, secondary, *, rendering=False, decompile=None):
    backend = load_backend(root)
    captures = []
    value_class = _renderer_class(root, backend, decompile, captures) if rendering else engine_class(backend)
    with tempfile.TemporaryDirectory(prefix="idax-diaphora-presentation-") as temporary:
        paths = [Path(temporary) / name for name in ("primary.sqlite", "secondary.sqlite")]
        for original, copied in zip((primary, secondary), paths):
            path = Path(original).resolve(strict=True)
            with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as one, sqlite3.connect(copied) as two:
                one.backup(two)
        value = value_class(str(paths[0]))
        try:
            # Parameter binding also handles a quoted temporary parent directory.
            value.get_db().execute("ATTACH DATABASE ? AS diff", (str(paths[1]),))
            yield value, backend, captures
        finally:
            value.db_close()


def render_diff(root, primary, secondary, first, second, *, field="assembly",
                html=True, decompile=None):
    """Return native side-by-side or syntax-highlighted patch HTML.

    Without a decompiler callback, pseudocode uses the persisted primary export.
    A callback returns (prototype, body_lines) from the current primary IDB.
    """
    if field not in ("assembly", "microcode", "pseudocode"):
        raise ValueError("Unknown Diaphora difference field: " + field)
    with _session(root, primary, secondary, rendering=True, decompile=decompile) as (value, _, _):
        first, second = format(int(first), "x"), format(int(second), "x")
        if field == "pseudocode":
            result = value.generate_pseudo_diff(first, second, html=html)
        else:
            title = "Diff assembly %s - %s" if field == "assembly" else "Diff microcode %s - %s"
            result = value.generate_asm_diff_internal(first, second, field, title, html=html)
        if result is None:
            raise ValueError("Native exports lack the requested " + field + " pair")
        content, title = result
        return RenderedDiff(title, content)


def render_source(root, primary, secondary, address, *, primary_side=True, field="assembly"):
    """Return the native single-function preview, including unmatched functions."""
    if field not in ("assembly", "pseudocode"):
        raise ValueError("Unknown Diaphora preview field: " + field)
    with _session(root, primary, secondary, rendering=True) as (value, _, captures):
        item = [0, format(int(address), "x")]
        method = value.show_asm if field == "assembly" else value.show_pseudo
        method(item, primary_side)
        if not captures:
            raise ValueError("Native export lacks the requested " + field + " source")
        return captures[-1]


def _block_model(title, data, colors):
    blocks, relations = data
    nodes = [(key, "\n".join(row[2] for row in rows), colors.get(key, 0xFFFFFF))
             for key, rows in blocks.items()]
    indices = {key: index for index, (key, _, _) in enumerate(nodes)}
    edges = []
    for parent, children in relations.items():
        for key in (parent, *sorted(children)):
            if key not in indices:
                indices[key] = len(nodes)
                nodes.append((key, "", colors.get(key, 0xFFFFFF)))
        edges.extend((indices[parent], indices[child]) for child in sorted(children))
    return GraphModel(title, nodes, edges)


def graph_pair(root, primary, secondary, first, second, *, microcode=False):
    """Copy native graph text, relations and exact-match/changed-block colors."""
    with _session(root, primary, secondary) as (value, _, _):
        addresses = (str(int(first)), str(int(second)))
        kind = "microcode" if microcode else "native"
        data = (value.get_graph(addresses[0], True, kind), value.get_graph(addresses[1], False, kind))
        if any(item == ({}, {}) for item in data):
            raise ValueError("Native exports lack the requested graph pair")
        colors = value.compare_graphs(*data)
        models = []
        for index, db in enumerate(("main", "diff")):
            row = value.get_db().execute(f"SELECT name FROM {db}.functions WHERE address=?",
                                         (addresses[index],)).fetchone()
            prefix = "Microcode graph" if microcode else "Graph"
            side = "primary" if index == 0 else "secondary"
            models.append(_block_model(f"{prefix} for {row['name']} ({side})", data[index], colors[index]))
        return tuple(models)


def callgraph_pair(root, primary, secondary, first, second):
    """Copy the native caller/target/callee graph, preserving duplicate nodes."""
    with _session(root, primary, secondary) as (value, backend, _):
        methods = upstream_definitions(root, "diaphora_ida.py", {"get_calls_graph"},
            {}, class_name="CIDABinDiff")
        models = []
        for address, db in ((first, "main"), (second, "diff")):
            row = value.get_db().execute(f"SELECT name FROM {db}.functions WHERE address=?",
                                         (str(int(address)),)).fetchone()
            if row is None:
                raise ValueError("Native export lacks the requested callgraph function")
            name = row["name"]
            nodes = [(name, name, backend.config.CALLGRAPH_COLOR_TARGET)]
            edges = []
            for kind, color in (("caller", backend.config.CALLGRAPH_COLOR_CALLER),
                                ("callee", backend.config.CALLGRAPH_COLOR_CALLEE)):
                for item in methods["get_calls_graph"](value, name, kind, db):
                    index = len(nodes)
                    nodes.append((item["name1"], item["name1"], color))
                    edges.append((index, 0) if kind == "caller" else (0, index))
            models.append(GraphModel(f"Call graph context for {name}", nodes, edges))
        return tuple(models)


def save_html(rendered, output):
    """Write UTF-8 HTML to a new destination without overwriting existing output."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(rendered.content)
