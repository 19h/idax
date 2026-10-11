"""Start actual chooser evidence inside an existing owned IDA GUI database."""
import json
import os
from pathlib import Path
import time

from idax import analysis, function, ui
from examples.diaphora.gui import show_results


def start(upstream, results, evidence, *, existing=False):
    analysis.wait()
    evidence = Path(evidence)

    def event(action, category, index):
        current = ui.screen_address()
        record = dict(action=action, category=category, index=index,
                      address=current, timestamp=time.time(), pid=os.getpid())
        if action == "import":
            record["comment"] = function.comment(current, True)
        if action in ("graph", "micrograph", "calls"):
            from examples.diaphora import gui
            record["graphs"] = [dict(nodes=value.total_node_count,
                edges=len(value.edges()), closed=callback.closed)
                for value, callback in gui._GRAPH_VIEWS]
        with evidence.open("a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")

    if existing:
        from examples.diaphora import gui
        choosers = gui._SESSIONS[-1]
        for chooser in choosers:
            for method, action in (("on_enter", "jump"), ("on_edit", "import"),
                                   ("show_diff", "diff"), ("show_graph", "graph"),
                                   ("show_micrograph", "micrograph"), ("show_calls", "calls")):
                original = getattr(chooser, method)
                def observed(index, *arguments, original=original, action=action,
                             chooser=chooser, **keywords):
                    original(index, *arguments, **keywords)
                    if action == "jump" and chooser.category == "secondary":
                        return
                    if action != "jump" and not chooser.matched:
                        return
                    event(action, chooser.category, index)
                setattr(chooser, method, observed)
    else:
        choosers = show_results(upstream, results, event_sink=event)
    with evidence.open("a", encoding="utf-8") as out:
        out.write(json.dumps(dict(action="shown", existing=existing,
            pid=os.getpid(),
            rows={value.category: value.count() for value in choosers})) + "\n")
    return choosers


def record_graphs(evidence):
    """Independently inspect every newly opened pair before closing any viewer."""
    import ida_graph
    import ida_kernwin
    from examples.diaphora import gui
    assert gui._GRAPH_SERIAL == len(gui._GRAPH_VIEWS)
    observations = []
    for serial, (value, callback) in enumerate(gui._GRAPH_VIEWS, 1):
        model = callback.model
        title = "Diaphora " + model.title
        if "(primary)" not in title and "(secondary)" not in title:
            title += " (primary)" if serial % 2 else " (secondary)"
        title += " [" + str(serial) + "]"
        widget = ida_kernwin.find_widget(title)
        assert widget is not None and not callback.closed
        native = ida_graph.get_viewer_graph(ida_graph.get_graph_viewer(widget))
        nodes = [node for node in range(native.size()) if native.exists(node)]
        edges = [(node, native.succ(node, index)) for node in nodes
                 for index in range(native.nsucc(node))]
        assert nodes == list(range(len(model.nodes))), (title, nodes)
        assert sorted(edges) == sorted(model.edges), (title, edges)
        observations.append(dict(title=title, nodes=len(nodes), edges=len(edges)))
    data = dict(action="native_graphs", pid=os.getpid(), observations=observations)
    with Path(evidence).open("a", encoding="utf-8") as out:
        out.write(json.dumps(data) + "\n")
    print("DIAPHORA_NATIVE_GRAPHS_PASS", len(observations))


def close_graphs():
    from idax import graph
    from examples.diaphora import gui
    assert gui._GRAPH_SERIAL == len(gui._GRAPH_VIEWS)
    for serial, (_, callback) in enumerate(gui._GRAPH_VIEWS, 1):
        title = "Diaphora " + callback.model.title
        if "(primary)" not in title and "(secondary)" not in title:
            title += " (primary)" if serial % 2 else " (secondary)"
        title += " [" + str(serial) + "]"
        if not callback.closed:
            graph.close_graph_viewer(title)


def record_closed_graphs(evidence):
    """Call after the GUI processes close notifications, retaining all owners."""
    from examples.diaphora import gui
    assert len(gui._GRAPH_VIEWS) == gui._GRAPH_SERIAL
    assert all(callback.closed for _, callback in gui._GRAPH_VIEWS)
    data = dict(action="graphs_closed", closed=len(gui._GRAPH_VIEWS), pid=os.getpid())
    with Path(evidence).open("a", encoding="utf-8") as out:
        out.write(json.dumps(data) + "\n")
    print("DIAPHORA_GRAPH_CLOSE_PASS", data)
