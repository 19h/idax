"""Actual GUI refresh/removal/lifetime assertions with native SDK observations.

Call start(path), record("initial"), refresh(), record("refreshed"), close(),
and record("closed") from an owned IDA GUI console. Native SDK imports below
are independent test observations; the exercised graph uses opaque IDAX only.
"""
import json
import os
from pathlib import Path

from idax import graph

_STATE = None
_TITLE = "IDAX graph refresh regression"


class Callback(graph.GraphCallback):
    def __init__(self):
        super().__init__()
        self.phase = 0
        self.refreshes = 0
        self.text_nodes = set()
        self.color_nodes = set()
        self.destroyed = False

    def on_refresh(self, value):
        self.refreshes += 1
        if self.phase == 1:
            value.remove_node(1)
            assert value.add_node() == 3
            value.add_edge(0, 2)
            value.add_edge(2, 3)
            self.phase = 2
        return True

    def on_node_text(self, node):
        self.text_nodes.add(node)
        return "IDAX graph refresh witness " + str(node)

    def on_node_color(self, node):
        self.color_nodes.add(node)
        return (0xCCCCFF, 0xCCFFCC, 0xFFCCCC, 0xCCFFFF)[node]

    def on_destroyed(self):
        self.destroyed = True


def start(evidence):
    global _STATE
    assert _STATE is None
    value, callback = graph.Graph(), Callback()
    for _ in range(3):
        value.add_node()
    value.add_edge(0, 1)
    value.add_edge(1, 2)
    _STATE = (value, callback, Path(evidence))
    graph.show_graph(_TITLE, value, callback)


def refresh():
    value, callback, _ = _STATE
    callback.phase = 1
    graph.refresh_graph(_TITLE)


def close():
    graph.close_graph_viewer(_TITLE)


def record(stage):
    assert stage in ("initial", "refreshed", "closed")
    import ida_graph
    import ida_kernwin
    value, callback, evidence = _STATE
    data = dict(stage=stage, pid=os.getpid(), refreshes=callback.refreshes,
        text_nodes=sorted(callback.text_nodes), color_nodes=sorted(callback.color_nodes),
        destroyed=callback.destroyed)
    widget = ida_kernwin.find_widget(_TITLE)
    if stage == "closed":
        assert callback.destroyed and widget is None
    else:
        assert widget is not None and callback.refreshes > 0
        native = ida_graph.get_viewer_graph(ida_graph.get_graph_viewer(widget))
        nodes = [node for node in range(native.size()) if native.exists(node)]
        edges = [(node, native.succ(node, index)) for node in nodes
                 for index in range(native.nsucc(node))]
        expected_nodes = [0, 1, 2] if stage == "initial" else [0, 2, 3]
        expected_edges = [(0, 1), (1, 2)] if stage == "initial" else [(0, 2), (2, 3)]
        assert nodes == expected_nodes and sorted(edges) == expected_edges
        assert set(nodes) <= callback.text_nodes and set(nodes) <= callback.color_nodes
        data.update(nodes=nodes, edges=edges, layout=native.current_layout)
    with evidence.open("a", encoding="utf-8") as out:
        out.write(json.dumps(data) + "\n")
    print("GRAPH_GUI_" + stage.upper() + "_PASS", data)
