"""Actual GUI proof of Python graph roots through terminal window closure.

Start each mode from an owned GUI console, then inspect its visible state in a
subsequent console action. Request closure for all modes except manual; close
that viewer through the native UI. Inspect closed state after GUI processing.
The retained state contains weak references only. SDK imports independently
observe widgets/topology; tested ownership uses the public opaque IDAX API.
"""
from __future__ import annotations

import gc
import json
import os
from pathlib import Path
import sys
import weakref

from idax import ValidationError, graph

_PROBES = {}
_UNRAISABLE = []
_PREVIOUS_UNRAISABLE = None


class Callback(graph.GraphCallback):
    def __init__(self, record):
        super().__init__()
        self.record = record

    def on_refresh(self, value):
        self.record['refreshes'] += 1
        return True

    def on_node_text(self, node):
        self.record['text_nodes'].add(node)
        return 'Python rooted graph node ' + str(node)

    def on_node_color(self, node):
        self.record['color_nodes'].add(node)
        return (0xCCCCFF, 0xCCFFCC, 0xFFCCCC)[node]

    def on_destroyed(self):
        assert self.record['graph_ref']() is not None
        assert self.record['callback_ref']() is self
        self.record['terminal_callbacks'] += 1
        if self.record['mode'] == 'raising':
            raise RuntimeError('Expected graph terminal callback witness')


def _write(record, stage, **observations):
    data = dict(mode=record['mode'], stage=stage, pid=os.getpid(),
        terminal_callbacks=record['terminal_callbacks'],
        refreshes=record['refreshes'], **observations)
    with record['evidence'].open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(data) + '\n')
    print('PYTHON_GRAPH_ROOT_' + stage.upper() + '_PASS', data)


def start(mode, evidence):
    global _PREVIOUS_UNRAISABLE
    assert mode in ('requested', 'manual', 'none', 'raising')
    assert mode not in _PROBES
    record = dict(mode=mode, title='IDAX Python graph roots ' + mode,
        evidence=Path(evidence), terminal_callbacks=0, refreshes=0,
        text_nodes=set(), color_nodes=set())
    value = graph.Graph()
    for _ in range(3):
        value.add_node()
    value.add_edge(0, 1)
    value.add_edge(1, 2)
    callback = None if mode == 'none' else Callback(record)
    record['graph_ref'] = weakref.ref(value)
    record['callback_ref'] = None if callback is None else weakref.ref(callback)
    if mode == 'raising':
        assert _PREVIOUS_UNRAISABLE is None
        _PREVIOUS_UNRAISABLE = sys.unraisablehook
        def observed(error):
            # Holding error.object or its traceback would root the callback.
            _UNRAISABLE.append((error.exc_type.__name__, str(error.exc_value)))
        sys.unraisablehook = observed
    _PROBES[mode] = record
    graph.show_graph(record['title'], value, callback)
    # Neither the graph nor the callback is returned or stored strongly here.


def inspect(mode, stage):
    global _PREVIOUS_UNRAISABLE
    assert stage in ('visible', 'closed')
    import ida_graph
    import ida_kernwin
    record = _PROBES[mode]
    gc.collect()
    widget = ida_kernwin.find_widget(record['title'])
    graph_alive = record['graph_ref']() is not None
    callback_alive = record['callback_ref'] is not None and record['callback_ref']() is not None
    if stage == 'visible':
        assert widget is not None and graph_alive
        assert callback_alive == (mode != 'none')
        native = ida_graph.get_viewer_graph(ida_graph.get_graph_viewer(widget))
        nodes = [node for node in range(native.size()) if native.exists(node)]
        edges = [(node, native.succ(node, index)) for node in nodes
                 for index in range(native.nsucc(node))]
        assert nodes == [0, 1, 2] and sorted(edges) == [(0, 1), (1, 2)]
        if mode != 'none':
            assert record['refreshes'] > 0
            assert record['text_nodes'] == record['color_nodes'] == {0, 1, 2}
        assert record['terminal_callbacks'] == 0
        _write(record, stage, graph_alive=graph_alive, callback_alive=callback_alive,
               nodes=nodes, edges=edges)
    else:
        assert widget is None and not graph_alive and not callback_alive
        assert record['terminal_callbacks'] == (0 if mode == 'none' else 1)
        if mode == 'raising':
            assert _UNRAISABLE == [('RuntimeError', 'Expected graph terminal callback witness')]
            sys.unraisablehook = _PREVIOUS_UNRAISABLE
            _PREVIOUS_UNRAISABLE = None
        _write(record, stage, graph_alive=graph_alive, callback_alive=callback_alive,
               unraisable=list(_UNRAISABLE) if mode == 'raising' else [])


def duplicate(mode):
    record = _PROBES[mode]
    value = graph.Graph()
    value.add_node()
    value_ref = weakref.ref(value)
    try:
        graph.show_graph(record['title'], value)
    except ValidationError as error:
        assert 'already in use' in str(error)
    else:
        raise AssertionError('Overlapping viewer title replaced a live owner')
    del value
    gc.collect()
    assert value_ref() is None and record['graph_ref']() is not None
    _write(record, 'duplicate_rejected', original_graph_alive=True,
           rejected_graph_collected=True)


def request_close(mode):
    assert mode != 'manual'
    record = _PROBES[mode]
    graph.close_graph_viewer(record['title'])
    _write(record, 'close_requested',
        graph_alive=record['graph_ref']() is not None,
        callback_alive=record['callback_ref'] is not None and record['callback_ref']() is not None)


def close_with_pending_duplicate(mode):
    """Check overlap before returning control to the native GUI event loop."""
    request_close(mode)
    assert _PROBES[mode]['graph_ref']() is not None
    duplicate(mode)
    _write(_PROBES[mode], 'pending_duplicate_rejected')


def restart(mode):
    """Reuse exactly the same title after the old terminal owner was collected."""
    record = _PROBES[mode]
    gc.collect()
    assert record['graph_ref']() is None
    assert record['callback_ref'] is None or record['callback_ref']() is None
    del _PROBES[mode]
    start(mode, record['evidence'])
    _write(_PROBES[mode], 'title_reused', old_roots_collected=True)


def headless():
    """Prove failed-show cleanup against a real initialized headless runtime."""
    from idax import UnsupportedError, database
    options = database.RuntimeOptions(
        quiet=True, plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True))
    database.init(['idax-python-graph-root-failure'], options)
    cases = [('no-ui', False, UnsupportedError),
             ('no-ui', True, UnsupportedError),
             ('embedded\0NUL', False, ValidationError),
             ('', False, ValidationError)]
    for title, no_callback, expected in cases:
        value = graph.Graph()
        value.add_node()
        record = dict(mode='headless', refreshes=0, terminal_callbacks=0,
                      text_nodes=set(), color_nodes=set())
        callback = None if no_callback else Callback(record)
        value_ref = weakref.ref(value)
        callback_ref = None if callback is None else weakref.ref(callback)
        try:
            graph.show_graph(title, value, callback)
        except expected:
            pass
        else:
            raise AssertionError('Expected real headless/validation failure')
        del value, callback
        gc.collect()
        assert value_ref() is None
        assert callback_ref is None or callback_ref() is None
    print('PYTHON_GRAPH_ROOT_HEADLESS_PASS', len(cases), 'failed shows collected')


if __name__ == '__main__':
    headless()
