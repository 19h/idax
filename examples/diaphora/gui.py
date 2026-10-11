"""Native IDAX chooser for all Diaphora result categories."""
from __future__ import annotations

import difflib
import json
from pathlib import Path
import sqlite3

import idax
from idax import plugin, ui

from .backend import read_results, verify_upstream
from .metadata import import_matches

_SESSIONS = []
_VIEWS = []
_SELECTION = None
_ACTIONS_REGISTERED = False


def _selected_match():
    return _SELECTION is not None and not _SELECTION[0].closed and _SELECTION[0].matched


def _ensure_actions():
    global _ACTIONS_REGISTERED
    if _ACTIONS_REGISTERED:
        return
    actions = (
        ("idax:diaphora:import", "Import selected Diaphora match", "Ctrl-Alt-Shift-I", "on_edit"),
        ("idax:diaphora:diff", "Show selected Diaphora differences", "Ctrl-Alt-Shift-D", "show_diff"),
    )
    registered = []
    try:
        for identifier, label, hotkey, method in actions:
            action = plugin.Action()
            action.id, action.label, action.hotkey = identifier, label, hotkey
            action.enabled = _selected_match
            def handler(method=method):
                if _selected_match():
                    chooser, index = _SELECTION
                    getattr(chooser, method)(index)
            action.handler = handler
            plugin.register_action(action)
            registered.append(identifier)
    except Exception:
        for identifier in registered:
            plugin.unregister_action(identifier)
        raise
    _ACTIONS_REGISTERED = True


def _differences(primary, secondary, record):
    values = []
    for source, key in ((primary, "address"), (secondary, "address2")):
        path = Path(source).resolve(strict=True)
        with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as db:
            row = db.execute("SELECT assembly,pseudocode,microcode FROM functions WHERE address=?",
                             (str(int(record[key], 16)),)).fetchone()
        if row is None:
            raise ValueError("Selected function is absent from its native export")
        values.append(row)
    return {field: list(difflib.unified_diff((values[0][index] or "").splitlines(),
                    (values[1][index] or "").splitlines(),
                    fromfile=record["name"], tofile=record["name2"], lineterm=""))
            for index, field in enumerate(("assembly", "pseudocode", "microcode"))}


def show_results(upstream, results, *, event_sink=None):
    """Keep native choosers alive; Enter jumps and Edit imports a matched row."""
    upstream = verify_upstream(upstream)
    results = Path(results).resolve(strict=True)
    with sqlite3.connect(f"{results.as_uri()}?mode=ro", uri=True) as db:
        primary, secondary = db.execute("SELECT main_db,diff_db FROM config").fetchone()
    rows = read_results(results)
    _ensure_actions()
    _SESSIONS[:] = [session for session in _SESSIONS if not all(chooser.closed for chooser in session)]
    choosers = []
    for category, records in rows.items():
        matched = category not in ("primary", "secondary")
        options = ui.ChooserOptions()
        options.title = "Diaphora: " + category
        options.can_edit = matched
        options.can_refresh = True
        options.modal = False
        columns = ("Address", "Name", "Peer address", "Peer name", "Ratio", "Description") if matched else ("Address", "Name")
        native_columns = []
        for heading in columns:
            column = ui.Column()
            column.name = heading
            column.width = 28 if "name" in heading.lower() or heading == "Description" else 16
            native_columns.append(column)
        options.columns = native_columns

        class ResultsChooser(ui.Chooser):
            def __init__(self, opts, category, records, matched):
                super().__init__(opts)
                self.category, self.records, self.matched = category, records, matched
                self.closed = False

            def count(self):
                return len(self.records)

            def row(self, index):
                value = ui.Row()
                record = self.records[index]
                keys = ("address", "name", "address2", "name2", "ratio", "description") if self.matched else ("address", "name")
                value.columns = [str(record[key]) for key in keys]
                return value

            def address_for(self, index):
                return idax.BAD_ADDRESS if self.category == "secondary" else int(self.records[index]["address"], 16)

            def on_enter(self, index):
                global _SELECTION
                _SELECTION = (self, index)
                if self.category != "secondary":
                    ui.jump_to(self.address_for(index))
                    if event_sink:
                        event_sink("jump", self.category, index)

            def on_edit(self, index):
                if self.matched:
                    record = self.records[index]
                    import_matches(upstream, primary, secondary,
                        [(int(record["address"], 16), int(record["address2"], 16))])
                    if event_sink:
                        event_sink("import", self.category, index)

            def show_diff(self, index):
                if self.matched:
                    for field, lines in _differences(primary, secondary, self.records[index]).items():
                        viewer = ui.create_custom_viewer("Diaphora " + field + " diff " + str(len(_VIEWS) + 1),
                                                         lines or ["No differences in the native exports"])
                        ui.show_widget(viewer)
                        _VIEWS.append(viewer)
                    if event_sink:
                        event_sink("diff", self.category, index)

            def on_close(self):
                self.closed = True

        chooser = ResultsChooser(options, category, records, matched)
        chooser.show()
        choosers.append(chooser)
    _SESSIONS.append(choosers)
    initial = next((chooser for chooser in choosers if chooser.count()), choosers[0])
    ui.activate_widget(ui.find_widget("Diaphora: " + initial.category))
    return choosers


def launch(configuration):
    """Open native results described by a JSON file in an existing IDA GUI."""
    config = json.loads(Path(configuration).read_text(encoding="utf-8"))
    return show_results(config["upstream"], config["results"])
