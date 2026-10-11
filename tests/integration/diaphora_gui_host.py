"""Start actual chooser evidence inside an existing owned IDA GUI database."""
import json
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
                      address=current, timestamp=time.time())
        if action == "import":
            record["comment"] = function.comment(current, True)
        with evidence.open("a", encoding="utf-8") as out:
            out.write(json.dumps(record) + "\n")

    if existing:
        from examples.diaphora import gui
        choosers = gui._SESSIONS[-1]
        for chooser in choosers:
            for method, action in (("on_enter", "jump"), ("on_edit", "import"),
                                   ("show_diff", "diff")):
                original = getattr(chooser, method)
                def observed(index, original=original, action=action, chooser=chooser):
                    original(index)
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
            rows={value.category: value.count() for value in choosers})) + "\n")
    return choosers
