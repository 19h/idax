"""Register an IDAPython-hosted action for an explicit lifetime."""

from __future__ import annotations

from idax import plugin


ACTION_ID = "example:idax:hello"


def install() -> None:
    action = plugin.Action()
    action.id = ACTION_ID
    action.label = "IDAX Python hello"
    action.handler = lambda: print("hello from IDAX Python")
    action.enabled = lambda: True
    plugin.register_action(action)


def uninstall() -> None:
    plugin.unregister_action(ACTION_ID)
