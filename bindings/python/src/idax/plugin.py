"""Plugin lifecycle, actions, hotkeys, and opaque host contexts."""

from ._native import plugin as _native

Info = _native.Info
Plugin = _native.Plugin
ExportFlags = _native.ExportFlags
TypeRef = _native.TypeRef
ActionContext = _native.ActionContext
HostHandle = _native.HostHandle
Action = _native.Action
ScopedHotkey = _native.ScopedHotkey
widget_host = _native.widget_host
with_widget_host = _native.with_widget_host
decompiler_view_host = _native.decompiler_view_host
with_decompiler_view_host = _native.with_decompiler_view_host
register_action = _native.register_action
unregister_action = _native.unregister_action
activate_action = _native.activate_action
register_hotkey = _native.register_hotkey
attach_to_menu = _native.attach_to_menu
attach_to_toolbar = _native.attach_to_toolbar
attach_to_popup = _native.attach_to_popup
detach_from_menu = _native.detach_from_menu
detach_from_toolbar = _native.detach_from_toolbar
detach_from_popup = _native.detach_from_popup

__all__ = [
    "Action", "ActionContext", "ExportFlags", "HostHandle", "Info", "Plugin",
    "ScopedHotkey", "TypeRef", "activate_action", "attach_to_menu",
    "attach_to_popup", "attach_to_toolbar", "decompiler_view_host",
    "detach_from_menu", "detach_from_popup", "detach_from_toolbar",
    "register_action", "register_hotkey", "unregister_action", "widget_host",
    "with_decompiler_view_host", "with_widget_host",
]
