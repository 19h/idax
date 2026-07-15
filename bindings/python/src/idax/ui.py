"""Dialogs, forms, widgets, choosers, timers, and UI events."""

from ._native import ui as _native
from .plugin import HostHandle

Chooser = _native.Chooser
ChooserOptions = _native.ChooserOptions
Column = _native.Column
ColumnFormat = _native.ColumnFormat
DockPosition = _native.DockPosition
Event = _native.Event
EventKind = _native.EventKind
FormAddressBinding = _native.FormAddressBinding
FormBinding = _native.FormBinding
FormBuilder = _native.FormBuilder
FormIntBinding = _native.FormIntBinding
FormPathBinding = _native.FormPathBinding
FormSvalBinding = _native.FormSvalBinding
FormTextBinding = _native.FormTextBinding
FormU16Binding = _native.FormU16Binding
LineRenderEntry = _native.LineRenderEntry
PopupEvent = _native.PopupEvent
Progress = _native.Progress
RenderingEvent = _native.RenderingEvent
Row = _native.Row
RowStyle = _native.RowStyle
ScopedSubscription = _native.ScopedSubscription
ShowWidgetOptions = _native.ShowWidgetOptions
WaitBox = _native.WaitBox
Widget = _native.Widget
WidgetType = _native.WidgetType
activate_widget = _native.activate_widget
ask_address = _native.ask_address
ask_file = _native.ask_file
ask_form = _native.ask_form
ask_long = _native.ask_long
ask_string = _native.ask_string
ask_text = _native.ask_text
ask_yn = _native.ask_yn
attach_dynamic_action = _native.attach_dynamic_action
attach_registered_action = _native.attach_registered_action
clipboard_backend = _native.clipboard_backend
close_custom_viewer = _native.close_custom_viewer
close_widget = _native.close_widget
copy_to_clipboard = _native.copy_to_clipboard
create_custom_viewer = _native.create_custom_viewer
create_widget = _native.create_widget
current_widget = _native.current_widget
custom_viewer_current_line = _native.custom_viewer_current_line
custom_viewer_jump_to_line = _native.custom_viewer_jump_to_line
custom_viewer_line_count = _native.custom_viewer_line_count
find_widget = _native.find_widget
form_address = _native.form_address
form_bitset = _native.form_bitset
form_builder = _native.form_builder
form_int = _native.form_int
form_path = _native.form_path
form_radio = _native.form_radio
form_sval = _native.form_sval
form_text = _native.form_text
info = _native.info
is_widget_visible = _native.is_widget_visible
jump_to = _native.jump_to
message = _native.message
on_current_widget_changed = _native.on_current_widget_changed
on_cursor_changed = _native.on_cursor_changed
on_database_closed = _native.on_database_closed
on_database_inited = _native.on_database_inited
on_event = _native.on_event
on_event_filtered = _native.on_event_filtered
on_popup_ready = _native.on_popup_ready
on_ready_to_run = _native.on_ready_to_run
on_rendering_info = _native.on_rendering_info
on_screen_ea_changed = _native.on_screen_ea_changed
on_view_activated = _native.on_view_activated
on_view_closed = _native.on_view_closed
on_view_created = _native.on_view_created
on_view_deactivated = _native.on_view_deactivated
on_widget_closing = _native.on_widget_closing
on_widget_invisible = _native.on_widget_invisible
on_widget_visible = _native.on_widget_visible
read_clipboard = _native.read_clipboard
refresh_all_views = _native.refresh_all_views
refresh_custom_viewer = _native.refresh_custom_viewer
register_timer = _native.register_timer
screen_address = _native.screen_address
selection = _native.selection
set_custom_viewer_lines = _native.set_custom_viewer_lines
show_widget = _native.show_widget
unregister_timer = _native.unregister_timer
unsubscribe = _native.unsubscribe
user_directory = _native.user_directory
warning = _native.warning
widget_host = _native.widget_host
widget_type = _native.widget_type
with_widget_host = _native.with_widget_host

__all__ = [
    "Chooser", "ChooserOptions", "Column", "ColumnFormat", "DockPosition",
    "Event", "EventKind", "FormAddressBinding", "FormBinding", "FormBuilder",
    "FormIntBinding", "FormPathBinding", "FormSvalBinding", "FormTextBinding",
    "FormU16Binding", "HostHandle", "LineRenderEntry", "PopupEvent", "Progress",
    "RenderingEvent", "Row", "RowStyle", "ScopedSubscription",
    "ShowWidgetOptions", "WaitBox", "Widget", "WidgetType", "activate_widget",
    "ask_address", "ask_file", "ask_form", "ask_long", "ask_string", "ask_text",
    "ask_yn", "attach_dynamic_action", "attach_registered_action",
    "clipboard_backend", "close_custom_viewer", "close_widget",
    "copy_to_clipboard", "create_custom_viewer", "create_widget", "current_widget",
    "custom_viewer_current_line", "custom_viewer_jump_to_line",
    "custom_viewer_line_count", "find_widget", "form_address", "form_bitset",
    "form_builder", "form_int", "form_path", "form_radio", "form_sval",
    "form_text", "info", "is_widget_visible", "jump_to", "message",
    "on_current_widget_changed", "on_cursor_changed", "on_database_closed",
    "on_database_inited", "on_event", "on_event_filtered", "on_popup_ready",
    "on_ready_to_run", "on_rendering_info", "on_screen_ea_changed",
    "on_view_activated", "on_view_closed", "on_view_created",
    "on_view_deactivated", "on_widget_closing", "on_widget_invisible",
    "on_widget_visible", "read_clipboard", "refresh_all_views",
    "refresh_custom_viewer", "register_timer", "screen_address", "selection",
    "set_custom_viewer_lines", "show_widget", "unregister_timer", "unsubscribe",
    "user_directory", "warning", "widget_host", "widget_type", "with_widget_host",
]
