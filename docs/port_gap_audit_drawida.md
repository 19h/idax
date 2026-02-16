# Port Gap Audit: DrawIDA

Date: 2026-02-16

This audit records findings from porting the following project to idax-first
surfaces:

- `/Users/int/Downloads/plo/DrawIDA-main`

## Port artifacts in this repository

- `examples/plugin/drawida_port_plugin.cpp`
- `examples/plugin/drawida_port_widget.hpp`
- `examples/plugin/drawida_port_widget.cpp`

## Source-to-idax API mapping

| DrawIDA source API | idax mapping | Status |
|---|---|---|
| `idaapi.plugin_t` + `PLUGIN_ENTRY()` | `ida::plugin::Plugin` + `IDAX_PLUGIN(...)` | covered |
| Plugin export flags (`plugin_t.flags`) | `IDAX_PLUGIN_WITH_FLAGS(...)` + `ida::plugin::ExportFlags` | covered |
| `ida_kernwin.PluginForm` + `FormToPyQtWidget()` | `ida::ui::create_widget()` + `ida::ui::with_widget_host()` | covered |
| Typed host widget cast (`QWidget*`) | `ida::ui::with_widget_host_as<QWidget>()` | covered |
| `PluginForm.Show()` / `raise_()` / `activateWindow()` | `ida::ui::show_widget()` + `ida::ui::activate_widget()` | covered |
| `ida_kernwin.msg()` | `ida::ui::message()` | covered |

## Confirmed migration gaps

- No open parity gaps remain for DrawIDA's feature set.

## Notes

- Draw/text/erase/select interactions, selection drag/delete, undo/redo stack,
  and style/background controls are implemented entirely in Qt widget logic and
  integrate cleanly with idax's plugin + dock-widget hosting surfaces.
- The follow-up ergonomics pass added:
  - `IDAX_PLUGIN_WITH_FLAGS(...)` with `ida::plugin::ExportFlags` for
    per-plugin export flag control while preserving idax's `PLUGIN_MULTI`
    bridge model.
  - `ida::ui::widget_host_as<T>()` and `ida::ui::with_widget_host_as<T>()`
    typed host helpers to avoid repetitive `void*` casts in Qt plugin code.
