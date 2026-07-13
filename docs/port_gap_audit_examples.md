# Example Port Gap Audit (Consolidated)

Date: 2026-07-14

This is the single status document for maintained real-world example ports.
Detailed historical churn was intentionally removed to keep the audit concise.

## Status at a glance

| Port | Artifact(s) | Status | Remaining gaps |
|---|---|---|---|
| ida-qtform + idalib-dump (no Telegram) | `examples/plugin/qtform_renderer_plugin.cpp`, `examples/plugin/qtform_renderer_widget.cpp`, `examples/tools/idalib_dump_port.cpp`, `examples/tools/idalib_lumina_port.cpp` | closed | None for audited non-Telegram workflows |
| ida2py | `examples/tools/ida2py_port.cpp` | closed | None for audited probe workflows |
| DrawIDA | `examples/plugin/drawida_port_plugin.cpp`, `examples/plugin/drawida_port_widget.cpp` | closed | None |
| IDA-names | `examples/plugin/ida_names_port_plugin.cpp`, `examples/plugin/ida_names_port_widget.cpp` | closed | None; widget title mutation intentionally crosses the explicit opaque-host Qt bridge because the SDK has no `set_widget_title` API |
| abyss | `examples/plugin/abyss_port_plugin.cpp` | closed | Non-blocking delta: `lvars_info`/`lvars_alias` remain advisory (no in-place rename during maturity callbacks) |
| DriverBuddy | `examples/plugin/driverbuddy_port_plugin.cpp` | closed | None; menu action and scoped one-call hotkey lifecycles are modeled separately |
| idapcode | `examples/plugin/idapcode_port_plugin.cpp`, `bindings/rust/idax/examples/idapcode_headless_port.rs` | closed | None for audited wrapper scope; Sleigh remains an explicit external runtime and language-selection policy |
| lifter | `examples/plugin/lifter_port_plugin.cpp` | closed | None for audited lifter-class migration scope |

## Notes

- DriverBuddy registers its menu-visible decode action separately from the
  move-only shortcut-only `ScopedHotkey`, preserving both discoverability and
  deterministic teardown.
- idapcode consumes `ProcessorProfile`, preserving unknown raw processor IDs
  while using optional verified `ProcessorId` values for Sleigh routing.
- idapcode remains opt-in via `IDAX_BUILD_EXAMPLE_IDAPCODE_PORT=ON`; optional spec build remains `IDAX_IDAPCODE_BUILD_SPECS=ON`.
- IDA-names no longer maintains a cached current-widget handle or approximates
  `hxe_switch_pseudocode` with screen-address/refresh events.
- lifter write-path closure is complete for audited workflows (filter hooks, typed emission, helper-call shaping, popup/view helpers).
- This file replaces the previous per-port gap audit documents.
