# Example Port Gap Audit (Consolidated)

Date: 2026-02-25

This is the single status document for maintained real-world example ports.
Detailed historical churn was intentionally removed to keep the audit concise.

## Status at a glance

| Port | Artifact(s) | Status | Remaining gaps |
|---|---|---|---|
| ida-qtform + idalib-dump (no Telegram) | `examples/plugin/qtform_renderer_plugin.cpp`, `examples/plugin/qtform_renderer_widget.cpp`, `examples/tools/idalib_dump_port.cpp`, `examples/tools/idalib_lumina_port.cpp` | closed | None for audited non-Telegram workflows |
| ida2py | `examples/tools/ida2py_port.cpp` | closed | None for audited probe workflows |
| DrawIDA | `examples/plugin/drawida_port_plugin.cpp`, `examples/plugin/drawida_port_widget.cpp` | closed | None |
| abyss | `examples/plugin/abyss_port_plugin.cpp` | closed | Non-blocking delta: `lvars_info`/`lvars_alias` remain advisory (no in-place rename during maturity callbacks) |
| DriverBuddy | `examples/plugin/driverbuddy_port_plugin.cpp` | partial | Ergonomic-only gap: no one-call hotkey callback helper equivalent to legacy `add_hotkey(...)` |
| idapcode | `examples/plugin/idapcode_port_plugin.cpp` | partial | Processor-profile normalization is best-effort; no first-class native `ida::pcode` namespace (external Sleigh by design) |
| lifter | `examples/plugin/lifter_port_plugin.cpp` | closed | None for audited lifter-class migration scope |

## Notes

- idapcode remains opt-in via `IDAX_BUILD_EXAMPLE_IDAPCODE_PORT=ON`; optional spec build remains `IDAX_IDAPCODE_BUILD_SPECS=ON`.
- lifter write-path closure is complete for audited workflows (filter hooks, typed emission, helper-call shaping, popup/view helpers).
- This file replaces the previous per-port gap audit documents.
