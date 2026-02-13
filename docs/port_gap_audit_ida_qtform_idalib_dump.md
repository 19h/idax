# Port Gap Audit: ida-qtform + idalib-dump (no Telegram)

Date: 2026-02-14

This audit records findings from porting the following projects to idax-first
surfaces:

- `/Users/int/dev/ida-qtform`
- `/Users/int/dev/idalib-dump` (excluding Telegram bot path)

## Port artifacts in this repository

- `examples/plugin/qtform_renderer_plugin.cpp`
- `examples/plugin/qtform_renderer_widget.hpp`
- `examples/plugin/qtform_renderer_widget.cpp`
- `examples/tools/idalib_dump_port.cpp`
- `examples/tools/idalib_lumina_port.cpp`

## Confirmed migration gaps

1. `ui::ask_form` wrapper is missing
   - Impact: `ida-qtform` can render and edit form markup, but cannot execute the
     direct "test in ask_form" flow without dropping to raw SDK calls.
   - Suggested API: `ida::ui::ask_form(std::string_view markup, ...)` with a
     typed argument model.

2. Decompiler microcode output surface is missing
   - Impact: `idalib-dump` `--mc` parity cannot be delivered through idax today.
   - Suggested API: `ida::decompiler::microcode(...)` facade with line/block
     serialization helpers.

3. Headless plugin-load control surface is missing
   - Impact: `--no-plugins` / `--plugin <pattern>` compatibility cannot be
     implemented through idax wrappers (currently requires environment and SDK
     internals in external tools).
   - Suggested API: database/session open options for plugin policy and plugin
     allowlist patterns.

4. Rich decompilation failure details are limited
   - Impact: external tools cannot report failure address details equivalent to
     raw `hexrays_failure_t` (`errea`, detailed descriptors).
   - Suggested API: structured decompile error payload in `ida::decompiler`.

5. Lumina push API is missing
   - Impact: `idalib-dump` `ida_lumina` cannot be ported to pure idax APIs
     without private SDK reverse-engineering patterns.
   - Suggested API: explicit `ida::lumina` namespace with safe push/query flows,
     or intentional non-goal documentation if this remains out of scope.

6. Additional binary metadata parity helpers are still useful
   - Impact: wrapper consumers still need raw SDK for file-format name,
     compiler metadata, and loaded-module inspection parity used by advanced
     diagnostics tools.
   - Suggested API: additive helpers under `ida::database` or `ida::diagnostics`.

## Notes

- The Qt host-mount path itself is available via `ida::ui::with_widget_host`,
  so panel embedding in the `ida-qtform` port works without raw `TWidget*`
  exposure.
- Telegram-bot paths were intentionally excluded per request.
