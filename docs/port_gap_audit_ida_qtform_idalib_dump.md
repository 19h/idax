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

- No open high-severity parity gaps remain for the audited non-Telegram paths.

## Notes

- The Qt host-mount path itself is available via `ida::ui::with_widget_host`,
  so panel embedding in the `ida-qtform` port works without raw `TWidget*`
  exposure.
- A markup-only `ida::ui::ask_form(std::string_view)` wrapper is now available
  for direct form-preview/test flows without vararg SDK calls.
- Decompiler microcode emission is now exposed through
  `DecompiledFunction::microcode()` and `DecompiledFunction::microcode_lines()`.
- Structured decompile failure details are now available through
  `ida::decompiler::DecompileFailure` + `decompile(address, &failure)`.
- Headless plugin-load controls are now available in `ida::database` via
  `RuntimeOptions` + `PluginLoadPolicy`, including `--no-plugins` and
  allowlist-pattern flows used by `idalib_dump_port`.
- Additional binary/runtime metadata parity helpers are now available in
  `ida::database`: `file_type_name`, `loader_format_name`, `compiler_info`, and
  `import_modules`.
- Lumina pull/push wrappers are now available in `ida::lumina` and exercised by
  `examples/tools/idalib_lumina_port.cpp`.
- Telegram-bot paths were intentionally excluded per request.
