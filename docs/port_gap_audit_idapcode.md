# Port Gap Audit: idapcode

Date: 2026-02-16

This audit records findings from porting:

- `/Users/int/Downloads/plo/idapcode-main`

to idax-first surfaces.

## Port artifact in this repository

- `examples/plugin/idapcode_port_plugin.cpp`

## Third-party dependency strategy (port-specific)

- Sleigh is integrated as a git submodule at `third-party/sleigh`.
- The idapcode port target is opt-in (`IDAX_BUILD_EXAMPLE_IDAPCODE_PORT=ON`) so
  the core idax build/test path remains unaffected.
- Sleigh spec compilation is separately opt-in (`IDAX_IDAPCODE_BUILD_SPECS=ON`)
  because building all specs is heavy and unnecessary for non-idapcode flows.

## Covered migration flows

- Plugin lifecycle via `ida::plugin::Plugin`; runtime shortcut set to
  `Ctrl-Alt-Shift-P` to avoid `Ctrl-Alt-S` collisions in common SigMaker
  environments.
- Current-function resolution and byte extraction from IDA database state.
- Custom viewer rendering of instruction headers and per-instruction p-code ops.
- Bidirectional navigation sync between linear disassembly and the p-code viewer
  (cursor/click in either view updates the other).
- Processor-context capture (ID, name, bitness, endianness, ABI) for Sleigh
  spec selection.
- Sleigh translation wiring for one-instruction p-code emission over function
  instruction addresses.

## Source-to-idax API mapping

| idapcode source API | idax / port mapping | Status |
|---|---|---|
| `idaapi.plugin_t` + `PLUGIN_ENTRY()` | `ida::plugin::Plugin` + `IDAX_PLUGIN(...)` | covered |
| `idaapi.get_screen_ea()` | `ida::ui::screen_address()` | covered |
| `ida_funcs.get_func()` | `ida::function::at()` | covered |
| `ida_name.get_name()` | `ida::function::Function::name()` | covered |
| `ida_bytes.get_bytes()` | `ida::data::read_bytes()` | covered |
| `ida_ida.inf_is_64bit()/inf_is_32bit_exactly()` | `ida::database::address_bitness()` | covered |
| `ida_ida.inf_is_be()` | `ida::database::is_big_endian()` | covered |
| `idaapi.ph_get_id()` | `ida::database::processor_id()` / `ida::database::processor()` | covered |
| `idaapi.get_abi_name()` | `ida::database::abi_name()` | covered |
| `ida_kernwin.simplecustviewer_t` | `ida::ui::create_custom_viewer()` + `set_custom_viewer_lines()` | covered |
| `pypcode.Context.translate()` | `ghidra::Sleigh::oneInstruction()` through Sleigh C++ API | covered |

## API surface gaps discovered

1. **Processor-profile granularity is still partial for perfect Sleigh language selection.**
   - Current idax processor metadata is now sufficient for many mappings
     (`processor_id`, `address_bitness`, `is_big_endian`, `abi_name`) but does
     not encode all processor-module profile details (e.g., ARM profile/revision
     variants) in a single normalized wrapper model.
   - Impact: the port uses deterministic best-effort `.sla` selection per
     processor family; uncommon profile variants may require manual spec override.

2. **No first-class idax p-code domain (intentional scope boundary).**
   - Translation is provided by external Sleigh libraries, not by a native
     `ida::pcode` namespace in idax.
   - Impact: this port remains plugin/example-specific and depends on Sleigh
     runtime assets (`.sla`/`.pspec`).

## Notes

- Runtime spec search follows Sleigh defaults and may be overridden with
  `IDAX_IDAPCODE_SPEC_ROOT`.
- The port keeps all plugin code SDK-opaque on the idax side; raw SDK symbols
  are not used directly in plugin logic.
