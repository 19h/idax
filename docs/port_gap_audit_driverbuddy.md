# Port Gap Audit: DriverBuddy

Date: 2026-02-16

This audit records findings from porting the following project to idax-first
surfaces:

- `/Users/int/Downloads/plo/DriverBuddy-master`

## Port artifacts in this repository

- `examples/plugin/driverbuddy_port_plugin.cpp`

## Covered migration flows

- Plugin lifecycle and hotkey-driven actions (`Ctrl-Alt-D`, `Ctrl-Alt-I`).
- Driver detection and type classification via imports (`WDM/WDF/Mini-Filter/AVStream/PortCls/Stream Minidriver`).
- Dangerous C/WinAPI function discovery with caller xref reporting.
- WDM dispatch discovery (`DispatchDeviceControl` / `DispatchInternalDeviceControl`) including fake-entry unwrapping heuristics.
- IOCTL decoding (interactive under cursor + listing-based scan from `IoControlCode` hits).
- WDF dispatch-table type materialization and annotation (`WDFFUNCTIONS`).

## Source-to-idax API mapping

| DriverBuddy source API | idax mapping | Status |
|---|---|---|
| `idaapi.plugin_t` + `PLUGIN_ENTRY()` | `ida::plugin::Plugin` + `IDAX_PLUGIN(...)` | covered |
| `autoWait()` | `ida::analysis::wait()` | covered |
| `Functions()` + `GetFunctionName()` | `ida::function::all()` + `ida::function::Function::name()` | covered |
| `enum_import_names()` + import callbacks | `ida::database::import_modules()` | covered |
| `CodeRefsTo()` | `ida::xref::code_refs_to()` | covered |
| `MinEA()/MaxEA()` + `FindText()` | `ida::database::min_address()/max_address()` + `ida::search::text()` | covered |
| `GetOpType()/GetOperandValue()/ScreenEA()` | `ida::instruction::decode()` + `ida::ui::screen_address()` | covered |
| `MakeName()` | `ida::name::force_set()` | covered |
| `OpStroffEx()` | `ida::instruction::set_operand_struct_offset()` | covered |
| `op_based_stroff`-style representation | `ida::instruction::set_operand_based_struct_offset()` | covered |
| `Til2Idb(-1, type)` + `doStruct()` | `ida::type::import_type()` + `ida::type::apply_named_type()` | partial |
| `add_hotkey()` | `ida::plugin::Action{.hotkey=...}` | partial |

## API surface gaps discovered

1. **No dedicated standard-type bootstrap helper (non-blocking).**
   - Raw workflow: `Til2Idb(-1, "IRP")` asks IDA to pull a built-in type into the IDB.
   - Current idax workaround: `ida::type::import_type("", "IRP")` (best effort).
   - Impact: ports that rely on many platform structs need extra fallback handling and diagnostics when the active type libraries differ.

2. **No struct-offset path introspection helper (non-blocking).**
   - Raw workflow: `get_stroff_path(...)` verifies/inspects operand struct-offset path metadata.
   - Current idax: write helpers (`set_operand_struct_offset`, `set_operand_based_struct_offset`) exist, but readback/introspection is not yet surfaced.
   - Impact: verification tooling around nested/complex struct-offset annotations requires SDK fallback today.

3. **No one-call hotkey callback helper (ergonomic only).**
   - Raw workflow: `add_hotkey("Ctrl+Alt+I", callback)`.
   - Current idax: use action registration (`register_action` + menu/popup attachment).
   - Impact: not a parity blocker, but simple utility hotkeys require more boilerplate than the legacy API.

## Notes

- This port intentionally keeps to idax public APIs only and does not use raw SDK symbols in plugin code.
- WDF table annotation uses a curated high-value slot subset (first 180 entries) to keep the example readable while preserving the migration pattern.
