# idax examples

Realistic reference implementations using the idax wrapper API. Each advanced
example solves a recognizable reverse-engineering problem rather than merely
exercising API calls.

## Minimal examples (quick-start)

- **`plugin/action_plugin.cpp`** — Quick Annotator: registers keyboard-driven
  actions for marking addresses as reviewed, adding numbered bookmarks, and
  clearing annotations from a function.
- **`loader/minimal_loader.cpp`** — Minimal custom loader skeleton.
- **`procmod/minimal_procmod.cpp`** — Minimal processor module skeleton.

## Advanced examples

### `plugin/deep_analysis_plugin.cpp` — Binary Audit Report

Generates a structured security-oriented audit report: W^X segment violations,
large stack frames (overflow surfaces), suspicious instruction patterns (INT3
sequences, NOP sleds), string recovery with annotation, fixup distribution
analysis, call-graph xref hotspots, and type-library entry creation. Hotkey:
**Ctrl-Shift-A**.

### `plugin/decompiler_plugin.cpp` — Complexity Metrics

Computes McCabe cyclomatic complexity for all decompilable functions using a
custom CtreeVisitor that counts decision points (if/for/while/switch/ternary/
logical operators). Produces a ranked report, annotates the most complex
function with comments and variable renames, and correlates flowchart block
counts with the ctree-derived metric. Hotkey: **Ctrl-Shift-C**.

### `plugin/event_monitor_plugin.cpp` — Change Tracker

Records all database modifications (renames, patches, comments, segment and
function changes) plus UI and debugger events into a thread-safe log. Presents
changes in a live chooser window and builds a labeled impact graph on stop.
Persists a summary into a netnode for cross-session audit trails. Toggle with
**Ctrl-Shift-T**.

### `plugin/storage_metadata_plugin.cpp` — Binary Fingerprint

Computes a structural fingerprint (segment layout digest, function histogram by
size bucket, fixup type distribution, string statistics, address coverage ratios)
and persists it in a netnode. On subsequent runs, compares against the stored
fingerprint and highlights what changed — useful for tracking database drift in
multi-analyst workflows. Hotkey: **Ctrl-Shift-F**.

### `loader/advanced_loader.cpp` — XBIN Format Loader

Demonstrates complete loader development with a hypothetical "XBIN" binary
format. Covers file identification via magic signature, multi-segment creation
with varied permissions/types, file-to-database and memory-to-database data
transfer, BSS gap filling, entry point registration with type application,
fixup injection for relocatable binaries, save capability queries, and rebase
handling.

### `procmod/advanced_procmod.cpp` — XRISC-32 Processor Module

A full processor module for a hypothetical 32-bit RISC ISA with 16 instructions.
Implements all required callbacks (analyze, emulate, output\_instruction,
output\_operand) with complete text generation including symbol resolution for
branch targets. Also implements all 15 optional callbacks: call/return
classification, function prolog recognition, stack pointer delta tracking,
indirect jump detection, basic block termination, switch table detection with
case enumeration and xref creation.

### `loader/jbc_full_loader.cpp` + `procmod/jbc_full_procmod.cpp` — JBC Full Port

End-to-end port of the `ida-jam` JAM Byte-Code modules into idax style. The
loader recreates JBC section mapping (`.strtab`, `.code`, `.data`), imports
actions/procedures into IDA entries/functions, and persists processor state in
`ida::storage::Node` (`$ JBC`). The paired processor reuses the JBC opcode
table for decode sizing, xref generation, jump/call/ret classification, and
text rendering via `OutputContext`.

This pair is intentionally "full" rather than minimal: it mirrors a real
porting workflow and surfaces where SDK-level procmod hooks still exceed the
current idax abstraction.

### `plugin/qtform_renderer_plugin.cpp` + `plugin/qtform_renderer_widget.cpp` — ida-qtform Port

Port of `/Users/int/dev/ida-qtform` to idax plugin and UI surfaces. It uses
`ida::ui::create_widget()` + `ida::ui::with_widget_host()` to mount a Qt
renderer widget in a dock panel and parse IDA form markup into live controls.
The original "Test in ask_form" flow now uses markup-only
`ida::ui::ask_form(std::string_view)`.

### `plugin/lifter_port_plugin.cpp` — lifter Port Probe

Port probe of `/Users/int/dev/lifter` focused on plugin-shell workflows that
are currently portable through idax: action registration, pseudocode popup
attachment, decompiler pseudocode/microcode snapshot dumping, and
outlined-flag/cache-invalidation helpers.

It also prints a gap report for the currently missing APIs needed for a full
AVX/VMX microcode-lifter migration (rich microcode IR mutation surfaces and
raw decompiler-view handle context for advanced per-view manipulations).

### `tools/idalib_dump_port.cpp` — idalib-dump Port (no Telegram)

Port of `/Users/int/dev/idalib-dump` `ida_dump` behavior to pure idax calls:
database open/analysis wait, function traversal/filtering, assembly dump, and
pseudocode/microcode dump, plus headless plugin policy controls
(`--no-plugins`, `--plugin <pattern>`) through `ida::database::RuntimeOptions`.
It also demonstrates database metadata helpers (`file_type_name`,
`loader_format_name`, `compiler_info`, `import_modules`).

### `tools/idalib_lumina_port.cpp` — ida_lumina Port Scaffold

Headless idax session scaffold for `ida_lumina`-style workflows using
`ida::lumina::pull()` and `ida::lumina::push()` against a resolved function
address.

### `tools/ida2py_port.cpp` — ida2py Port Probe

Port of `/Users/int/Downloads/plo/ida2py-main` static query workflows to pure
idax calls: user-defined symbol discovery, type apply/retrieve checks,
symbol-centric value/xref inspection, and decompiler-backed callsite text
listing. It also includes optional runtime `--appcall-smoke` coverage for
debugger-capable hosts (`ida::debugger::appcall`); use
`scripts/build_appcall_fixture.sh` to generate a host-native `ref4` fixture
before running smoke checks.

## Building

By default, examples are listed as source-only targets. To build addon binaries:

```bash
cmake -S . -B build -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_ADDONS=ON
cmake --build build
```

To build the idalib tool port example as an executable:

```bash
cmake -S . -B build -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_TOOLS=ON
cmake --build build --target idax_idalib_dump_port idax_idalib_lumina_port idax_ida2py_port
```

When a real IDA runtime is available (`IDADIR` or common macOS install path),
tool examples are linked against the real runtime dylibs. Otherwise they fall
back to SDK idalib stubs for compile-only environments.
