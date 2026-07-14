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

### `plugin/ida_names_port_plugin.cpp` + `plugin/ida_names_port_widget.cpp` — IDA-names Port

Qt plugin port that keeps pseudocode window titles synchronized with the
current function name. It uses `ida::ui::current_widget()` for active-view
polling, `ida::decompiler::on_switch_pseudocode()` for function-switch
notifications, and address-free `ida::name::demangled(symbol)` before crossing
the explicit widget-host bridge for `QWidget::setWindowTitle`. The Shift-T
action provides manual title editing.

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

### `loader/sep_firmware_loader.cpp` — Apple SEP Firmware Loader Port

Port of `<userhome>/Downloads/sep-binja-main` into an idax example loader.
It detects raw 64-bit SEP firmware images via the `Built by legion2` markers,
parses the SEP container header/app table, maps the boot/kernel/SEPOS/app/shared
library modules into distinct IDA segments, loads embedded Mach-O segments with
ARM64 permissions, registers discovered entry points plus exported symbols,
annotates Mach-O headers/load commands, defines/applies SEP firmware structure
types, and performs the Binary Ninja loader's init/GOT/tagged-pointer rewrite
passes inside the IDA database.

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

Port of `<userhome>/dev/ida-qtform` to idax plugin and UI surfaces. It uses
`ida::ui::create_widget()` + `ida::ui::with_widget_host()` to mount a Qt
renderer widget in a dock panel and parse IDA form markup into live controls.
The original "Test in ask_form" flow now uses markup-only
`ida::ui::ask_form(std::string_view)`.

### `plugin/drawida_port_plugin.cpp` + `plugin/drawida_port_widget.cpp` — DrawIDA Port (Not Applicable / Host-Constrained)

Port of `<userhome>/Downloads/plo/DrawIDA-main` to idax plugin and UI surfaces.
It recreates DrawIDA's whiteboard workflow (draw/text/eraser/select,
undo/redo, style dialog, clear canvas) using `ida::plugin::Plugin` and
`ida::ui::create_widget()` + `ida::ui::with_widget_host()` to host a Qt canvas
inside a dockable IDA panel.

Since this plugin is purely UI and lacks a meaningful non-UI analysis slice, 
there is no standalone/headless adaptation.

### `plugin/abyss_port_plugin.cpp` — abyss Port

Port of the Python abyss Hex-Rays post-processing framework (Dennis Elser,
"patois") to pure idax APIs. The port includes all 8 original filters:
`token_colorizer`, `signed_ops`, `hierarchy`, `lvars_alias`, `lvars_info`,
`item_sync`, `item_ctype`, and `item_index`.

The plugin demonstrates decompiler+UI event fanout (`on_func_printed`,
`on_maturity_changed`, `on_curpos_changed`, `on_create_hint`,
`on_refresh_pseudocode`, `on_populating_popup`, `on_rendering_info`,
`on_screen_ea_changed`), pseudocode tagged-line rewrites (`ida::lines`),
dynamic popup actions (`ida::ui::attach_dynamic_action`), and live
disassembly-to-pseudocode highlight overlays. It also demonstrates plugin-host
Hex-Rays ownership with `ida::decompiler::initialize()` and
`ScopedSession`.

Experimental filters (`item_ctype`, `item_index`, `item_sync`, `lvars_alias`,
`lvars_info`) start disabled by default and can be toggled from the pseudocode
popup under the `abyss/` submenu.

### `plugin/codedump_parity_probe_plugin.cpp` — ida-cdump Parity Probe

Compact reference plugin for the audited ida-cdump migration gaps. It keeps an
owned Hex-Rays `ScopedSession`, registers a pseudocode popup action, registers a
Local Types `type_ref` action, shows a typed `FormBuilder` dialog, uses
`WaitBox` progress, captures/restores local-variable settings while reapplying
the current prototype declaration, and publishes the resulting report through
the optional Qt clipboard helper with `ask_text` fallback.

### `plugin/driverbuddy_port_plugin.cpp` — DriverBuddy Port

Port of `<userhome>/Downloads/plo/DriverBuddy-master` to idax plugin, search,
analysis, type, xref, and instruction surfaces.

The plugin keeps DriverBuddy's core workflows:
- Detects `DriverEntry` and classifies drivers (WDM/WDF/Mini-Filter/AVStream/
  PortCls/Stream Minidriver) from imports.
- Scans for interesting C/WinAPI routines and reports caller xrefs.
- Locates WDM dispatch handlers (`DispatchDeviceControl`,
  `DispatchInternalDeviceControl`) and applies WDM-struct offset annotations.
- Decodes IOCTL constants both interactively (`Ctrl-Alt-I`) and from listing
  hits (`IoControlCode`).
- For WDF targets, builds/applies a `WDFFUNCTIONS` type over the dispatch table
  using idax type APIs (strict parity mode uses the full 440 historical slots).

### `plugin/intelligent_inliner_port_plugin.cpp` — Intelligent Function Inliner Port

Port of `<userhome>/Downloads/intelligent-function-inliner.py` to idax function,
graph, instruction, xref, type, progress-UI, action, and decompiler-cache APIs.
It preserves the original `<7`-instruction strict rule and score threshold/weights,
skips thunk/library/non-returning/variadic functions, detects processor-marked
memory writes, and sets `FUNC_OUTLINE` on selected functions. The SDK defines
this marker as “outlined code, not a real function”; the original uses it as its
inline-candidate signal, and the port does not rewrite binary code. The
interactive pass is cancellable and reports exact skip/change/failure counts.

The Rust adaptation (`intelligent_inliner_port`) provides the same analysis in
headless form. It reports without mutation by default; `--apply` sets the markers,
invalidates available decompiler caches, and saves the database. Example:

```bash
cargo run -p idax --example intelligent_inliner_port -- <idb> --show 20
cargo run -p idax --example intelligent_inliner_port -- <idb> --apply
```

### `plugin/magic_strings_port_plugin.cpp` — IDAMagicStrings Port

Port of `<userhome>/Downloads/plo/idamagicstrings-master/IDAMagicStrings.py`
to idax data, lines, name, xref, function, chooser, graph, and action APIs. It
preserves the original non-NLTK path: one-byte/two-byte string discovery,
source filename and language evidence, first-token candidate extraction,
blacklist and one-function rarity filtering, scoped class hierarchies, and
false-positive marking. Three actions separate analysis from confirmed
candidate and source-derived renames; proposed identifiers are sanitized and
only `sub_*` functions are changed.

The Rust adaptation (`magic_strings_port`) is report-only by default. Candidate
and source fallback mutations require separate explicit flags, and simultaneous
application gives a candidate priority over a source name for the same
function:

```bash
cargo run -p idax --example magic_strings_port -- <idb> --show 20
cargo run -p idax --example magic_strings_port -- <idb> --apply-candidates --apply-sources
```

### `plugin/auto_enum_port_plugin.cpp` — Auto Enum Port

Port of `<userhome>/Downloads/plo/auto-enum-main` to idax import, type,
instruction, decompiler, plugin-action, and refresh APIs. The global action
matches imported functions by normalized name, matches arguments by name with
positional fallback, creates named `ENUM_<id>` local enum types, and replaces
only eligible integral argument types while preserving the remaining function
prototype metadata. The local action starts from the decompiler call at the
cursor and applies selector-dependent enum display to the target operand.

The embedded corpus is a representative dependency-free Linux/Windows subset covering
file flags, address families/socket types, memory protection/mapping, `prctl`,
access modes, socket levels, and selected `socket`/`setsockopt`/`prctl`
specializations plus Windows `OpenProcess` access rights. The table-driven engine does not depend on Python or JSON and
does not claim coverage for omitted source-corpus entries.
The upstream MIT notice is retained in `plugin/auto_enum_port_LICENSE.txt`.

The Rust adaptation (`auto_enum_port`) covers the deterministic global workflow.
It reports without mutation by default; `--apply` creates the enum types,
applies revised imported prototypes, and saves the database:

```bash
cargo run -p idax --example auto_enum_port -- <idb> --show 20
cargo run -p idax --example auto_enum_port -- <idb> --apply
```

### `plugin/symless_structure_port_plugin.cpp` — Symless Structure Reconstruction Port

Bounded port of `<userhome>/Downloads/plo/symless-main` to the opaque owned
microcode graph and type APIs. The interactive plugin has separate report and
apply actions for one selected function argument, declarative allocator roots,
and verified constructor/vtable roots. It preserves register/stack
propagation, nested instruction evaluation, pointer add/sub, load/store width
recovery, topological predecessor-state preference, and the upstream
minimum-width overlap rule. It also follows resolved direct calls and exact
database-derived indirect targets with an explicit maximum depth, active-cycle
rejection, completed-context reuse, ABI argument injection, and conservative
terminal-return consensus. Plain immediates, call-info hints without database
provenance, runtime-only targets, and non-entry addresses remain unresolved.
Apply creates
or reuses a named UDT, changes eligible ordinary arguments/returns, and applies
exact shifted-parent/delta metadata to proven nonzero propagated argument
sites. Existing mismatched complex pointers remain unchanged; shifted returns
remain excluded as in upstream Symless. Exact same-name local structure
forwards are replaced at their existing ordinal with the recovered complete
definition; complete definitions and incompatible declarations are preserved.
For each exact type-compatible recovered field, apply also ensures persistent
user informational references from every unique access instruction to the
member's internal IDA identity. Report mode counts candidates without mutation;
apply reports candidate, added, reused, and skipped reference counts. Register
evidence from direct memory locations and pointer add/sub observations is mapped
to processor registers, grouped by `(instruction, register)`, and matched to a
phrase/displacement or register-preceded immediate machine operand. The first
source-ordered field in each group receives an exact opaque `[root, member]`
struct-offset path; additional fields remain represented by their member
references. Repeated apply verifies and reuses the copied root/member-name path.

Allocator mode accepts one specification per line: `malloc:<locator>:<size-index>`,
`realloc:<locator>:<size-index>`, or
`calloc:<locator>:<count-index>:<size-index>`. A locator is an exact
name/address or `module!import-prefix`. The bounded classifier verifies exact
direct calls plus database-derived fixed-pointer calls reached through one
exact data-slot reference hop, recognizes constants in `1..0x3fff`, confirms
forwarding wrappers only through terminal return of the originating call token,
recursively visits unique heirs, and reconstructs each fixed-size root as a
distinct UDT. Apply
keeps allocator/wrapper returns generic `void*` and types/names existing
size/count parameters as `size_t`; it does not synthesize parameters or assign
one allocation-specific type to a reusable allocator return.

Constructor/vtable mode scans bounded pointer-width function tables and accepts
a class root only when preoptimized microcode proves an exact table store into
argument zero at byte offset zero. Referenced non-first slots terminate a table,
all-import tables are excluded, multiple distinct zero-offset tables make the
constructor ambiguous, and nonzero stores remain reported secondary evidence.
Load discovery searches the function-array address first, then falls back to
the two-pointer Itanium RTTI label and recursively crosses only exact
pointer-valued data aliases. Every candidate still requires final table-value
store confirmation. Accepted non-import table members become deduplicated
argument-zero roots, so method-only fields join constructor evidence under the
same depth and conflict bounds. Apply creates semantic class/vftable UDTs,
applies the table type, and replaces only existing eligible generic `this`
arguments. It does not synthesize missing ABI parameters, resolve runtime
object dispatch, or rank inheritance by table size/xref counts.

This is not a full Symless parity claim: runtime-only or object-dependent
indirect dispatch and microcode-widget operand selection remain outside this
port. The upstream MIT notice is retained in
`plugin/symless_port_LICENSE.txt`.

The Rust adaptation (`symless_structure_port`) is report-only by default and
requires `--apply` before saving the UDT/prototype mutation:

```bash
cargo run -p idax --example symless_structure_port -- <idb> --function <address-or-name> --argument 0 --max-depth 8
cargo run -p idax --example symless_structure_port -- <idb> --function <address-or-name> --argument 0 --max-depth 8 --name recovered_type --apply
cargo run -p idax --example symless_structure_port -- <idb> --allocator malloc:_malloc:0 --max-depth 8
cargo run -p idax --example symless_structure_port -- <idb> --allocator malloc:_malloc:0 --name recovered_alloc --max-depth 8 --apply
cargo run -p idax --example symless_structure_port -- <idb> --vtables --name recovered --max-depth 8
cargo run -p idax --example symless_structure_port -- <idb> --vtables --name recovered --max-depth 8 --apply
```

### `plugin/lifter_port_plugin.cpp` — lifter Port Probe (Adapted Standalone Port)

Port probe of `<userhome>/dev/lifter` focused on plugin-shell workflows that
are currently portable through idax: action registration, pseudocode popup
attachment, decompiler pseudocode/microcode snapshot dumping, and
outlined-flag/cache-invalidation helpers.

The Rust adaptation (`lifter_headless_port`) extracts the non-UI analysis slice 
of the VMX/AVX lifter plugin (scanning all instructions, decoding them, and 
classifying them as supported VMX/AVX/SSE passthrough or K-register operations) 
into a headless reporting script, as microcode IR mutation requires decompiler filter callbacks.

It now installs a VMX + AVX scalar/packed microcode lifter subset through
`ida::decompiler::register_microcode_filter`, combining typed helper-call
lowering (`vzeroupper`, `vmxon/vmxoff/vmcall/vmlaunch/vmresume/vmptrld/vmptrst/vmclear/vmread/vmwrite/invept/invvpid/vmfunc`)
with typed microcode emission for scalar/packed AVX lowering
(`vaddps/vsubps/vmulps/vdivps`, `vaddpd/vsubpd/vmulpd/vdivpd`,
`vminps/vmaxps/vminpd/vmaxpd`, `vsqrtps/vsqrtpd`,
`vaddsubps/vaddsubpd`, `vhaddps/vhaddpd`, `vhsubps/vhsubpd`,
typed `vand*/vor*/vxor*`, `vpand*/vpor*/vpxor*` (with helper fallback for `*andn*` forms),
typed `vpadd*`/`vpsub*` integer add/sub direct forms (with helper fallback for memory-source/saturating variants),
typed `vpmulld`/`vpmullq` integer multiply direct forms (with helper fallback for `vpmullw`/`vpmuludq`/`vpmaddwd` variants),
(typed binary paths also accept two-operand encodings by treating destination as the implicit left source),
`vblend*/vpblend*`, `vshuf*/vperm*` helper-fallback families,
typed `vps*` shift forms with helper fallback for `vpror*`/`vprol*` and mixed variants,
`vcmp*`/`vpcmp*` compare helper-fallback families,
`vdpps`/`vround*`/`vrcp*`/`vrsqrt*`/`vget*`/`vfixup*`/`vscale*`/`vrange*`/`vreduce*`,
`vbroadcast*`/`vextract*`/`vinsert*`/`vunpck*`/`vmov*dup`/`vmaskmov*` helper-fallback families,
with mixed register/immediate/memory-source forwarding and compare mask-destination no-op tolerance,
`vcvtps2pd/vcvtpd2ps`, `vcvtdq2ps/vcvtudq2ps`, `vcvtdq2pd/vcvtudq2pd`,
`vcvt*2dq/udq/qq/uqq` (including truncating variants),
`vmovaps/vmovups/vmovapd/vmovupd`, `vmovdqa/vmovdqu` families,
`vaddss/vsubss/vmulss/vdivss`, `vaddsd/vsubsd/vmulsd/vdivsd`,
`vminss/vmaxss/vminsd/vmaxsd`, `vsqrtss/vsqrtsd`,
`vcvtss2sd`, `vcvtsd2ss`, `vmovss`, `vmovsd`).

Helper-call modeling in the probe also exercises richer typed non-scalar/write
semantics (register-pair/global-address/stack-variable/helper-reference values,
declaration-driven vector element typing, and advanced register-list/
visible-memory callinfo shaping).

It also prints a gap report for the currently missing APIs needed for a full
AVX/VMX microcode-lifter migration (rich microcode IR mutation surfaces and
raw decompiler-view handle context for advanced per-view manipulations).

### `plugin/idapcode_port_plugin.cpp` — idapcode Port (Adapted Standalone Port)

Port of `<userhome>/Downloads/plo/idapcode-main` to idax plugin/UI/database
surfaces with Sleigh-backed p-code generation.

The Rust adaptation (`idapcode_headless_port`) extracts the non-UI analysis slice 
of the plugin (determining Sleigh processor context and resolving `.sla` spec files) 
into a headless script, as the UI viewer logic is host-constrained.

The plugin uses `Ctrl-Alt-Shift-P` (chosen to avoid common `Ctrl-Alt-S`
conflicts with SigMaker setups) and opens a custom viewer for the current
function, rendering instruction headers plus lifted p-code ops. It also keeps
linear-view/custom-viewer navigation synchronized in both directions, including
cross-function follow when the linear cursor moves into a different function.
It uses idax wrappers for current-function lookup, byte extraction, custom
viewer hosting, and normalized architecture context (`ProcessorProfile` with
raw and optional verified identity, bitness, endianness, and optional ABI),
then resolves Sleigh specs via `sleigh::FindSpecFile`.

Build requires `IDAX_BUILD_EXAMPLE_IDAPCODE_PORT=ON`. Runtime spec resolution
uses Sleigh default search paths and can be overridden with
`IDAX_IDAPCODE_SPEC_ROOT`.

If the Sleigh submodule is not present, fetch it with:
`git submodule update --init --recursive third-party/sleigh`.

### `tools/idalib_dump_port.cpp` — idalib-dump Port (no Telegram)

Port of `<userhome>/dev/idalib-dump` `ida_dump` behavior to pure idax calls:
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

Port of `<userhome>/Downloads/plo/ida2py-main` static query workflows to pure
idax calls: user-defined symbol discovery, type apply/retrieve checks,
symbol-centric value/xref inspection, and decompiler-backed callsite text
listing. It also includes optional runtime `--appcall-smoke` coverage for
debugger-capable hosts (`ida::debugger::appcall`); use
`scripts/build_appcall_fixture.sh` to generate a host-native `ref4` fixture
before running smoke checks. The smoke launch path now probes both
`--wait` and default-argument startup variants for stronger diagnostics, and
includes an external spawn+attach fallback probe when direct debugger launch
fails.

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

To build the dedicated DrawIDA addon target (Qt plugin):

```bash
cmake --build build --target build_qt
cmake --build build --target idax_drawida_port_plugin
```

To build the idapcode port addon target (Sleigh-backed plugin):

```bash
cmake -S . -B build \
  -DIDAX_BUILD_EXAMPLES=ON \
  -DIDAX_BUILD_EXAMPLE_ADDONS=ON \
  -DIDAX_BUILD_EXAMPLE_IDAPCODE_PORT=ON \
  -DIDAX_IDAPCODE_BUILD_SPECS=ON
cmake --build build --target idax_idapcode_port_plugin
```

When a real IDA runtime is available (`IDADIR` or common macOS install path),
tool examples are linked against the real runtime dylibs. Otherwise they fall
back to SDK idalib stubs for compile-only environments.
