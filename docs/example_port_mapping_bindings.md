# Example Port Mapping (Source -> Rust/Node)

This matrix tracks how examples from `examples/` map into binding-level examples.

Legend:
- `Direct` - close functional equivalent
- `Adapted` - standalone/headless approximation (same concept, different host model)
- `N/A (host-constrained)` - requires IDA plugin/loader/procmod host entrypoint surface
- `Pending` - not ported yet

## Tool Examples

| Source | Rust | Node | Notes |
|---|---|---|---|
| `examples/tools/idalib_dump_port.cpp` | `bindings/rust/idax/examples/idalib_dump_port.rs` (`Direct`) | `bindings/node/examples/idalib_dump_port.ts` (`Direct`) | Headless tool flow supported in both bindings |
| `examples/tools/idalib_lumina_port.cpp` | `bindings/rust/idax/examples/idalib_lumina_port.rs` (`Direct`) | `bindings/node/examples/idalib_lumina_port.ts` (`Direct`) | Pull/push batch API exercised |
| `examples/tools/ida2py_port.cpp` | `bindings/rust/idax/examples/ida2py_port.rs` (`Adapted`) | `bindings/node/examples/ida2py_port.ts` (`Adapted`) | Appcall smoke remains host/debugger-dependent |

## Loader Examples

| Source | Rust | Node | Notes |
|---|---|---|---|
| `examples/loader/minimal_loader.cpp` | `bindings/rust/idax/examples/minimal_loader.rs` (`Adapted`) | `N/A (host-constrained)` | Node bindings target standalone idalib workflows |
| `examples/loader/advanced_loader.cpp` | `bindings/rust/idax/examples/advanced_loader.rs` (`Adapted`) | `N/A (host-constrained)` | XBIN plan/report adaptation |
| `examples/loader/jbc_full_loader.cpp` | `bindings/rust/idax/examples/jbc_full_loader.rs` (`Adapted`) | `N/A (host-constrained)` | Header/layout planning adaptation |

## Processor Module Examples

| Source | Rust | Node | Notes |
|---|---|---|---|
| `examples/procmod/minimal_procmod.cpp` | `bindings/rust/idax/examples/minimal_procmod.rs` (`Adapted`) | `N/A (host-constrained)` | Trait-level processor model demo |
| `examples/procmod/advanced_procmod.cpp` | `bindings/rust/idax/examples/advanced_procmod.rs` (`Adapted`) | `N/A (host-constrained)` | XRISC decode/render adaptation |
| `examples/procmod/jbc_full_procmod.cpp` | `bindings/rust/idax/examples/jbc_full_procmod.rs` (`Adapted`) | `N/A (host-constrained)` | JBC bytecode disasm adaptation |

## Plugin Examples

| Source | Rust | Node | Notes |
|---|---|---|---|
| `examples/plugin/action_plugin.cpp` | `bindings/rust/idax/examples/action_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | CLI-driven annotation actions instead of UI menu actions |
| `examples/plugin/abyss_port_plugin.cpp` | `bindings/rust/idax/examples/abyss_port_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | Headless decompiler post-process subset (token colorizer, item-index tag visualization, lvars preview, caller/callee hierarchy) |
| `examples/plugin/event_monitor_plugin.cpp` | `bindings/rust/idax/examples/event_monitor_plugin.rs` (`Adapted`) | `bindings/node/examples/change_tracker.ts` (`Adapted`) | Event + storage flow ported headlessly |
| `examples/plugin/decompiler_plugin.cpp` | `bindings/rust/idax/examples/decompiler_plugin.rs` (`Adapted`) | `bindings/node/examples/complexity_metrics.ts` (`Adapted`) | Complexity analysis workflow via decompiler |
| `examples/plugin/driverbuddy_port_plugin.cpp` | `bindings/rust/idax/examples/driverbuddy_port_plugin.rs` (`Adapted`) | `bindings/node/examples/binary_forensics.ts` (`Adapted`) | Headless driver fingerprinting/IOCTL scan subset |
| `examples/plugin/ida_names_port_plugin.cpp` | `bindings/rust/idax/examples/ida_names_port_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | Headless title-derivation report (demangled-short fallback to raw) |
| `examples/plugin/intelligent_inliner_port_plugin.cpp` | `bindings/rust/idax/examples/intelligent_inliner_port.rs` (`Adapted`) | `N/A (plugin host-constrained)` | Exact scoring report; explicit `--apply` persists `FUNC_OUTLINE` markers |
| `examples/plugin/magic_strings_port_plugin.cpp` | `bindings/rust/idax/examples/magic_strings_port.rs` (`Adapted`) | `N/A (plugin host-constrained)` | Complete no-NLTK analysis; explicit candidate/source apply flags persist sanitized names |
| `examples/plugin/auto_enum_port_plugin.cpp` | `bindings/rust/idax/examples/auto_enum_port.rs` (`Adapted`) | `N/A (plugin host-constrained)` | Global import-prototype report/apply is headless; cursor-selected selector annotation remains in the interactive C++ action |
| `examples/plugin/symless_structure_port_plugin.cpp` | `bindings/rust/idax/examples/symless_structure_port.rs` (`Adapted`) | `N/A (plugin host-constrained)` | Same depth-bounded direct-call engine plus declarative allocator roots, exact argument-zero constructor/vtable roots, exact shifted propagated arguments, ordinal-preserving local structure-forward replacement, persistent informational references, and source-ordered exact operand struct-offset paths for recovered members; report is non-mutating, apply is explicit, ambiguous inheritance remains report-only, and no full Symless parity is claimed |
| `examples/plugin/qtform_renderer_plugin.cpp` | `bindings/rust/idax/examples/qtform_renderer_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | Headless parser/report for form-declaration markup; plugin-host "Test in ask_form" uses idax markup-only `ask_form` |
| `examples/plugin/storage_metadata_plugin.cpp` | `bindings/rust/idax/examples/storage_metadata_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | Fingerprint collection + netnode persistence |
| `examples/plugin/deep_analysis_plugin.cpp` | `bindings/rust/idax/examples/deep_analysis_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | Security-oriented audit report adaptation |
| `examples/plugin/*` (GUI-heavy variants) | `Pending` | `Mostly N/A (host-constrained)` | Custom widgets/docked UI remain host/plugin-centric |

## Current focus

- Keep Node additions centered on standalone idalib tooling workflows.
- Continue Rust adapted ports where semantics are meaningful without plugin export macros.

## Runtime Validation Snapshot (2026-02-25)

| Example | Result | Evidence |
|---|---|---|
| `bindings/node/examples/idalib_dump_port.ts` | Pass | `npx tsx ... --list` produced full function table + summary |
| `bindings/node/examples/ida2py_port.ts` | Pass | `npx tsx ... --list-user-symbols --max-symbols 5` produced symbol/type rows |
| `bindings/node/examples/idalib_lumina_port.ts` | Pass | `npx tsx ...` produced pull/push success counts |
| `bindings/rust/idax/examples/minimal_procmod.rs` | Pass | `cargo run -p idax --example minimal_procmod -- 0x90` |
| `bindings/rust/idax/examples/advanced_procmod.rs` | Pass | `cargo run -p idax --example advanced_procmod -- 0x31230004 0xC0000010` |
| `bindings/rust/idax/examples/action_plugin.rs` | Pass | `cargo run -p idax --example action_plugin -- <idb> add-bookmark 0x530 --label phase19` |
| `bindings/rust/idax/examples/abyss_port_plugin.rs` | Pass | `cargo run -p idax --example abyss_port_plugin -- <idb> --function main --hier-depth 2 --max-lines 80 --item-index` |
| `bindings/rust/idax/examples/event_monitor_plugin.rs` | Pass | `cargo run -p idax --example event_monitor_plugin -- <idb>` |
| `bindings/rust/idax/examples/decompiler_plugin.rs` | Pass | `cargo run -p idax --example decompiler_plugin -- <idb> --top 5` |
| `bindings/rust/idax/examples/driverbuddy_port_plugin.rs` | Pass | `cargo run -p idax --example driverbuddy_port_plugin -- <idb> --top 10 --max-scan 5000` |
| `bindings/rust/idax/examples/storage_metadata_plugin.rs` | Pass | `cargo run -p idax --example storage_metadata_plugin -- <idb>` |
| `bindings/rust/idax/examples/deep_analysis_plugin.rs` | Pass | `cargo run -p idax --example deep_analysis_plugin -- <idb> --max-scan 1000` |
| `bindings/rust/idax/examples/ida_names_port_plugin.rs` | Pass | `cargo run -p idax --example ida_names_port_plugin -- <idb> --limit 5` |
| `bindings/rust/idax/examples/intelligent_inliner_port.rs` | Pass | `cargo run -p idax --example intelligent_inliner_port -- <idb> --show 5`; isolated-copy `--apply` changed 5/5 candidates and reopen observed 5/5 already outlined |
| `bindings/rust/idax/examples/magic_strings_port.rs` | Pass | Isolated stripped Mach-O: report found 1 candidate without mutation; `--apply-candidates` renamed 1/1 with zero failures; reopen retained `uniqueHandler` |
| `bindings/rust/idax/examples/auto_enum_port.rs` | Pass | Disposable host-native fixture: report found 6 imports/8 arguments without mutation; `--apply` changed 6/8 with zero failures; reopen observed all 8 as enum-typed |
| `bindings/rust/idax/examples/symless_structure_port.rs` | Pass | Argument fixture: exact intraprocedural/interprocedural fields and idempotent prototype apply. Shifted fixture: root `0 B` plus callee `+8 B`, one shifted argument changed then recognized on reopen. Forward/member-reference fixture: one DWARF structure forward, exact +4/4 B, +8/8 B, +24/1 B fields/sites, one ordinal-preserving replacement/three members/three persistent member references on first apply, and zero replacement/addition with three members/references reused after fresh-process reopen. Allocator fixture: one malloc wrapper/root with exact bounded fields. Constructor fixture: one three-method table/root, exact +8/4 B, +16/8 B, +24/1 B fields, two semantic UDTs/seven members/four prototypes, and zero-change reopen |
| `bindings/rust/idax/examples/qtform_renderer_plugin.rs` | Pass | `cargo run -p idax --example qtform_renderer_plugin -- --sample --ask-form-test` |
| `bindings/rust/idax/examples/jbc_full_loader.rs` | Pass | Synthetic `.jbc` fixture generated at runtime (`/tmp/idax_phase19_sample.jbc`); header/plan output validated |
| `bindings/rust/idax/examples/jbc_full_procmod.rs` | Pass | Synthetic `.jbc` fixture generated at runtime; code-section decode path validated (`pushi/loads/call/jmp/ret`) |
