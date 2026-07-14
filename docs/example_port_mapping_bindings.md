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
| `examples/plugin/diaphora_exact_port_plugin.cpp` | `bindings/rust/idax/examples/diaphora_exact_port.rs` (`Direct`) | `N/A (plugin host-constrained)` | Byte-compatible function, instruction-metadata, and semantic pseudocode-comment manifests; deterministic exact comparison; absent-only conservative apply |
| `examples/plugin/symless_structure_port_plugin.cpp` | `bindings/rust/idax/examples/symless_structure_port.rs` (`Adapted`) | `N/A (plugin host-constrained)` | Same depth-bounded direct/database-derived indirect-call engine, allocator roots, exact constructor/vtable and RTTI/data-alias reachability, static virtual-method roots, shifted arguments, forward replacement, persistent references, exact operand paths, and explicit register/stack microcode-root selection. C++ uses a modal chooser; Rust lists/selects deterministic candidate indices. Report is non-mutating and apply is explicit |
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
| `bindings/rust/idax/examples/diaphora_exact_port.rs` | Pass | IDA 9.4 fixture: function layer retained two byte-identical 22-record exports and 22/22 strongest-tier self matches; instruction layer emitted two byte-identical 9-record/22-function manifests, matched all 9 records, applied 1 ordinary comment + 1 repeatable comment + 1 forced operand while preserving 8 existing values, changed zero after fresh reopen while preserving 11, and reproduced the source manifest byte-for-byte; pseudocode-comment layer retained two locations at one instruction, applied 2 then 0 after reopen, reproduced SHA-256 `5e8a42dc99e28d57f6b7843d29292ce39c9ed8b387fa6d517ddfa93cb030ba23`, rejected one altered guard, and preserved one target-owned conflict |
| `bindings/rust/idax/examples/symless_structure_port.rs` | Pass | Argument fixture: exact intraprocedural/interprocedural fields and idempotent prototype apply. Indirect fixture: one database-resolved ordinary call plus one fixed-pointer malloc wrapper/root and zero-addition reopen. Shifted and forward fixtures preserve exact metadata and ordinals. Direct/RTTI vtable fixtures preserve constructor and static method roots. Microcode-root fixture lists 18 readable candidates, injects candidate zero exactly once before `0x100000460.0`, recovers four exact fields, adds four members/references/paths, and reuses all four after fresh-process reopen |
| `bindings/rust/idax/examples/qtform_renderer_plugin.rs` | Pass | `cargo run -p idax --example qtform_renderer_plugin -- --sample --ask-form-test` |
| `bindings/rust/idax/examples/jbc_full_loader.rs` | Pass | Synthetic `.jbc` fixture generated at runtime (`/tmp/idax_phase19_sample.jbc`); header/plan output validated |
| `bindings/rust/idax/examples/jbc_full_procmod.rs` | Pass | Synthetic `.jbc` fixture generated at runtime; code-section decode path validated (`pushi/loads/call/jmp/ret`) |
