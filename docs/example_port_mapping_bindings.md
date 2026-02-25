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
| `examples/plugin/event_monitor_plugin.cpp` | `bindings/rust/idax/examples/event_monitor_plugin.rs` (`Adapted`) | `bindings/node/examples/change_tracker.ts` (`Adapted`) | Event + storage flow ported headlessly |
| `examples/plugin/decompiler_plugin.cpp` | `bindings/rust/idax/examples/decompiler_plugin.rs` (`Adapted`) | `bindings/node/examples/complexity_metrics.ts` (`Adapted`) | Complexity analysis workflow via decompiler |
| `examples/plugin/storage_metadata_plugin.cpp` | `bindings/rust/idax/examples/storage_metadata_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | Fingerprint collection + netnode persistence |
| `examples/plugin/deep_analysis_plugin.cpp` | `bindings/rust/idax/examples/deep_analysis_plugin.rs` (`Adapted`) | `N/A (host-constrained)` | Security-oriented audit report adaptation |
| `examples/plugin/*` (GUI-heavy variants) | `Pending` | `Mostly N/A (host-constrained)` | Custom widgets/docked UI remain host/plugin-centric |

## Current focus

- Keep Node additions centered on standalone idalib tooling workflows.
- Continue Rust adapted ports where semantics are meaningful without plugin export macros.
