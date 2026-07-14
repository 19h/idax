# Example Port Gap Audit (Consolidated)

Date: 2026-07-14

This is the single status document for maintained real-world example ports.
Detailed historical churn was intentionally removed to keep the audit concise.

## Status at a glance

| Port | Artifact(s) | Status | Remaining gaps |
|---|---|---|---|
| ida-qtform + idalib-dump (no Telegram) | `examples/plugin/qtform_renderer_plugin.cpp`, `examples/plugin/qtform_renderer_widget.cpp`, `examples/tools/idalib_dump_port.cpp`, `examples/tools/idalib_lumina_port.cpp` | closed | None for audited non-Telegram workflows |
| ida2py | `examples/tools/ida2py_port.cpp` | closed | None for audited probe workflows |
| DrawIDA | `examples/plugin/drawida_port_plugin.cpp`, `examples/plugin/drawida_port_widget.cpp` | closed | None |
| IDA-names | `examples/plugin/ida_names_port_plugin.cpp`, `examples/plugin/ida_names_port_widget.cpp` | closed | None; widget title mutation intentionally crosses the explicit opaque-host Qt bridge because the SDK has no `set_widget_title` API |
| abyss | `examples/plugin/abyss_port_plugin.cpp` | closed | Non-blocking delta: `lvars_info`/`lvars_alias` remain advisory (no in-place rename during maturity callbacks) |
| DriverBuddy | `examples/plugin/driverbuddy_port_plugin.cpp` | closed | None; menu action and scoped one-call hotkey lifecycles are modeled separately |
| idapcode | `examples/plugin/idapcode_port_plugin.cpp`, `bindings/rust/idax/examples/idapcode_headless_port.rs` | closed | None for audited wrapper scope; Sleigh remains an explicit external runtime and language-selection policy |
| lifter | `examples/plugin/lifter_port_plugin.cpp` | closed | None for audited lifter-class migration scope |
| Intelligent Function Inliner | `examples/plugin/intelligent_inliner_port_plugin.cpp`, `bindings/rust/idax/examples/intelligent_inliner_port.rs` | closed | None; Phase 34 preserves processor-reported operand access modes through Node and Rust |
| IDAMagicStrings | `examples/plugin/magic_strings_port_plugin.cpp`, `bindings/rust/idax/examples/magic_strings_port.rs` | closed | None for the original non-NLTK workflow; Phase 35 adds copied string-list/source metadata and safe Rust full-name inventory |
| Auto Enum | `examples/plugin/auto_enum_port_plugin.cpp`, `bindings/rust/idax/examples/auto_enum_port.rs` | closed | None for the audited wrapper scope; Phase 36 adds metadata-preserving argument edits and opaque named operand-enum apply/readback. The embedded corpus is representative rather than exhaustive |
| Symless | `examples/plugin/symless_structure_port_plugin.cpp`, `bindings/rust/idax/examples/symless_structure_port.rs` | bounded/closed | None for depth-bounded resolved direct and database-derived indirect-call argument/return propagation, declarative allocator/wrapper/fixed-root discovery including fixed-pointer wrappers, exact argument-zero constructor/vtable roots, direct-first/two-pointer-RTTI/data-alias table reachability, statically seeded non-import virtual methods, exact shifted propagated arguments, ordinal-preserving local structure-forward replacement, persistent informational references to exact recovered members, or source-ordered exact operand struct-offset paths. Full upstream parity additionally requires runtime-only/object-dependent indirect dispatch and a microcode-widget picker |

## Notes

- DriverBuddy registers its menu-visible decode action separately from the
  move-only shortcut-only `ScopedHotkey`, preserving both discoverability and
  deterministic teardown.
- idapcode consumes `ProcessorProfile`, preserving unknown raw processor IDs
  while using optional verified `ProcessorId` values for Sleigh routing.
- idapcode remains opt-in via `IDAX_BUILD_EXAMPLE_IDAPCODE_PORT=ON`; optional spec build remains `IDAX_IDAPCODE_BUILD_SPECS=ON`.
- IDA-names no longer maintains a cached current-widget handle or approximates
  `hxe_switch_pseudocode` with screen-address/refresh events.
- lifter write-path closure is complete for audited workflows (filter hooks, typed emission, helper-call shaping, popup/view helpers).
- Intelligent Function Inliner preserves the original scoring constants and
  `FUNC_OUTLINE` mutation semantics; its Rust command is report-only unless
  `--apply` is specified.
- IDAMagicStrings preserves source-path/language detection, first-token and
  blacklist filtering, one-function rarity, scoped-class evidence, and
  confirmed rename modes without adding Python, NLTK, or Qt dependencies to
  the core wrapper.
- Auto Enum preserves global prototype enrichment and interactive
  selector-dependent operand annotation without exposing native type IDs. The
  Rust adaptation covers the deterministic global pass; selected-call cursor
  state remains an interactive C++ host concern.
- The Symless adaptation preserves the source-audited CPU-state and field
  conflict rules for one function argument over owned preoptimized microcode
  graphs. It follows resolved direct calls and exact database-derived indirect
  targets with an explicit depth bound, context-cycle/repetition guards, ABI
  argument injection, and terminal-return consensus. Plain integers and
  runtime/object-dependent targets remain unresolved. Declarative allocator
  mode adds exact direct-call verification plus one bounded fixed-slot reference
  hop, bounded malloc/calloc/realloc constants, terminal call-token wrapper
  confirmation, cycle-safe heir traversal, and call-site-specific UDTs. Report
  mode is non-mutating. Proven nonzero argument shifts use copied exact
  parent/delta metadata; shifted returns and mismatched complex pointers remain
  excluded. Exact same-name local structure forwards are replaced at their
  existing ordinal with a copied complete definition; complete definitions and
  incompatible declarations are preserved. Each exact compatible recovered
  field receives a persistent user informational reference from every unique
  access item head; the member identity remains internal, and apply reports
  candidate/added/reused/skipped counts. Register-backed pointer-arithmetic and
  memory-access observations select one source-ordered machine operand per
  `(instruction, processor register)` group and apply a verified opaque
  root/member path; later fields retain member references. Constructor/vtable
  mode searches direct table references first, falls back to a two-pointer RTTI
  label, recursively crosses only exact pointer-valued data aliases, and still
  requires an exact final table store into argument zero. Each accepted
  non-import method is a deduplicated argument-zero field-propagation root.
  Mutation requires the C++ apply action or Rust `--apply`. Runtime-only object
  dispatch and the microcode-widget picker remain explicitly separate rather
  than being approximated.
- This file replaces the previous per-port gap audit documents.
