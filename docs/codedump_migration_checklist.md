# ida-cdump migration checklist

This checklist maps the updated
`<userhome>/dev/ida-cdump/docs/IDAX_GAPS.md` notes to concrete idax APIs and
remaining implementation work. It is intentionally source-oriented: each row
names the SDK shape `ida-cdump` uses today, the idax replacement, binding
coverage, and any residual caveat before the plugin can remove that direct SDK
use.

## Dialog Shape Inventory

The current `ida-cdump` dialogs use a small fixed set of true-vararg
`ask_form(...)` signatures. idax's C++ typed form API can cover these with a
compile-time pointer pack; binding APIs must not attempt to synthesize a
runtime `va_list`.

| ida-cdump call site | SDK binding signature | idax C++ shape |
| --- | --- | --- |
| `show_dump_dialog` | `sval_t*`, `sval_t*`, `sval_t*`, `char[QMAXPATH]`, `ushort*`, `ushort*` | `form_sval`, `form_sval`, `form_sval`, `form_path`, `form_bitset`, `form_bitset` |
| `show_type_dump_dialog` | `sval_t*`, `char[QMAXPATH]`, `ushort*` | `form_sval`, `form_path`, `form_bitset` |
| `do_copy_type` recursive dialog | `sval_t*`, `ushort*` | `form_sval`, `form_bitset` |
| `do_type_graph` | `ushort*`, `sval_t*`, `char[QMAXPATH]`, `ushort*` | `form_radio`, `form_sval`, `form_path`, `form_bitset` |
| `do_export_metadata` | `sval_t*`, `char[QMAXPATH]`, `ushort*` | `form_sval`, `form_path`, `form_bitset` |
| `do_apply_metadata` | `char[QMAXPATH]`, `ushort*` | `form_path`, `form_bitset` |

## Gap Map

| Gap note section | Current direct SDK use in ida-cdump | idax replacement | Status | Binding status | Residual task |
| --- | --- | --- | --- | --- | --- |
| Typed `ask_form()` | Dialogs pass raw `sval_t*`, `ushort*`, `char[QMAXPATH]` to `ask_form` | `ida::ui::ask_form(markup, bindings...)`, `form_*` factories, `FormBuilder` | C++ implemented | Fixed-shape Node/Rust entrypoints implemented for audited dialog shapes | Run host-gated modal scenario on an interactive IDA host |
| Wait box | Local `WaitBoxGuard`, `show_wait_box`, `replace_wait_box`, `hide_wait_box`, `user_cancelled` | `ida::ui::WaitBox`, `Progress`, `ProgressFn` | Implemented | Node/Rust wait-box wrappers implemented; runtime remains host-UI gated | No idax task remains |
| Hex-Rays popup event | `install_hexrays_callback(... hxe_populating_popup ...)` | `ida::decompiler::on_populating_popup` | Implemented | Node/Rust callback wrappers implemented | No idax task remains |
| Local Types `type_ref` | Raw `action_handler_t` reads `ctx->type_ref` | `ida::plugin::ActionContext::type_ref` | Implemented | Rust safe/FFI coverage implemented; Node has no plugin/action namespace, so no Node action-context binding applies | No idax task remains |
| Clipboard | Shells out through `common/clipboard.cpp` | Optional Qt `ida::ui::copy_to_clipboard`, `read_clipboard`, `clipboard_backend` | Implemented behind `IDAX_ENABLE_QT_CLIPBOARD`; Qt headers are isolated in a bridge TU | Node/Rust wrappers implemented | Configure with an IDA-compatible `QT_NAMESPACE=QT` Qt package, then run host-gated Qt write/read/restore on a Qt-enabled IDA host |
| Bulk lvar settings/prototype export/apply | `get_tinfo` for recursive type dependencies only; lvar locator export/apply and prototype export/apply have been migrated | `LvarSnapshot`, `LocalVariableUserSetting`, `saved_user_lvar_settings`, `apply_user_lvar_setting`, `function::declaration`, `function::apply_decl`, `set_prototype` | Implemented for current ida-cdump lvar/prototype flows | Node/Rust wrappers implemented for opaque snapshots; serializable lvar settings are C++ only until a binding caller needs them | No idax lvar/prototype task remains |
| Read-only ctree analysis | Type collection still uses direct `ctree_visitor_t`, `cexpr_t`, and `cfunc_t`; provenance analysis has migrated | `ExpressionView`, `StatementView`, parent snapshots, helper/type/member/size accessors, `LocalVariable::index`, `variable(index)`; residual collection facade needs P22.R3 for type collection | Partially implemented | Node/Rust callback payloads implemented | Extend C++ read-only snapshots or add a dedicated collection facade before `type_collector.cpp` and plugin type collection can remove `cfunc_t`/`cexpr_t` |
| `get_path(PATH_TYPE_IDB)` | Fallback in `default_dump_dir()` | `ida::database::idb_path()` | Implemented | Node/Rust database wrappers implemented | No idax task remains |
| `qbasename` / `qdirname` / `qisdir` | Path cleanup and output display | `ida::path::{basename, dirname, is_directory}` plus `<filesystem>` | Implemented | Node/Rust path wrappers implemented and locally validated | No idax task remains |
| `ask_text` | Clipboard fallback text dialog | `ida::ui::ask_text` | Implemented | Node/Rust wrappers implemented; runtime remains host-modal | No idax task remains |
| Hex-Rays init/term | Direct `init_hexrays_plugin` / `term_hexrays_plugin` in plugin lifecycle | `ida::decompiler::initialize()` returning `ScopedSession` | Implemented with example lifecycle and host-runtime coverage | Node/Rust owned scoped-session wrappers implemented; runtime remains Hex-Rays-host gated | No idax task remains |
| Bulk local type declarations | `parse_decls(nullptr, blob, nullptr, HTI_DCL)` in metadata apply | `ida::type::parse_declarations(...)` | Implemented | Node/Rust wrappers implemented and locally compile-validated | No idax task remains |
| Lower-level transfer/analysis helpers | `get_tinfo`, `decompile`, `cfunc_t`, `cexpr_t` for recursive type and ctree collection | Existing wrappers cover simple function, instruction, comment, name, type, xref, segment, address, data-read, mnemonic, switch-table, register operand read/write, and lvar locator call sites; residual exact needs map to P22.R2-P22.R3 | Partially covered by idax | Existing namespace bindings apply where exposed | Implement residual C++ APIs before the remaining raw type/ctree call sites can be removed |
| Already-corrected items | `generate_disasm_line`, `get_input_file_path`, `PLUGIN_HIDE` | `instruction::text`, `database::input_file_path`, `ExportFlags::hidden` | Already covered | Existing coverage | No task |
| UI diagnostic formatting comfort | `info(...)` / `warning(...)` can accept printf-style formatting in the SDK | `ida::ui::info(std::string_view)` / `warning(std::string_view)` with caller-side formatting | Existing API is sufficient for current ida-cdump because messages are already preformatted | No binding-specific task | No parity task; revisit only if idax-owned formatting overloads become useful for a concrete port |
| Future/non-blocking | Hex-Rays `user_cmts`, mutable ctree, broader microcode | No current `ida-cdump` dependency | Out of scope for this parity pass | Out of scope | Track only if ida-cdump grows that feature |

## Evidence Map

This map ties each gap row to the idax-side proof that the replacement is
implemented, intentionally host-gated, or still represented by a residual API
task.

| Gap note section | Current proof | Binding proof | Host/runtime proof still needed |
| --- | --- | --- | --- |
| Typed `ask_form()` | C++ API surface and adapter coverage in `tests/unit/api_surface_parity_test.cpp` and `tests/unit/core_unit_test.cpp`; host gate path in `tests/integration/codedump_parity_host_gates_test.cpp`; parity example in `examples/plugin/codedump_parity_probe_plugin.cpp` | Node fixed-form validation in `bindings/node/test/unit.test.js`; Rust `ui_tests::test_codedump_typed_forms_reject_empty_markup_without_modal_ui` plus signature/result-shape coverage | `IDAX_RUN_MODAL_FORMS=1` in an interactive IDA UI host |
| Wait box | API surface coverage and `codedump_parity_probe_plugin.cpp` usage | Node `ui.WaitBox` constructor/prototype coverage; Rust `ui_tests` wrapper coverage | Optional UI-host runtime only; no idax implementation task remains |
| Hex-Rays popup event | C++ decompiler event surface coverage and `examples/plugin/abyss_port_plugin.cpp` popup attachment | Node `onPopulatingPopup` argument validation; Rust `decompiler_tests::test_populating_popup_event_defaults` checks event payload and callback signature | None |
| Local Types `type_ref` | C++ action-context snapshot coverage for `ActionContext::type_ref` | Rust safe `TypeRef` construction plus `plugin::tests::action_context_type_ref_is_exposed_in_ffi_shape`; Node plugin/action binding is not part of the current binding surface | None |
| Clipboard | Default unsupported contract in `codedump_parity_host_gates`; Qt namespace configure guard in `CMakeLists.txt`; bridge implementation in `src/detail/qt_clipboard_bridge.*` | Node default unsupported validation; Rust `ui_tests::test_clipboard_default_contract_and_validation` covers wrapper validation and unsupported-backend mapping | `IDAX_RUN_QT_CLIPBOARD=1` in an IDA Qt host after configuring with an IDA-compatible `QT_NAMESPACE=QT` Qt package |
| Bulk lvar/prototype metadata | C++ API surface coverage for serializable `LocalVariableUserSetting`; ida-cdump metadata export/apply build proves lvar locator migration; decompiler storage hardening and type round-trip integration cover opaque snapshots and prototype apply | Node fixture integration checks decompiled-function metadata/snapshot method surfaces; Rust `function_tests::test_prototype_apply_function_signatures` and `decompiler_tests::test_lvar_snapshot_and_comment_function_signatures` cover safe signatures | None for current ida-cdump C++ parity |
| Read-only ctree analysis | Decompiler storage hardening coverage for helper/type/parent/local-variable-index helpers | Node fixture integration inspects expression/item callback payload fields and stable local-variable lookup; Rust `decompiler_tests::test_ctree_callback_payload_shapes` covers callback payload structs and signatures | P22.R3 for current ida-cdump analyzer/type-collector parity |
| `get_path(PATH_TYPE_IDB)` | Database wrapper coverage in smoke/integration paths | Node/Rust database wrappers | None |
| `qbasename` / `qdirname` / `qisdir` | Pure path helper coverage in `tests/unit/core_unit_test.cpp` | Node path unit tests and Rust path tests | None |
| `ask_text` | UI API surface and host-modal contract | Node `askText` argument validation and Rust `ui_tests` signatures | Host-modal runtime is optional; no idax implementation task remains |
| Hex-Rays init/term | `codedump_parity_host_gates` passes with `IDAX_RUN_HEXRAYS_SESSION=1`; `abyss_port_plugin` owns a scoped session | Node/Rust owned scoped-session wrappers | None |
| Bulk local type declarations | Type round-trip / parse-declarations integration coverage | Node unit validation for `type.parseDeclarations`; Rust `types_tests::test_parse_declarations_function_signature_and_report` plus fixture `types_parse_declarations` integration coverage | None |
| Lower-level transfer/analysis helpers | Function/comment/name/instruction/type/graph/decompiler-lvar/type-rendering/popup integration and smoke coverage across existing suites | Existing Node/Rust namespace coverage where those APIs are bound; C++ ida-cdump uses the wrappers directly for current parity flows | None for current ida-cdump parity |
| Already-corrected items | API surface and smoke coverage for existing replacements | Existing bindings where those namespaces are exposed | None |
| UI diagnostic formatting comfort | Existing `ida::ui::info` / `warning` string-view APIs; callers can use `std::format` or equivalent before calling idax | Existing binding callers pass final strings | None |
| Future/non-blocking | Explicitly marked outside this parity pass in the updated gap notes and the task tracker | Not scheduled | Only revisit if ida-cdump starts depending on Hex-Rays positioned comments, mutable ctree, or broader microcode mutation |

## Remaining idax Tasks

These tasks are the concrete queue after reconciling the updated gap notes and
the follow-up ida-cdump port audit with the current idax Phase 22
implementation.

| ID | Task | Primary files | Exit condition |
| --- | --- | --- | --- |
| P22.R1 processor operand access metadata | Expose operand read/write/change/use classification, canonical register display, operand size, and instruction feature bits without raw `insn_t`/`op_t` | `include/ida/instruction.hpp`, `src/instruction.cpp`, API surface test | Complete; `analysis/register_analyzer.cpp` stopped using `decode_insn`, `get_canon_feature`, `has_cf_use`, `has_cf_chg`, `get_dtype_size`, and `get_reg_name` |
| P22.R2 type dependency traversal | Add declaration rendering, ordinal dependency ordering, used-member trimming, size comments, type graph rendering, and ordinal declaration snapshots without raw `tinfo_t` at ida-cdump call sites | `include/ida/type.hpp`, `src/type.cpp`, API surface test | Complete; ida-cdump removed local `type_formatter` / `type_graph_dot` and no longer uses raw `typeinf.hpp` for type rendering/metadata export |
| P22.R3 ctree/type collection facade | Add read-only expression helpers plus `ida::decompiler::collect_referenced_types(Address)` for type ordinals and used member offsets | `include/ida/decompiler.hpp`, `src/decompiler.cpp`, API surface test | Complete for current ida-cdump parity; `ctree_analyzer.cpp` and `type_collector.cpp` no longer consume raw `cfunc_t` / `cexpr_t` |
| P22.R4 serializable lvar locator metadata | Add enumerable/applicable local-variable user settings with stable locator fields, name/type/comment payloads, and per-lvar declaration parsing | `include/ida/decompiler.hpp`, `src/decompiler.cpp`, API surface test | Complete; metadata export/apply no longer needs `lvar_uservec_t`, `lvar_saved_info_t`, `restore_user_lvar_settings`, `modify_user_lvar_info`, or direct `parse_decl` |
| P22.R5 graph recovery switch metadata | Add switch/jump-table descriptors needed by graph recovery | `include/ida/graph.hpp`, `src/graph.cpp`, API surface test | Complete; `graph_builder.cpp` uses `ida::graph::switch_table` |
| P22.R6 popup attachment for registered actions | Attach already-registered actions to a currently-building popup while preserving normal action context payloads such as Local Types `type_ref` | `include/ida/ui.hpp`, `src/ui.cpp`, API surface test | Complete; `codedump_plugin.cpp` uses `ida::ui::on_popup_ready` and `attach_registered_action` instead of a raw `HT_UI` listener |
| P22.H1 modal typed-form evidence | Run `codedump_parity_host_gates` with `IDAX_RUN_MODAL_FORMS=1` on an interactive IDA UI host | `tests/integration/codedump_parity_host_gates_test.cpp`, `docs/validation_report.md` | Local default run proves deterministic skip behavior; modal form proof remains interactive UI gated |
| P22.H2 Qt clipboard evidence | Configure with `IDAX_ENABLE_QT_CLIPBOARD=ON` and an IDA-compatible `QT_NAMESPACE=QT` Qt package, then run `codedump_parity_host_gates` with `IDAX_RUN_QT_CLIPBOARD=1` on an IDA Qt host | `CMakeLists.txt`, `src/detail/qt_clipboard_bridge.*`, `tests/integration/codedump_parity_host_gates_test.cpp`, `docs/validation_report.md` | Default unsupported behavior is proven locally; Qt clipboard write/read/restore proof remains interactive Qt-host gated |
| P22.V1 final validation refresh | Run focused C++/example/Node/Rust validation and record blockers separately from implementation tasks | CMake, compact parity probe example, Node, Rust test targets; `docs/validation_report.md`; `.agents/*` | Latest local refresh passes across focused C++, compact parity probe example build, Node native unit/integration, Rust no-run, and non-modal Rust typed-form validation; rerun after host-only evidence is collected |

Concrete closure subtasks:

- P22.H1.1: run the modal host gate with
  `IDAX_RUN_MODAL_FORMS=1 IDAX_EVIDENCE_LOG=logs/codedump-modal-forms.log`
  inside an interactive IDA UI session.
- P22.H1.2: accept the opened codedump-shaped typed form. A cancellation is a
  failed evidence run, not a skip.
- P22.H1.3: verify the log with
  `scripts/check_codedump_parity_evidence_log.sh logs/codedump-modal-forms.log modal`
  and record the result in `docs/validation_report.md`.
- P22.H2.1: supply an IDA-compatible namespaced Qt package through
  `IDAX_QT6_DIR`; plain system Qt packages are intentionally rejected.
- P22.H2.2: run the Qt clipboard host gate with
  `IDAX_ENABLE_QT_CLIPBOARD=ON`, `IDAX_RUN_QT_CLIPBOARD=1`, and
  `IDAX_EVIDENCE_LOG=logs/codedump-qt-clipboard.log`.
- P22.H2.3: verify the log with
  `scripts/check_codedump_parity_evidence_log.sh logs/codedump-qt-clipboard.log qt-clipboard`
  and record the backend plus write/read/restore result in
  `docs/validation_report.md`.
- P22.V1.1: rerun `scripts/run_codedump_parity_local_validation.sh
  build-test-fetch RelWithDebInfo` after host evidence is collected; include
  Node fixture integration when `IDADIR` is available.
- P22.V1.2: close Phase 22 only after the validation report, active work file,
  and progress ledger distinguish verified idax parity from downstream
  ida-cdump migration cleanup.

## Existing-API Migration Cleanup

These ida-cdump call sites can move off raw SDK calls without new idax work
only where the caller needs the listed simple metadata. The residual P22.R*
tasks cover the call sites that need data not yet represented by idax.

| SDK call family | idax API | Applies to |
| --- | --- | --- |
| `get_func` | `ida::function::at`, `name_at`, `chunks`, `callees`, `callers` as needed | transfer, graph, plugin flows that only need function metadata or relationships |
| `decode_insn` | `ida::instruction::decode` and operand accessors | transfer call-target recovery, graph scan logic, and register read/write analysis |
| `generate_disasm_line` | `ida::instruction::text` | assembly/dump rendering |
| `get_cmt` / `set_cmt` | `ida::comment::get` / `set` | metadata address comments |
| `get_func_cmt` / `set_func_cmt` | `ida::function::comment` / `set_comment` | metadata function comments |
| `set_name` | `ida::name::set` / `force_set` | metadata name apply |
| `get_tinfo` / `apply_tinfo` | `ida::type::retrieve`, `TypeInfo::apply`, `function::declaration`, `function::set_prototype`, `function::apply_decl` | simple metadata type export/apply; recursive dependency walking needs P22.R2 |
| `parse_decls` | `ida::type::parse_declarations` | bulk local type imports |

## Host Evidence Commands

The remaining gates can be built and run with:

```bash
scripts/run_codedump_parity_host_gates.sh
```

For durable evidence logs and expected-output criteria, use
`docs/codedump_host_evidence.md`.

Opt into the interactive modal form gate inside an IDA UI session with:

```bash
IDAX_RUN_MODAL_FORMS=1 scripts/run_codedump_parity_host_gates.sh
```

Opt into the Qt clipboard gate only after configuring against an
IDA-compatible Qt package built with `QT_NAMESPACE=QT`:

```bash
IDAX_ENABLE_QT_CLIPBOARD=ON \
IDAX_QT6_DIR=/path/to/qt-install/lib/cmake/Qt6 \
IDAX_RUN_QT_CLIPBOARD=1 \
scripts/run_codedump_parity_host_gates.sh
```

## Migration Notes

- C++ `ida-cdump` migration is no longer blocked by typed form API shape; it can
  use the compile-time idax form bindings directly.
- Node/Rust typed forms are a binding parity concern, not a current blocker for
  the C++ `ida-cdump` plugin. Their API is intentionally fixed-shape and backed
  by concrete C++ call sites.
- The updated notes explicitly called out bulk local type declaration import.
  idax now covers that path with `ida::type::parse_declarations(...)`;
  `TypeInfo::from_declaration` and `function::apply_decl` remain
  single-declaration helpers and are not the metadata-import replacement.
- Hex-Rays positioned user comments, mutable ctree, and broader microcode
  mutation are deliberately out of this parity queue because the current
  `ida-cdump` code does not require them.
