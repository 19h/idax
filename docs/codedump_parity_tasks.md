# ida-cdump parity implementation tasks

This task list translates ida-cdump identified parity gaps in idax
into concrete idax-side implementation work. The goal is to make the
`ida-cdump` plugin able to remove its remaining direct IDA / Hex-Rays SDK
usage without adding raw SDK escape hatches to idax public APIs.

## Scope

Primary parity blockers:

- typed `ask_form` bindings
- Qt clipboard fallback
- Hex-Rays scoped initialization/lifetime helper

Secondary migration helpers:

- bulk local type-declaration import and lower-level transfer-module cleanups

Already addressed in idax during Phase 22:

- wait-box / cancellation UI
- Hex-Rays `hxe_populating_popup` subscription
- Local Types `type_ref` action context payload
- multiline `ask_text`, IDB path fallback, and small path helpers
- Hex-Rays lvar settings snapshot/writeback, per-lvar comments, and
  function prototype apply
- read-only ctree accessors needed by `analysis/ctree_analyzer.cpp`

## Current gap-to-task map

This table reflects the updated `<userhome>/dev/ida-cdump/docs/IDAX_GAPS.md`
notes as of 2026-05-28 and maps each still-relevant gap to idax work.

| ida-cdump gap | idax task | Status |
| --- | --- | --- |
| Typed `ask_form` varargs | P22.1 typed binding pack plus compile-time `FormBuilder` | C++ plus fixed-shape Node/Rust bindings implemented; host-modal runtime execution pending |
| Wait box | P22.2 `ida::ui::WaitBox`, `Progress`, `ProgressFn` | implemented |
| Hex-Rays popup event | P22.3 `ida::decompiler::on_populating_popup` | implemented |
| Local Types `type_ref` | P22.4 `ida::plugin::ActionContext::type_ref` | implemented |
| Clipboard fallback | P22.5 Qt-backed `copy_to_clipboard` / `read_clipboard` | C++ optional backend plus Node/Rust wrappers implemented; host-runtime pending |
| `ask_text`, `idb_path`, path helpers | P22.5 multiline text, `database::idb_path`, `ida::path` | implemented |
| Bulk lvar/prototype metadata | P22.6 `LvarSnapshot`, lvar comments, `function::apply_decl` | implemented |
| Read-only ctree+lvar analysis | P22.7 helper-name/type/parent/local-variable-index helpers | implemented |
| Hex-Rays init/term ownership | P22.9 scoped Hex-Rays session or plugin option | implemented with example lifecycle and host-runtime coverage |
| Bulk local type declarations | P22.10 `type::parse_declarations`, options, structured report, and validation | implemented |
| `generate_disasm_line`, input path, `PLUGIN_HIDE` | Existing `instruction::text`, `database::input_file_path`, `ExportFlags::hidden` | no task |
| Lower-level transfer/analysis SDK calls | Existing `function`, `instruction`, `comment`, `name`, and `type` wrappers | no new idax API task; migration cleanup only |
| `info(...)` / `warning(...)` printf comfort overloads | Existing `ida::ui::info(std::string_view)` / `warning(std::string_view)` with caller-side formatting | no parity task |

## Concrete idax implementation work items

These are the idax-side tasks established from the updated gap notes. Completed
items remain listed so the parity scope is auditable; the open rows are
evidence/host-execution tasks, not missing API design work.

| ID | Gap covered | Concrete idax work | Primary files | Binding work | Exit condition |
| --- | --- | --- | --- | --- | --- |
| P22.1 | Typed `ask_form` vararg bindings | Add typed `form_*` factories, variadic `ask_form(markup, bindings...)`, compile-time `FormBuilder`, audited dialog-pack coverage, and host-gated modal runtime path | `include/ida/ui.hpp`, `src/ui.cpp`, `tests/unit/api_surface_parity_test.cpp`, `tests/unit/core_unit_test.cpp`, `tests/integration/codedump_parity_host_gates_test.cpp`, `examples/plugin/codedump_parity_probe_plugin.cpp` | Fixed-shape Node/Rust entrypoints for the audited codedump packs | API and binding work complete; remaining exit is `IDAX_RUN_MODAL_FORMS=1` on an interactive IDA UI host |
| P22.2 | Wait box / progress UI | Add RAII `WaitBox`, cooperative `Progress`, and `ProgressFn` cancellation contract | `include/ida/ui.hpp`, `src/ui.cpp`, `tests/unit/api_surface_parity_test.cpp`, `examples/plugin/codedump_parity_probe_plugin.cpp` | Node/Rust owned wait-box wrappers | Complete; runtime remains naturally UI-host gated |
| P22.3 | Hex-Rays `hxe_populating_popup` | Add `PopulatingPopupEvent` and `ida::decompiler::on_populating_popup` through the decompiler event bridge | `include/ida/decompiler.hpp`, `src/decompiler.cpp`, `examples/plugin/abyss_port_plugin.cpp`, `tests/unit/api_surface_parity_test.cpp` | Node/Rust callback wrappers | Complete |
| P22.4 | Local Types `type_ref` action context | Snapshot `til_type_ref_t` into owned `plugin::TypeRef` on `ActionContext` | `include/ida/plugin.hpp`, `src/plugin.cpp`, action/plugin coverage | Rust safe/FFI callback context coverage; Node has no plugin/action namespace | Complete |
| P22.5 | Clipboard, `ask_text`, IDB path, portable path helpers | Add optional Qt clipboard bridge with default `Unsupported` contract, multiline `ask_text`, `database::idb_path`, and `ida::path` helpers | `include/ida/ui.hpp`, `src/ui.cpp`, `src/detail/qt_clipboard_bridge.*`, `include/ida/database.hpp`, `src/database.cpp`, `include/ida/path.hpp`, `src/path.cpp`, `tests/integration/codedump_parity_host_gates_test.cpp` | Node/Rust wrappers for clipboard, `ask_text`, `database::idb_path`, and `ida::path` | API and binding work complete; remaining clipboard exit is `IDAX_ENABLE_QT_CLIPBOARD=ON` with IDA-compatible `QT_NAMESPACE=QT` Qt plus `IDAX_RUN_QT_CLIPBOARD=1` in an IDA Qt host |
| P22.6 | Bulk lvar settings, lvar comments, prototype apply | Add `LvarSnapshot`, capture/restore, `set_variable_comment`, `function::set_prototype`, and `function::apply_decl` | `include/ida/decompiler.hpp`, `src/decompiler.cpp`, `include/ida/function.hpp`, `src/function.cpp`, `tests/integration/decompiler_storage_hardening_test.cpp`, `tests/integration/type_roundtrip_test.cpp` | Node/Rust lvar snapshot/comment and prototype wrappers | Complete |
| P22.7 | Read-only ctree/lvar analysis helpers | Add helper-name/type accessors, callback-scoped parent snapshots, stable local-variable indexes, and lookup by ctree index | `include/ida/decompiler.hpp`, `src/decompiler.cpp`, `tests/integration/decompiler_storage_hardening_test.cpp` | Node/Rust visitor payload and direct local-variable lookup coverage | Complete |
| P22.8 | Migration documentation, example, and validation harness | Maintain parity task list, migration checklist, host-evidence runbook, compact codedump-parity example, validation report, host-gate runner, evidence-log verifier, and local validation runner | `docs/codedump_parity_tasks.md`, `docs/codedump_migration_checklist.md`, `docs/codedump_host_evidence.md`, `docs/validation_report.md`, `examples/plugin/codedump_parity_probe_plugin.cpp`, `scripts/run_codedump_parity_host_gates.sh`, `scripts/check_codedump_parity_evidence_log.sh`, `scripts/run_codedump_parity_local_validation.sh` | Binding docs and tests record C++/Node/Rust coverage | Complete except the two host-evidence rows below |
| P22.9 | Hex-Rays init/term ownership | Add move-only `ScopedSession` and `decompiler::initialize()` with ownership/refcount behavior separate from non-owning `available()` | `include/ida/decompiler.hpp`, `src/decompiler.cpp`, `examples/plugin/abyss_port_plugin.cpp`, `tests/integration/codedump_parity_host_gates_test.cpp` | Node/Rust owned scoped-session wrappers | Complete; local `IDAX_RUN_HEXRAYS_SESSION=1` host gate passes |
| P22.10 | Bulk local type declaration import | Add `type::parse_declarations`, options, structured report, and validation | `include/ida/type.hpp`, `src/type.cpp`, `tests/integration/type_roundtrip_test.cpp` | Node/Rust parse-declarations wrappers | Complete |
| P22.M1 | Lower-level transfer/analysis SDK cleanup | Migrate ida-cdump call sites that already have idax replacements: function lookup/comments, instruction decode/text, address comments, names, applied types, and bulk type declarations | ida-cdump-side `src/transfer/*`, `src/analysis/*`, `src/graph/*`, `src/plugin/codedump_plugin.cpp` | Existing binding coverage applies where those namespaces are exposed | No new idax API task; track as downstream ida-cdump migration work |
| P22.F1 | Future Hex-Rays positioned user comments | Add `DecompiledFunction::user_comments()` and batch setter only if ida-cdump starts exporting `cfunc->user_cmts` | Not scheduled | Not scheduled | Out of scope for current parity because the updated gap notes identify it as future/non-blocking |
| P22.F2 | Mutable ctree / broader microcode mutation | Design explicit mutable APIs only for a concrete caller that needs them | Not scheduled | Not scheduled | Out of scope for current ida-cdump parity |
| P22.F3 | Printf-style UI diagnostic overloads | Add formatting overloads for `ida::ui::info` / `warning` only if a future port needs idax-owned formatting | Not scheduled | Existing string-view API is sufficient for current ida-cdump, which already preformats messages | Comfort gap only; no direct SDK dependency remains when callers format before invoking idax |

## Current closure queue

The updated gap notes no longer leave a missing idax API for the audited
high-value areas. The remaining work is host evidence:

| Priority | Task | Primary files | Binding posture | Exit condition |
| --- | --- | --- | --- | --- |
| 1 | P22.H1 modal typed-form evidence | `tests/integration/codedump_parity_host_gates_test.cpp`, `docs/validation_report.md` | C++ plus fixed-shape Node/Rust entrypoints implemented | Run `IDAX_RUN_MODAL_FORMS=1` in an interactive IDA UI host and record the result |
| 2 | P22.H2 Qt clipboard host evidence | `CMakeLists.txt`, `src/detail/qt_clipboard_bridge.*`, `tests/integration/codedump_parity_host_gates_test.cpp`, `scripts/run_codedump_parity_host_gates.sh` | C++ optional Qt backend and Node/Rust wrappers implemented | Build with an IDA-compatible `QT_NAMESPACE=QT` Qt package, then run `IDAX_RUN_QT_CLIPBOARD=1` in an IDA Qt host |
| 3 | P22.V1 final parity validation refresh | CMake, parity example, Node, Rust validation targets; `docs/validation_report.md`; `.agents/*` | Binding tests cover the new surfaces structurally, compile-time, and through non-modal validation where available | Latest local refresh passes including the compact parity probe example; rerun focused C++/example/Node/Rust checks after host evidence is collected and record any host-only skips separately |

## Actionable remaining task breakdown

The concrete idax implementation backlog is now limited to evidence execution
and final documentation refresh. New C++/Node/Rust API work should only be
opened if one of these evidence runs exposes a real implementation defect.

| ID | Task | Exact action | Closure proof |
| --- | --- | --- | --- |
| P22.H1.1 | Modal host setup | Start an interactive IDA UI host from this checkout with the generated `codedump_parity_host_gates` target available. | Host can launch the parity gate runner without default/modal build failures. |
| P22.H1.2 | Accepted typed-form run | Run `IDAX_RUN_MODAL_FORMS=1 IDAX_EVIDENCE_LOG=logs/codedump-modal-forms.log scripts/run_codedump_parity_host_gates.sh` and accept the codedump-shaped dialog with default values. | Log contains `host-gated codedump-shaped typed form`, no modal skip, zero failures, and at least 4 passed checks. |
| P22.H1.3 | Modal evidence verification | Run `scripts/check_codedump_parity_evidence_log.sh logs/codedump-modal-forms.log modal`. | Verifier exits successfully; record command, log path, and check counts in `docs/validation_report.md`. |
| P22.H2.1 | Qt package setup | Provide `IDAX_QT6_DIR` pointing at a Qt6 package compatible with IDA and built with `QT_NAMESPACE=QT`. Do not use an un-namespaced system Qt package. | `scripts/run_codedump_parity_host_gates.sh --self-test` still passes, and the Qt preflight no longer rejects `IDAX_QT6_DIR`. |
| P22.H2.2 | Qt clipboard run | Run `IDAX_ENABLE_QT_CLIPBOARD=ON IDAX_QT6_DIR=/path/to/qt-install/lib/cmake/Qt6 IDAX_RUN_QT_CLIPBOARD=1 IDAX_EVIDENCE_LOG=logs/codedump-qt-clipboard.log scripts/run_codedump_parity_host_gates.sh` inside an IDA Qt UI host. | Log contains `host-gated Qt clipboard roundtrip`, no Qt clipboard skip, zero failures, and at least 2 passed checks. |
| P22.H2.3 | Qt evidence verification | Run `scripts/check_codedump_parity_evidence_log.sh logs/codedump-qt-clipboard.log qt-clipboard`. | Verifier exits successfully; record command, log path, backend, and check counts in `docs/validation_report.md`. |
| P22.V1.1 | Local final sweep | After P22.H1/P22.H2 evidence, rerun `scripts/run_codedump_parity_local_validation.sh build-test-fetch RelWithDebInfo`; set `IDAX_RUN_NODE_INTEGRATION=1 IDADIR=/path/to/ida` when fixture integration is available. | Focused C++, default/opt-in host evidence verification, compact parity example, Node, and Rust parity checks pass or host-only skips are explicitly justified. |
| P22.V1.2 | Closure documentation | Update `docs/validation_report.md`, `.agents/active_work.md`, and `.agents/progress_ledger.md` with final evidence; keep `docs/codedump_migration_checklist.md` aligned. | P22.H1/P22.H2 are marked closed only with verified logs; remaining ida-cdump raw SDK use is classified as downstream migration cleanup or future/non-blocking scope. |

P22.8 migration validation is complete: every updated `IDAX_GAPS.md` row maps
to an implemented API, an explicit host-evidence item, or an out-of-scope
future note in `docs/codedump_migration_checklist.md`.

## Existing-API Migration Candidates

The updated gap notes also mention lower-level direct SDK calls that remain in
ida-cdump after the high-value parity surfaces are available. These are not
new idax implementation tasks because idax already exposes stable replacements:

| SDK shape in ida-cdump | idax replacement | Notes |
| --- | --- | --- |
| `get_func(ea)` | `ida::function::at(ea)` / `name_at(ea)` | Use value snapshots instead of raw `func_t*` where callers only need bounds, entry, name, flags, comments, or relationships. |
| `decode_insn(&insn, ea)` | `ida::instruction::decode(ea)` | Use operand accessors for register/immediate/target decoding; keep raw SDK only where a missing operand detail is proven. |
| `generate_disasm_line` | `ida::instruction::text(ea)` | Already listed as corrected in the updated gap notes. |
| `get_cmt` / `set_cmt` | `ida::comment::get` / `set` | Covers ida-cdump's plain address comments. Hex-Rays positioned comments remain future-only. |
| `get_func_cmt` / `set_func_cmt` | `ida::function::comment` / `set_comment` | Covers function comments in metadata export/apply. |
| `set_name` | `ida::name::set` / `force_set` | Choose `force_set` only for SDK paths that currently use force-like flags. |
| `get_tinfo` | `ida::type::retrieve` plus `TypeInfo::to_string()` | Covers applied type retrieval; function prototypes use `DecompiledFunction::declaration()` or `function::apply_decl` depending on direction. |
| `parse_decls` | `ida::type::parse_declarations` | P22.10 closes the bulk local type import path. |
| `get_input_file_path` / `get_path(PATH_TYPE_IDB)` | `ida::database::input_file_path()` / `idb_path()` | P22.5 closes the IDB fallback. |
| `qbasename` / `qdirname` / `qisdir` | `ida::path::{basename, dirname, is_directory}` or `<filesystem>` | P22.5 provides shared helper semantics for C++ and bindings. |

## P22.1 Typed forms

Implement type-safe `ida::ui::ask_form` bindings.

Status: C++ core implemented for direct typed bindings and compile-time
`FormBuilder` construction. Node/Rust exposure is implemented through fixed
codedump-shaped entrypoints only; a host-modal codedump-shaped runtime scenario
remains pending. Binding-side APIs must not synthesize a runtime `va_list`.

Deliverables:

- Add a variadic template overload:
  `Result<bool> ida::ui::ask_form(std::string_view markup, Bindings&... bindings)`.
- Support the binding forms used by `ida-cdump`: signed integer depth/count
  fields, `std::uint16_t` checkbox/radio groups, path/text strings, and
  address fields.
- Add a compile-time `FormBuilder<...>` convenience API whose final type
  encodes the bound field tuple. Do not use a runtime type-erased vector as
  the mechanism for invoking SDK varargs.
- Internally marshal `std::string` path/text fields through bounded SDK
  buffers and write accepted results back to the caller.

Concrete implementation tasks:

- P22.1.1 [x] Add public binding factory types in `include/ida/ui.hpp`:
  `form_int(std::int64_t&)`, `form_sval(sval_t&)`,
  `form_bitset(std::uint16_t&)`, `form_radio(std::uint16_t&)`,
  `form_address(Address&)`, `form_text(std::string&)`, and
  `form_path(std::string&, bool for_saving = true)`.
- P22.1.2 [x] Implement internal binding adapters that own SDK-side storage before
  the call and commit back only on accepted forms: `sval_t*` for numeric
  fields, `ushort*` for checkbox/radio groups, `ea_t*` for addresses,
  `qstring*` for text fields, and bounded `char[QMAXPATH]` buffers for paths.
- P22.1.3 [x] Add the variadic
  `ask_form(std::string_view markup, Bindings&... bindings)` overload as a
  header template so the concrete pointer pack reaches SDK `ask_form(...)`
  without trying to synthesize a runtime `va_list`.
- P22.1.4 [x] Add `FormBuilder<Bound...>` with chaining methods for the seven
  codedump dialog shapes: signed depth/count fields, checkbox bitsets, radio
  groups, save/open paths, free text, and address inputs. Each `add_*` returns
  a new builder type whose tuple preserves the SDK vararg order.
- P22.1.5 [x] Validate field text before crossing the SDK boundary: non-empty
  markup, path length within `QMAXPATH`, no embedded NULs in string-backed
  fields, and SDK rejection reported as an `Error::sdk`.
- P22.1.6 [x] Add compile/API coverage in `tests/unit/api_surface_parity_test.cpp`
  for direct bindings and builder construction, plus non-modal unit coverage
  for numeric/address/path adapter prepare/commit behavior and the audited
  codedump dialog builder packs.
- P22.1.7 [x] Defer Node/Rust exposure until P22.1.1-P22.1.6 are stable. Binding
  APIs must use a fixed generated/templated invocation set for supported form
  shapes; they must not expose a runtime vector that pretends to call C/C++
  varargs.
- P22.1.8 [x] Add a host-gated codedump-shaped form runtime scenario that skips
  cleanly when modal UI is unavailable. The
  `codedump_parity_host_gates` integration test exercises the scenario only
  when `IDAX_RUN_MODAL_FORMS=1` is set, and the interactive evidence path now
  requires accepting the dialog so a cancellation cannot close P22.H1.
- P22.1.9 [x] Expose only concrete supported binding signatures that match the
  audited dialog shapes: `(sval,bitset)`, `(sval,path,bitset)`,
  `(path,bitset)`, `(radio,sval,path,bitset)`, and
  `(sval,sval,sval,path,bitset,bitset)`. Node structural/non-modal tests and
  Rust `ui_tests::test_codedump_typed_forms_reject_empty_markup_without_modal_ui`
  plus signature/result-shape checks cover the binding surface; modal execution
  remains host-gated.

Acceptance:

- `tests/unit/api_surface_parity_test.cpp` covers the template surface and
  builder construction.
- At least one integration/example path demonstrates a form equivalent to a
  codedump dialog shape, gated/skipped cleanly on headless hosts if needed.
- Documentation explains the varargs limitation and why the builder is
  compile-time typed.

## P22.2 Long-running progress UI

Implement wait-box and cancellation helpers in `ida::ui`.

Status: implemented for the C++ surface in the first P22 slice
(`ida::ui::WaitBox`, `Progress`, `ProgressFn`), with compile-time API
coverage. Node/Rust now expose RAII/owned wait-box wrappers for binding-side
plugin UI code. Runtime exercise remains host-gated because wait boxes require
an IDA UI host.

Deliverables:

- Add `ida::ui::WaitBox` RAII wrapper over `show_wait_box`,
  `replace_wait_box`, `hide_wait_box`, and `user_cancelled`.
- Provide `update(std::string_view)`, `cancelled()`, and `dismiss()`.
- Add optional formatting convenience only if it can remain header-only and
  not increase binary coupling.
- Add a small `Progress` / `ProgressFn` model for reusable long-running
  algorithms.

Acceptance:

- API surface parity test covers construction/move restrictions and method
  availability.
- UI integration coverage exercises construction/update/dismiss where a UI
  host is available, or compile-only coverage documents why runtime testing
  is host-gated.
- Quickstart/API docs include the RAII lifetime rule.
- Node/Rust wrappers preserve the same lifetime rule and avoid opening UI in
  ordinary structural tests.

## P22.3 Hex-Rays popup event subscription

Expose Hex-Rays `hxe_populating_popup` through the existing decompiler event
subscription machinery.

Status: implemented for C++ and threaded through Node/Rust bindings as
`on_populating_popup` / `onPopulatingPopup`. The event carries callback-scoped
opaque widget, popup, and decompiler-view handles plus the function address
when Hex-Rays provides one. `examples/plugin/abyss_port_plugin.cpp` now uses
the event to attach pseudocode popup actions.

Deliverables:

- Add `PopulatingPopupEvent` with opaque widget, popup, and `vdui_t` handles,
  plus `function_address` when available.
- Add `Result<Token> ida::decompiler::on_populating_popup(...)`.
- Wire the event into the existing `hexrays_event_bridge` without breaking
  current subscriptions.
- Consider a generic advanced `on_event` only after the concrete popup event
  is stable.

Acceptance:

- Unit/API surface coverage for the new event type and subscription call.
- Integration or example coverage showing dynamic popup attachment from the
  event.
- Existing decompiler event tests still pass.

## P22.4 Local Types action context

Surface Local Types `til_type_ref_t` through `ida::plugin::ActionContext`.

Status: implemented. `ida::plugin::ActionContext::type_ref` now snapshots
the SDK `action_ctx_base_t::type_ref` payload into an owned
`ida::plugin::TypeRef` carrying the type name plus `ida::type::TypeInfo`.
Rust FFI/safe bindings carry the optional payload through context-aware
action callbacks.

Deliverables:

- Add `ida::plugin::TypeRef { std::string name; ida::type::TypeInfo type; }`.
- Add `std::optional<TypeRef> ActionContext::type_ref`.
- Populate the field in action activation and update contexts when the SDK
  provides `ctx->type_ref`.
- Preserve current opaque context behavior for all non-Local-Types widgets.

Acceptance:

- API surface test verifies `ActionContext::type_ref`.
- Action plugin/example demonstrates enabling an action only for
  `WidgetType::LocalTypes` with a present type ref.
- No regressions in existing action registration tests.

## P22.5 Clipboard, multiline text, and path helpers

Add the small UI/path helpers needed by codedump's user-facing flows.

Status: implemented with host evidence pending. `ida::ui::ask_text`,
`ida::database::idb_path`, and `ida::path::{basename, dirname, is_directory}`
are available in C++; `database::idb_path`, multiline `ask_text`, and the
portable path helpers are wired through Node/Rust where bindings need the same
user-facing fallback surface. C++ clipboard helpers now exist behind an
explicit optional Qt backend (`IDAX_ENABLE_QT_CLIPBOARD=ON`) and return
`Unsupported` in default non-Qt builds. Node/Rust wrappers expose the same
copy/read/backend helpers; host-gated runtime coverage remains pending.
Enabling the Qt backend requires an IDA-compatible Qt package built with
`QT_NAMESPACE=QT`; CMake now rejects plain system Qt packages early to avoid
mixed Qt/IDA links.

Deliverables:

- Add Qt-backed `ida::ui::copy_to_clipboard(std::string_view)` and
  `ida::ui::read_clipboard()`.
- Add diagnostic backend text if practical, with Qt reported as the backend.
- Add `ida::ui::ask_text(...)` for multiline text display/input.
- Add `ida::database::idb_path()` wrapping `get_path(PATH_TYPE_IDB)`.
- Either add `ida::path::{basename, dirname, is_directory}` or document that
  codedump should use `std::filesystem` for those helpers.

Concrete implementation tasks:

- P22.5.1 [x] Keep `ask_text`, `database::idb_path`, and `ida::path` helpers as
  implemented and covered.
- P22.5.2 [x] Audit existing Qt linkage in the core library, plugin examples, and
  Node addon build. Choose one supported boundary: core Qt linkage, optional
  compile-time Qt feature, or host-gated bridge returning `Unsupported`.
- P22.5.3 [x] Add `Status ida::ui::copy_to_clipboard(std::string_view)`,
  `Result<std::string> ida::ui::read_clipboard()`, and
  `std::string_view ida::ui::clipboard_backend()` to `include/ida/ui.hpp`.
- P22.5.4 [x] Implement the helpers through `src/detail/qt_clipboard_bridge.*`
  with `QApplication::clipboard()` / `QClipboard` when a Qt application
  instance is present. Keep Qt headers out of IDA SDK translation units and do
  not shell out to platform tools; Qt is the intended backend.
- P22.5.5 [x] Return structured errors for no UI host, no Qt application,
  unsupported Qt linkage, and empty read result where the platform reports no
  clipboard text.
- P22.5.6 [x] Add C++ surface coverage and a host-gated runtime test that writes
  a unique token, reads it back, and restores/skips deterministically. C++
  surface coverage and a gated test path are present; a Qt-enabled UI-host run
  with `IDAX_RUN_QT_CLIPBOARD=1` remains pending and requires
  `IDAX_ENABLE_QT_CLIPBOARD=ON` plus an IDA-compatible `QT_NAMESPACE=QT` Qt
  package.
- P22.5.7 [x] Add Node/Rust wrappers over the C++ optional-Qt clipboard shape.
- P22.5.8 [x] Add Node/Rust wrappers for `ask_text` so the ida-cdump
  clipboard fallback dialog has binding parity with the C++ surface. Runtime
  execution remains host-modal like other prompt APIs.
- P22.5.9 [x] Add Node/Rust wrappers for `ida::path::{basename, dirname,
  is_directory}` so binding-side codedump ports can use the same portable
  helper semantics as the C++ surface instead of relying on host-language
  path APIs.

Acceptance:

- Compile/API tests cover all new helpers.
- Runtime tests are host-gated where Qt clipboard or modal UI is unavailable.
- Docs describe clipboard behavior and failure modes.

## P22.6 Hex-Rays lvar settings and prototype apply

Close the high-value metadata transfer gaps.

Status: implemented. C++ now exposes `ida::decompiler::LvarSnapshot`,
`DecompiledFunction::{capture_user_lvar_settings,restore_user_lvar_settings}`,
`DecompiledFunction::set_variable_comment(...)`,
`DecompilerView` forwarding helpers, and
`ida::function::{set_prototype,apply_decl}`. Node and Rust bindings expose the
same lvar snapshot/comment and function prototype workflows. Rust no-run
validation now reaches the high-level wrapper tests after repairing the
recursive microcode bindgen output.

Deliverables:

- Add an opaque/idax-owned `LvarSnapshot` model that captures the relevant
  `lvar_uservec_t` data without exposing SDK structs.
- Add `DecompiledFunction::capture_user_lvar_settings()` and
  `restore_user_lvar_settings(const LvarSnapshot&)`.
- Add `DecompiledFunction::set_variable_comment(...)` using the same user
  lvar settings path.
- Add `ida::function::set_prototype(Address, const ida::type::TypeInfo&)`.
- Add `ida::function::apply_decl(Address, std::string_view c_decl)`.
- Bulk local type declaration import is tracked separately as P22.10 because
  it targets `ida::type`, not the Hex-Rays lvar/prototype APIs in this slice.

Acceptance:

- Integration coverage round-trips lvar name/type/comment settings on a
  decompiled function where Hex-Rays is available.
- Prototype apply coverage parses a C declaration, applies it, and verifies
  retrieval/decompiler declaration text.
- Metadata APIs return structured errors for missing Hex-Rays, missing
  function, invalid declaration, and unmatched lvar locator/name cases.

## P22.7 Read-only ctree migration helpers

Add any small read-only ctree accessors still needed to port
`analysis/ctree_analyzer.cpp` off raw `cexpr_t`/`cfunc_t` access.

Status: implemented. `ExpressionView` now exposes
`helper_name()`, `type_declaration()`, and callback-scoped parent snapshots
when `VisitOptions::track_parents` is enabled; `StatementView` exposes the
same parent-chain access. `LocalVariable` carries the stable ctree variable
index and `DecompiledFunction::variable(index)` performs direct lookup. Node
and Rust bindings expose stable local-variable lookup plus ctree callback
payloads for helper names, expression type strings, parent item summaries,
and parent-chain depth.

Deliverables:

- Add expression helper-name access for `ExprHelper`.
- Add expression type/declaration string access where Hex-Rays provides
  `cexpr_t::type`.
- Add parent-chain access when `VisitOptions::track_parents` is enabled, or
  a visitor callback context that exposes parent items safely.
- Add a direct `LocalVariable` lookup by expression variable index, or a
  stable index field on `LocalVariable`.

Concrete implementation tasks:

- P22.7.1 [x] Add `ExpressionView::helper_name()` for `ExprHelper`; return a
  validation error for non-helper expressions and never expose the raw
  `cexpr_t::helper` pointer.
- P22.7.2 [x] Add `ExpressionView::type_declaration()` over `cexpr_t::type`,
  returning a C declaration/type string when Hex-Rays has materialized type
  information and a structured unsupported/not-found result when it has not.
- P22.7.3 [x] Add a callback-scoped `CtreeItemView` parent model and populate it
  when `VisitOptions::track_parents` is true. At minimum expose parent item
  type, address, expression/statement classification, and parent-chain length.
- P22.7.4 [x] Add `ExpressionView::parent()` / `parents()` and
  `StatementView::parent()` / `parents()` that return empty results unless
  `track_parents` was enabled for the traversal.
- P22.7.5 [x] Add `LocalVariable::index` matching the stable index returned by
  `ExpressionView::variable_index()`, plus
  `DecompiledFunction::variable(std::size_t)` for direct lookup.
- P22.7.6 [x] Thread the new read-only fields through Node/Rust only after the
  C++ API is validated, because current Rust visitor callbacks expose only
  shallow `ExpressionInfo`/`StatementInfo`. Node and Rust now expose
  local-variable index/direct lookup and ctree callback helper/type/parent
  payloads.
- P22.7.7 [x] Add integration coverage that classifies helper calls, typed
  expressions, variable references, and nested call/assignment parents using
  only idax ctree views and `LocalVariable` APIs.

Acceptance:

- A focused integration test exercises call argument origin analysis using
  only `ExpressionView`, `StatementView`, and `LocalVariable` APIs.
- Existing decompiler visitor tests still pass.
- Docs explicitly state that ctree views are read-only and callback-scoped.

## P22.9 Hex-Rays lifetime helper

Close the remaining direct `init_hexrays_plugin()` / `term_hexrays_plugin()`
usage in ida-cdump plugin lifecycle code.

Status: C++ implemented with `ida::decompiler::initialize()` returning a
move-only `ScopedSession`. Existing `available()` remains a non-owning
query/use initializer, while scoped sessions track only explicit ownership.
`examples/plugin/abyss_port_plugin.cpp` now holds a scoped session across the
plugin lifetime. The host-gated `IDAX_RUN_HEXRAYS_SESSION=1` runtime path
passes locally against `tests/fixtures/simple_appcall_linux64`. Node and Rust
now expose owned scoped-session wrappers with explicit `close` and validity
checks; binding runtime execution remains Hex-Rays-host gated.

Deliverables:

- Add a scoped handle, for example `ida::decompiler::ScopedSession`, returned
  by `ida::decompiler::initialize()` or `require_available()`.
- Ensure the handle represents explicit plugin ownership and releases it on
  destruction without changing the existing `available()` query semantics.
- Consider a plugin option such as `Plugin::requires_hexrays()` only if it
  can be integrated without surprising standalone/idalib callers.

Concrete implementation tasks:

- P22.9.1 [x] Audit current `ida::decompiler::available()` and all existing
  decompiler entrypoints to confirm they remain query/use APIs and do not take
  ownership of Hex-Rays initialization.
- P22.9.2 [x] Add a move-only `ScopedSession` in `include/ida/decompiler.hpp` with
  `valid()`, boolean conversion, deleted copy operations, and destructor-based
  release.
- P22.9.3 [x] Add `Result<ScopedSession> ida::decompiler::initialize()` in
  `src/decompiler.cpp`, backed by `init_hexrays_plugin()` and
  `term_hexrays_plugin()`. Treat `available()` as non-owning and
  `initialize()` as the explicit plugin-host ownership boundary.
- P22.9.4 [x] Define lifecycle behavior for repeated sessions. Prefer an internal
  reference count guarded by a mutex so multiple idax consumers in one plugin
  can hold sessions without prematurely calling `term_hexrays_plugin()`.
- P22.9.5 [x] Add API surface coverage for move-only semantics and a host-gated
  plugin/example path that initializes Hex-Rays, decompiles, and releases
  through the scoped handle. API surface coverage and example lifecycle coverage
  are present, and `codedump_parity_host_gates` passes the
  `IDAX_RUN_HEXRAYS_SESSION=1` runtime path against
  `tests/fixtures/simple_appcall_linux64`.
- P22.9.6 [x] Expose owned Node/Rust scoped-session wrappers over
  `ida::decompiler::initialize()` so binding-side plugin lifecycle code can
  hold explicit Hex-Rays ownership without changing `available()` semantics.

Acceptance:

- ida-cdump can replace direct Hex-Rays init/term calls with idax C++.
- Existing `decompiler::available()` behavior remains source-compatible.
- Docs explain the difference between a query and an owning session.

## P22.10 Bulk local type declaration import

Close the remaining metadata-apply type import gap identified in the updated
ida-cdump notes.

Status: implemented. idax now exposes
`ida::type::parse_declarations(...)` with a stable
`ParseDeclarationsReport`, validation for empty/embedded-NUL input, a small
options model over clear `HTI_*` behavior, C++ integration coverage, Node
bindings, and Rust shim/safe wrappers. Rust high-level validation remains
locally compile-validated with the repaired recursive microcode bindgen
output.

Deliverables:

- Add a C++ API such as
  `ida::type::parse_declarations(std::string_view declarations,
  const ParseDeclarationsOptions& options = {})`.
- Model the result as a structured report rather than a raw SDK integer. The
  SDK documents the return as a declaration error count, where zero means the
  import completed without parser errors; idax should expose that count and
  optional diagnostics in a stable shape.
- Support the current local-IDB import mode backed by
  `parse_decls(nullptr, blob.c_str(), nullptr, HTI_DCL)`.
- Add options only when they map cleanly to IDA flags, for example silent mode,
  replace existing declarations, or target TIL once a concrete caller needs it.
- Add Node and Rust wrappers after the C++ surface is covered.

Concrete implementation tasks:

- P22.10.1 [x] Add public value types in `include/ida/type.hpp`:
  `ParseDeclarationsOptions` and `ParseDeclarationsReport`.
- P22.10.2 [x] Implement
  `Result<ParseDeclarationsReport> ida::type::parse_declarations(...)` in
  `src/type.cpp`, validating non-empty input and embedded NULs before calling
  `parse_decls`.
- P22.10.3 [x] Add focused C++ coverage that imports a small struct/typedef
  declaration block, verifies resulting local type lookup, and reports parser
  failures as structured idax errors.
- P22.10.4 [x] Add Node wrappers and TypeScript declarations for the same
  report shape.
- P22.10.5 [x] Add Rust shim/safe wrappers and tests. The generated
  `IdaxMicrocodeInstruction` layout blocker is fixed in the Rust build script
  so high-level wrapper no-run validation can execute.
- P22.10.6 [x] Update docs and the migration checklist so
  `metadata_apply.cpp` has an idax replacement for `parse_decls`.

Acceptance:

- `ida-cdump` metadata apply can import a `.cdumpmeta` type block without
  direct SDK `parse_decls` calls.
- The C++ API reports invalid input and SDK parser failures as structured idax
  errors.
- Node/Rust bindings expose the same report without leaking SDK constants.

## P22.8 Documentation and migration validation

Keep parity work visible and reproducible.

Deliverables:

- Update `docs/sdk_domain_coverage_matrix.md`, `docs/api_reference.md`,
  `docs/example_port_mapping_bindings.md`, and relevant quickstarts.
- Add or update an example that mirrors the codedump flows without depending
  on the codedump repository.
- Add a migration checklist mapping each row of `IDAX_GAPS.md` to an idax API.

Concrete implementation tasks:

- P22.8.1 [x] Add a `docs/codedump_migration_checklist.md` table with one row per
  `<userhome>/dev/ida-cdump/docs/IDAX_GAPS.md` section: direct SDK call,
  idax replacement, implementation status, binding availability, and residual
  caveats.
- P22.8.2 [x] Update `docs/api_reference.md`, `docs/sdk_domain_coverage_matrix.md`,
  `docs/namespace_topology.md`, README, and `.agents/api_catalog.md` for each
  completed P22.1/P22.5/P22.9 API.
- P22.8.3 [x] Add or refresh a compact codedump-parity example that exercises the
  dialog, clipboard, Hex-Rays session, popup, action-context, lvar/prototype,
  and ctree helper flows without depending on the sibling `ida-cdump` repo.
- P22.8.3a [x] Add a repeatable host-gate runner script
  (`scripts/run_codedump_parity_host_gates.sh`) so the remaining modal and Qt
  clipboard evidence can be collected with the same build/test target and
  environment toggles documented in the migration checklist. The runner has a
  lightweight self-test for default and combined host evidence mode inference,
  missing-Qt-package preflights, and missing-Hex-Rays-fixture preflights.
- P22.8.3b [x] Add a host-evidence runbook and durable runner logging with
  `IDAX_EVIDENCE_LOG`; the runner now fails before CMake when the Qt clipboard
  runtime gate is requested without `IDAX_QT6_DIR`, resolves Hex-Rays fixture
  inputs before configure/build work, and auto-verifies completed evidence
  logs for the enabled gate modes after the capture stream closes.
- P22.8.3c [x] Add an evidence-log verifier so default, Hex-Rays, modal, and
  Qt clipboard host-gate logs can be checked mechanically before updating the
  validation report. The verifier requires the relevant sections and minimum
  per-gate pass counts, so skipped sections, missing sections, and weak
  one-check summaries cannot close modal or Qt clipboard evidence. Non-default
  modes accept stronger combined host-gate logs, allowing one interactive run
  to close multiple gates when every enabled section is unskipped. Its
  self-test rejects failed summaries, contaminated mixed failed+successful
  summaries, unknown gate names, skipped host-gate sections, missing sections,
  and weak per-gate pass counts.
- P22.8.3d [x] Add a local validation runner that refreshes focused C++,
  default host-gate, evidence-verifier, the compact parity probe example,
  Node, and Rust parity evidence with one command; Node fixture integration
  remains opt-in through `IDADIR`. The runner has a lightweight self-test for
  default and combined host evidence mode inference.
- P22.8.4 [x] Run the focused validation set:
  `idax_api_surface_check`, UI/path unit coverage, decompiler storage
  hardening, segment/function edge cases, Node structural tests, and Rust
  wrapper compile/no-run.
  Locally runnable C++ checks pass. Node native build, unit, and integration
  tests now pass on the local Node 26 host after upgrading NAN and linking the
  addon against the local idax build. Rust library and type-declaration
  integration no-run validation pass after repairing the recursive microcode
  bindgen output.
- P22.8.5 [x] Record known blockers separately from parity tasks. No local
  Node/Rust binding blocker remains; only modal typed-form evidence and
  Qt clipboard evidence remain host-gated. The Qt clipboard build additionally
  requires an IDA-compatible `QT_NAMESPACE=QT` Qt package; a plain system Qt
  package is rejected at configure time.

Acceptance:

- C++ API surface parity target passes.
- All locally runnable C++ tests pass.
- Any host-gated Hex-Rays/UI tests report clear skip reasons when not runnable.

## Suggested order

1. P22.1 typed forms and builder.
2. P22.5 Qt clipboard helpers.
3. P22.9 Hex-Rays lifetime helper.
4. P22.8 docs, migration checklist, examples, bindings sweep, and validation.
