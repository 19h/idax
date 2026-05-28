# ida-cdump parity implementation tasks

This task list translates ida-cdump identified parity gaps in idax
into concrete idax-side implementation work. The goal is to make the
`ida-cdump` plugin able to remove its remaining direct IDA / Hex-Rays SDK
usage without adding raw SDK escape hatches to idax public APIs.

## Scope

Primary parity blockers:

- typed `ask_form` bindings
- wait-box / cancellation UI
- Hex-Rays `hxe_populating_popup` subscription
- Local Types `type_ref` action context payload
- Qt clipboard and multiline text fallback
- IDB path / small path helpers
- Hex-Rays lvar settings snapshot/writeback and prototype apply

Secondary migration helpers:

- read-only ctree accessor coverage needed by `ctree_analyzer.cpp`
- bulk type-declaration import and lower-level transfer-module cleanups

## P22.1 Typed forms

Implement type-safe `ida::ui::ask_form` bindings.

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

Acceptance:

- `tests/unit/api_surface_parity_test.cpp` covers the template surface and
  builder construction.
- At least one integration/example path demonstrates a form equivalent to a
  codedump dialog shape, gated/skipped cleanly on headless hosts if needed.
- Documentation explains the varargs limitation and why the builder is
  compile-time typed.

## P22.2 Long-running progress UI

Implement wait-box and cancellation helpers in `ida::ui`.

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

## P22.3 Hex-Rays popup event subscription

Expose Hex-Rays `hxe_populating_popup` through the existing decompiler event
subscription machinery.

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

Deliverables:

- Add Qt-backed `ida::ui::copy_to_clipboard(std::string_view)` and
  `ida::ui::read_clipboard()`.
- Add diagnostic backend text if practical, with Qt reported as the backend.
- Add `ida::ui::ask_text(...)` for multiline text display/input.
- Add `ida::database::idb_path()` wrapping `get_path(PATH_TYPE_IDB)`.
- Either add `ida::path::{basename, dirname, is_directory}` or document that
  codedump should use `std::filesystem` for those helpers.

Acceptance:

- Compile/API tests cover all new helpers.
- Runtime tests are host-gated where Qt clipboard or modal UI is unavailable.
- Docs describe clipboard behavior and failure modes.

## P22.6 Hex-Rays lvar settings and prototype apply

Close the high-value metadata transfer gaps.

Deliverables:

- Add an opaque/idax-owned `LvarSnapshot` model that captures the relevant
  `lvar_uservec_t` data without exposing SDK structs.
- Add `DecompiledFunction::capture_user_lvar_settings()` and
  `restore_user_lvar_settings(const LvarSnapshot&)`.
- Add `DecompiledFunction::set_variable_comment(...)` using the same user
  lvar settings path.
- Add `ida::function::set_prototype(Address, const ida::type::TypeInfo&)`.
- Add `ida::function::apply_decl(Address, std::string_view c_decl)`.
- If needed for parity, add `ida::type::parse_declarations(...)` for bulk
  type import currently handled by `parse_decls`.

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

Deliverables:

- Add expression helper-name access for `ExprHelper`.
- Add expression type/declaration string access where Hex-Rays provides
  `cexpr_t::type`.
- Add parent-chain access when `VisitOptions::track_parents` is enabled, or
  a visitor callback context that exposes parent items safely.
- Add a direct `LocalVariable` lookup by expression variable index, or a
  stable index field on `LocalVariable`.

Acceptance:

- A focused integration test exercises call argument origin analysis using
  only `ExpressionView`, `StatementView`, and `LocalVariable` APIs.
- Existing decompiler visitor tests still pass.

## P22.8 Documentation and migration validation

Keep parity work visible and reproducible.

Deliverables:

- Update `docs/sdk_domain_coverage_matrix.md`, `docs/api_reference.md`,
  `docs/example_port_mapping_bindings.md`, and relevant quickstarts.
- Add or update an example that mirrors the codedump flows without depending
  on the codedump repository.
- Add a migration checklist mapping each row of `IDAX_GAPS.md` to an idax API.

Acceptance:

- C++ API surface parity target passes.
- All locally runnable C++ tests pass.
- Any host-gated Hex-Rays/UI tests report clear skip reasons when not runnable.

## Suggested order

1. P22.5 `idb_path` / `ask_text` / clipboard helpers where low risk.
2. P22.2 wait box RAII.
3. P22.3 Hex-Rays popup event.
4. P22.4 Local Types action context.
5. P22.6 lvar snapshot and prototype apply.
6. P22.1 typed forms and builder.
7. P22.7 ctree migration helpers.
8. P22.8 docs and validation sweep.
