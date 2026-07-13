# Validation Report

Date: 2026-02-15 (base report; API-surface namespace count updated 2026-05-28 after Phase 22 checks)

## Test suite summary

- Unit: `idax_unit_test` -> pass (22/22)
- API surface parity: `idax_api_surface_check` -> pass (compile-time, 28 namespaces verified)
- Integration smoke: `idax_smoke_test` -> pass (232/232)
- Debugger/UI/graph/event: `idax_debugger_ui_graph_event_test` -> pass (60/60)
- Loader/processor scenario: `idax_loader_processor_scenario_test` -> pass (all checks)
- Name/comment/xref/search behavior: pass
- Data mutation safety: pass
- Segment/function edge cases: pass
- Instruction decode behavior: pass
- Type roundtrip: pass
- Fixup relocation: pass
- Operand and text: pass
- Decompiler/storage hardening: pass
- Decompiler edge cases: pass
- Event stress: pass
- Performance benchmark: pass
- Matrix automation script: `full`, `unit`, and `compile-only` profiles pass on macOS arm64
- Matrix example addon compile coverage: `IDAX_BUILD_EXAMPLES=ON` + `IDAX_BUILD_EXAMPLE_ADDONS=ON` validated locally for `compile-only` and `unit`
- Hosted validation matrix (provided log bundle): all jobs passed for Linux/macOS `compile-only` + `unit`, plus Windows `compile-only`
- Matrix full+packaging profile: pass (`build-matrix-full-pack/idax-0.1.0-Darwin.tar.gz`)
- Open-point closure sweep (`scripts/run_open_points.sh`): full matrix pass,
  lumina smoke pass, appcall smoke blocked by debugger backend/session
  readiness even after backend auto-selection + request-path fallbacks
  with bounded request-settle cycles (`start_process` `0` + `request_start`
  no-process, `attach_process` `-1` + `request_attach` no-process)
  (`build-open-points-surge6/logs/*`)
- Consistency audit: 0 SDK type leaks in public headers
- Packaging check: `idax-0.1.0-Darwin.tar.gz` (lib + headers + cmake config)

**Total: 16/16 CTest targets pass**

## Scenario coverage highlights

- Address/data/database flows
- Name/comment/xref/search behaviors
- Segment/function/type/fixup traversals and mutations, including function prototype application
- Instruction decode/render/operand representation
- Loader base class, helper functions, value types
- Processor base class, metadata, switch detection types, optional callbacks
- Plugin action types, handler execution, and Local Types `TypeRef` context payloads
- Loader/procmod/plugin example addon builds
- Debugger event subscription lifecycle (all 11 event types)
- UI event subscriptions (5 event types + ScopedSubscription RAII)
- Graph object operations (node/edge/group/path/clear/move semantics)
- Flowchart generation from function addresses
- Event typed subscriptions + generic routing + filtered routing
- Decompiler pseudocode/ctree/comment/address mapping scenarios, including lvar comment snapshot/restore and read-only ctree helper/parent coverage
- Decompiler edge cases: multi-function, variable classification, ctree diversity, rename roundtrip
- Storage alt/sup/hash/blob operations
- Event stress: concurrent subscribers, rapid sub/unsub, multi-event fan-out
- Performance benchmarks: decode throughput, function iteration, pattern search, decompile latency

## Platform/compiler matrix (current pass)

- macOS arm64, AppleClang 17, default profile: pass (16/16)
- macOS arm64, AppleClang 17, RelWithDebInfo profile: pass (16/16)
- macOS arm64, AppleClang 17, Release profile: pass (16/16)
- Linux x86_64, GCC 13.3.0, RelWithDebInfo compile-only (GitHub Actions): pass (`job-logs1.txt`)
- Linux x86_64, GCC 13.3.0, RelWithDebInfo unit (GitHub Actions): pass, 2/2 (`job-logs4.txt`)
- macOS arm64, AppleClang 15.0.0.15000309, RelWithDebInfo compile-only (GitHub Actions): pass (`job-logs2.txt`)
- macOS arm64, AppleClang 15.0.0.15000309, RelWithDebInfo unit (GitHub Actions): pass, 2/2 (`job-logs5.txt`)
- Windows x64, MSVC 19.44.35222.0, RelWithDebInfo compile-only (GitHub Actions): pass (`job-logs3.txt`)
- Linux x86_64, GCC 13.3.0, RelWithDebInfo compile-only: pass (`build-matrix-linux-gcc-docker/`)
- Linux x86_64, Clang 18.1.3, RelWithDebInfo compile-only: fail (baseline container run fails because `std::expected` is unavailable with this compiler/libstdc++ pairing; see `build-matrix-linux-clang18-amd64-baseline/`)
- Linux x86_64, Clang 19.1.1, RelWithDebInfo compile-only: pass (baseline container run with `IDAX_BUILD_EXAMPLE_ADDONS=OFF` and `IDAX_BUILD_EXAMPLE_TOOLS=OFF`; see `build-matrix-linux-clang19-amd64-baseline/`)

Remaining runtime-dependent `full` Linux/Windows rows and command profiles are
tracked in `docs/compatibility_matrix.md`.

## Recent focused validation

- 2026-05-31 ida-trida port and rich type metadata parity:
  Added opaque rich `ida::type` metadata for TypeInfo kind/name/declaration,
  function details, enum details, UDT details, and member bit-layout flags;
  mirrored the surface through Node and Rust bindings; and ported
  `<dev-root_>/ida-trida` to consume idax for plugin actions/forms/wait/path/
  clipboard plus generator type walking. Validation passed:
  `cmake --build build-test-fetch --target idax_api_surface_check idax_type_roundtrip_test -j2`,
  `./build-test-fetch/tests/integration/idax_type_roundtrip_test build-test-fetch/_deps/ida_sdk-src/src/plugins/idapython/examples/debugger/appcall/test_programs/simple_appcall/simple_appcall_linux64`
  (209/209 checks), `env IDASDK=<dev-root_>/idax/build-test-fetch/_deps/ida_sdk-src/src npm run build`,
  `env IDASDK=<dev-root_>/idax/build-test-fetch/_deps/ida_sdk-src/src npm test`
  (183/183 checks), `env -u IDASDK cargo test -p idax types_tests --lib`,
  `env -u IDASDK cargo test -p idax --lib --no-run`, and
  `IDASDK=<userhome>/ida-sdk cmake -S . -B build-idax -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFETCHCONTENT_SOURCE_DIR_IDAX=<dev-root_>/idax`
  plus `cmake --build build-idax -j2` from `<dev-root_>/ida-trida`.
- 2026-05-31 clipboard fallback availability:
  `cmake --build build-test-fetch --target idax_api_surface_check -j2`
  passed after adding external clipboard-command fallback and backend
  detection. `scripts/check_codedump_parity_evidence_log.sh --self-test` and
  `git diff --check` passed. The host has working `xclip` clipboard access
  (`xclip` write/read/restore roundtrip passed). The mirrored ida-cdump cached
  idax dependency also rebuilt successfully with
  `IDASDK=<dev-root_>/ida-cdump/build/_deps/ida_sdk-src cmake --build build
  -j2` from `<dev-root_>/ida-cdump`.
- 2026-05-28 P22.10 bulk type declaration import:
  `cmake --build build-test-fetch --target idax_api_surface_check idax_type_roundtrip_test -j2`
  passed.
- 2026-05-28 P22.10 bulk type declaration import:
  `ctest --test-dir build-test-fetch -R 'api_surface_parity|type_roundtrip' --output-on-failure`
  passed.
- 2026-05-28 Node structural bindings:
  `npm test` in `bindings/node` now passes with the native addon loaded after
  the Node native build fix recorded below.
- 2026-05-28 Rust targeted no-run:
  `env -u IDASDK cargo test -p idax --lib --no-run` and
  `env -u IDASDK cargo test -p idax types_parse_declarations --test integration --no-run`
  pass after repairing the generated recursive microcode instruction binding.
- 2026-05-28 P22.9 scoped Hex-Rays example lifecycle:
  `env -u IDASDK cmake -S . -B build-examples-fetch -DIDAX_BUILD_EXAMPLES=ON -DIDAX_BUILD_EXAMPLE_ADDONS=ON -DIDAX_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo`
  followed by
  `cmake --build build-examples-fetch --target idax_abyss_port_plugin -j2`
  passed.
- 2026-05-28 P22 host-gated UI/runtime harness:
  reconfigured `build-test-fetch`, built
  `idax_codedump_parity_host_gates_test`, and ran
  `ctest --test-dir build-test-fetch -R codedump_parity_host_gates --output-on-failure`.
  The default run passed with deterministic skips for interactive modal,
  Qt clipboard, and Hex-Rays ownership runtime paths unless
  `IDAX_RUN_MODAL_FORMS=1`, `IDAX_RUN_QT_CLIPBOARD=1`, or
  `IDAX_RUN_HEXRAYS_SESSION=1` is set.
- 2026-05-28 P22 Hex-Rays scoped-session host gate:
  `env IDAX_RUN_HEXRAYS_SESSION=1 IDADIR=<userhome>/ida-pro-9.3 build-test-fetch/tests/integration/idax_codedump_parity_host_gates_test tests/fixtures/simple_appcall_linux64`
  passed with 9 checks, 0 failures, and only the modal/Qt clipboard gates
  skipped. The fixture was restored afterward.
- 2026-05-28 P22.8 compact parity example:
  reconfigured `build-examples-fetch` and built
  `idax_codedump_parity_probe_plugin`, covering the compile path for typed
  forms, wait boxes, clipboard fallback, scoped Hex-Rays ownership,
  pseudocode popup attachment, Local Types `type_ref`, lvar snapshots, and
  prototype reapply in one independent example.
- 2026-05-28 Qt example build bridge:
  split the `qtform_renderer` and `drawida` plugin glue through non-Qt bridge
  headers so the plugin translation units no longer include Qt headers beside
  `ida/idax.hpp`. `env -u IDASDK cmake --build build-examples-fetch --target
  idax_qtform_renderer_plugin idax_drawida_port_plugin -j2` passed, closing
  the local Qt/IDA global `q*` helper conflict.
- 2026-05-28 P22 Qt clipboard build gate:
  `env -u IDASDK cmake -S . -B build-test-qt-clipboard -DIDAX_BUILD_TESTS=ON -DIDAX_ENABLE_QT_CLIPBOARD=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo`
  now fails early with an actionable requirement for an IDA-compatible Qt6
  package built with `QT_NAMESPACE=QT`. This prevents the previous mixed
  system-Qt/IDA-Qt link failure and leaves clipboard runtime evidence pending
  until that Qt package and an interactive IDA Qt host are available.
- 2026-05-28 P22 host-gate runner:
  `scripts/run_codedump_parity_host_gates.sh` builds and runs the
  `idax_codedump_parity_host_gates_test` target with the documented
  `IDAX_RUN_MODAL_FORMS`, `IDAX_RUN_QT_CLIPBOARD`,
  `IDAX_ENABLE_QT_CLIPBOARD`, and `IDAX_QT6_DIR` controls. The default
  non-interactive run passed with 3 checks, 0 failures, and 3 skips. Running
  the same script with `IDAX_RUN_HEXRAYS_SESSION=1` and
  `IDADIR=<userhome>/ida-pro-9.3` passed with 9 checks, 0 failures, and 2
  skips; the default `.i64` fixture was restored afterward. Modal and Qt
  clipboard proof still require an interactive IDA Qt host.
- 2026-05-28 P22 host-gate runner refresh:
  After the additional binding parity closures, reran
  `env -u IDASDK scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host tests/fixtures/simple_appcall_linux64 RelWithDebInfo`
  and the default path passed with 3 checks, 0 failures, and 3 expected skips.
  Reran
  `env -u IDASDK IDADIR=<userhome>/ida-pro-9.3 IDAX_RUN_HEXRAYS_SESSION=1 scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host tests/fixtures/simple_appcall_linux64 RelWithDebInfo`;
  the Hex-Rays scoped-session path passed with 9 checks, 0 failures, and 2
  expected skips, and the runner restored the default `.i64` fixture.
- 2026-05-28 P22 focused C++ parity refresh:
  `env -u IDASDK cmake --build build-test-fetch --target idax_api_surface_check idax_unit_test idax_codedump_parity_host_gates_test -j2`
  passed, followed by
  `ctest --test-dir build-test-fetch -R '^idax_unit_test$|api_surface_parity|codedump_parity_host_gates' --output-on-failure`
  passing all 3 selected tests.
- 2026-05-28 P22 typed-form audited-pack unit coverage:
  `tests/unit/core_unit_test.cpp` now checks the non-modal builder markup for
  the audited ida-cdump dialog packs: three `sval_t` + path + two bitsets,
  `sval_t` + path + bitset, `sval_t` + bitset, radio + `sval_t` + path +
  bitset, and path + bitset. `env -u IDASDK cmake --build build-test-fetch
  --target idax_unit_test -j2 && ctest --test-dir build-test-fetch -R
  '^idax_unit_test$' --output-on-failure` passed.
- 2026-05-28 Rust UI binding surface closure:
  `bindings/rust/idax/src/tests.rs` now compile-checks the safe Rust
  typed-form result structs and function signatures for all fixed ida-cdump
  dialog packs, plus `ask_text`, `WaitBox`, and clipboard helper signatures,
  without invoking modal UI. The Rust `qtform_renderer_plugin` adaptation now
  correctly reports `ui::ask_form` as available but host-modal.
  `env -u IDASDK cargo test -p idax ui_tests --lib --no-run`,
  `env -u IDASDK cargo test -p idax --lib --no-run`, and
  `env -u IDASDK cargo check -p idax --example qtform_renderer_plugin`
  passed from `bindings/rust`.
- 2026-05-28 Rust typed-form validation evidence:
  Hardened Rust fixed typed-form wrappers so empty markup is rejected as
  `Validation` before entering the modal/FFI path, and added
  `ui_tests::test_codedump_typed_forms_reject_empty_markup_without_modal_ui`
  for every audited ida-cdump form shape. `env -u IDASDK cargo test -p idax
  ui_tests::test_codedump_typed_forms_reject_empty_markup_without_modal_ui --lib`,
  `env -u IDASDK cargo test -p idax ui_tests --lib --no-run`, and
  `env -u IDASDK cargo test -p idax --lib --no-run` pass from
  `bindings/rust`.
- 2026-05-28 Node UI binding smoke:
  `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm
  test` passed from `bindings/node`, loading the native addon and confirming
  structural assertions including `WaitBox`, `askText`, the UI clipboard, and
  fixed typed-form entrypoints. The UI assertions also exercise non-modal
  runtime behavior: `askText` argument-shape validation, clipboard backend
  contract behavior, and empty-markup validation failures for each fixed
  typed-form entrypoint. Current result: 175/175 passed.
- 2026-05-28 Node/Rust path binding parity:
  Node now exposes `path.basename`, `path.dirname`, and `path.isDirectory`;
  Rust now exposes `path::{basename, dirname, is_directory}` over the same
  `ida::path` helpers. `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm test`
  passed from `bindings/node` with 180/180 assertions, and
  `env -u IDASDK cargo test -p idax path_tests --lib` passed from
  `bindings/rust` with 2/2 path assertions.
- 2026-05-28 Node/Rust scoped Hex-Rays session binding parity:
  Node now exposes `decompiler.initialize()` returning a `ScopedSession`
  wrapper with `valid()` and `close()`, and Rust now exposes
  `decompiler::initialize() -> ScopedSession` with RAII `Drop` release.
  `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm run build`
  and `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm test`
  passed from `bindings/node`; the Node structural suite remains 180/180.
  `env -u IDASDK cargo test -p idax decompiler_tests --lib --no-run`,
  `env -u IDASDK cargo test -p idax decompiler_tests::test_scoped_session_function_signatures --lib`,
  and `env -u IDASDK cargo test -p idax --lib --no-run` passed from
  `bindings/rust`.
- 2026-05-28 Node native build and runtime bindings:
  `npm install --ignore-scripts` installed local dependencies,
  `npm install nan@^2.27.0 --save --ignore-scripts` upgraded NAN for local
  Node 26 headers, and
  `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm run build`
  passed. `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm test`
  then loaded the native addon and passed 170/170 unit assertions without the
  previous native-addon skip. `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src IDADIR=<userhome>/ida-pro-9.3 npm run test:integration -- ../../tests/fixtures/simple_appcall_linux64`
  passed 63/63 integration assertions.
- 2026-05-28 P22.8 focused validation sweep:
  `cmake --build build-test-fetch --target idax_api_surface_check idax_unit_test idax_decompiler_storage_hardening_test idax_segment_function_edge_cases_test -j2`
  and
  `ctest --test-dir build-test-fetch -R '^idax_unit_test$|api_surface_parity|decompiler_storage_hardening|segment_function_edge_cases|codedump_parity_host_gates' --output-on-failure`
  passed across the locally runnable C++ targets. Node native build/unit and
  fixture integration validation pass locally. Rust high-level no-run
  validation passes locally.
- 2026-05-28 P22 concrete task/evidence mapping:
  Re-read `<userhome>/dev/ida-cdump/docs/IDAX_GAPS.md` and expanded
  `docs/codedump_parity_tasks.md` with an idax implementation matrix for
  P22.1-P22.10, plus explicit host-only P22.H1/P22.H2 and final validation
  P22.V1 rows. `docs/codedump_migration_checklist.md` now includes an evidence
  map tying each gap to C++ proof, binding proof, and any remaining host gate.
- 2026-05-28 Rust lvar/prototype binding evidence:
  Added focused Rust unit signature checks for `function::set_prototype`,
  `function::apply_decl`, `DecompiledFunction`/`DecompilerView` lvar snapshot
  capture/restore, variable comment setters, and `LvarSnapshot` accessors.
  `env -u IDASDK cargo test -p idax function_tests::test_prototype_apply_function_signatures --lib`
  and
  `env -u IDASDK cargo test -p idax decompiler_tests::test_lvar_snapshot_and_comment_function_signatures --lib`
  pass from `bindings/rust`; `env -u IDASDK cargo test -p idax --lib --no-run`
  also passes.
- 2026-05-28 Node decompiler metadata binding evidence:
  Extended the Node fixture integration decompile path to assert the
  `DecompiledFunction` metadata methods added for P22 (`declaration`,
  `variableCount`, `variables`, stable `variable(index)`,
  `captureUserLvarSettings`, `restoreUserLvarSettings`,
  `setVariableComment`, `forEachExpression`, and `forEachItem`) plus the
  returned `LvarSnapshot` method shape. `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src IDADIR=<userhome>/ida-pro-9.3 npm run test:integration -- ../../tests/fixtures/simple_appcall_linux64`
  passes from `bindings/node` with 63/63 integration checks, and the fixture
  remains clean afterward. `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm test`
  also passes with 180/180 unit checks.
- 2026-05-28 Bulk declaration binding evidence:
  Added Node unit validation that `type.parseDeclarations` rejects an empty
  declaration block before SDK import, and Rust unit coverage for
  `types::parse_declarations` signature, options, and report semantics.
  `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm test`
  passes from `bindings/node` with 182/182 unit checks, and
  `env -u IDASDK cargo test -p idax types_tests::test_parse_declarations_function_signature_and_report --lib`
  passes from `bindings/rust`.
- 2026-05-28 Hex-Rays popup binding evidence:
  Added Node unit validation for the `decompiler.onPopulatingPopup` callback
  argument shape and Rust compile-time callback signature coverage in
  `decompiler_tests::test_populating_popup_event_defaults`. `env -u IDASDK
  cargo test -p idax decompiler_tests::test_populating_popup_event_defaults --lib`
  passes from `bindings/rust`; the Node check is covered by the 182/182 unit
  run above. `env -u IDASDK cargo test -p idax --lib --no-run` also passes
  after the additional signature coverage.
- 2026-05-28 Read-only ctree binding evidence:
  Extended the Node fixture decompile integration path to inspect
  `forEachExpression` and `forEachItem` callback payload fields, including
  `variableIndex`, `helperName`, `typeDeclaration`, `parent`, and
  `parentDepth`, and added Rust unit coverage for `ExpressionInfo`,
  `StatementInfo`, `CtreeItemInfo`, and visitor function signatures.
  `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src IDADIR=<userhome>/ida-pro-9.3 npm run test:integration -- ../../tests/fixtures/simple_appcall_linux64`
  passes from `bindings/node` with 63/63 integration checks, and
  `env -u IDASDK cargo test -p idax decompiler_tests::test_ctree_callback_payload_shapes --lib`
  passes from `bindings/rust`.
- 2026-05-28 Local Types action-context binding evidence:
  Added an internal Rust plugin bridge test for the `ActionContext::type_ref`
  FFI shape, complementing the safe `TypeRef` construction test. The test
  checks that a Rust action context with a `type_ref` exposes the Local Types
  name through the FFI action-context payload and that an FFI context without a
  type handle maps back to `None`. `env -u IDASDK cargo test -p idax
  plugin::tests::action_context_type_ref_is_exposed_in_ffi_shape --lib` passes,
  and `env -u IDASDK cargo test -p idax --lib --no-run` remains green.
- 2026-05-28 Rust clipboard binding evidence:
  Hardened Rust `ui::{copy_to_clipboard,read_clipboard}` so the default
  native `unsupported` backend maps failed clipboard operations to
  `ErrorCategory::Unsupported` even if the FFI error slot is empty, and added
  clipboard wrapper validation for embedded-NUL input plus unsupported-backend
  error mapping when no backend is available.
  `env -u IDASDK cargo test -p idax ui_tests::test_clipboard_default_contract_and_validation --lib`
  and `env -u IDASDK cargo test -p idax --lib --no-run` pass from
  `bindings/rust`.
- 2026-05-28 P22.V1 final local validation refresh:
  Focused C++ parity build passed with `env -u IDASDK cmake --build
  build-test-fetch --target idax_api_surface_check idax_unit_test
  idax_codedump_parity_host_gates_test idax_decompiler_storage_hardening_test
  idax_segment_function_edge_cases_test idax_type_roundtrip_test -j2`.
  Focused CTest passed with `ctest --test-dir build-test-fetch -R
  '^idax_unit_test$|api_surface_parity|codedump_parity_host_gates|decompiler_storage_hardening|segment_function_edge_cases|type_roundtrip'
  --output-on-failure`.
  Host-gate runner default passed with 3 checks, 0 failures, and 3 expected
  skips; the locally available `IDAX_RUN_HEXRAYS_SESSION=1` run passed with 9
  checks, 0 failures, and 2 expected skips. Node native build/unit/integration
  passed with `npm run build`, `npm test` (182/182), and
  `npm run test:integration -- ../../tests/fixtures/simple_appcall_linux64`
  (63/63). Rust passed
  `env -u IDASDK cargo test -p idax
  ui_tests::test_codedump_typed_forms_reject_empty_markup_without_modal_ui --lib`,
  `env -u IDASDK cargo test -p idax --lib --no-run`, and
  `env -u IDASDK cargo test -p idax types_parse_declarations --test integration
  --no-run`. Remaining evidence is host-only: interactive modal typed forms and
  Qt clipboard with an IDA-compatible `QT_NAMESPACE=QT` Qt package.
- 2026-05-28 P22 host-evidence workflow hardening:
  Added `docs/codedump_host_evidence.md` with explicit P22.H1/P22.H2 host-run
  commands, expected evidence criteria, and validation-report recording rules.
  `scripts/run_codedump_parity_host_gates.sh` now supports
  `IDAX_EVIDENCE_LOG` and records configure/build/run output to the requested
  log path. `env -u IDASDK IDAX_EVIDENCE_LOG=build-codedump-parity-host/codedump-host-default.log
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/simple_appcall_linux64 RelWithDebInfo` passed with 3 checks,
  0 failures, and 3 expected skips. The Qt runtime preflight now fails before
  CMake when `IDAX_RUN_QT_CLIPBOARD=1 IDAX_ENABLE_QT_CLIPBOARD=ON` is set
  without `IDAX_QT6_DIR`, preserving the requirement for an IDA-compatible
  `QT_NAMESPACE=QT` Qt package.
- 2026-05-28 binding documentation parity refresh:
  `bindings/node/agents.md` now documents the `idax.ui` parity surface,
  fixed typed-form entrypoints, clipboard backend behavior, bulk declaration
  import, lvar snapshot/comment helpers, ctree callback hooks, and
  `onPopulatingPopup`. `bindings/rust/idax/README.md` now has an ida-cdump
  parity section that names the Rust fixed-form, UI, clipboard, decompiler,
  type-import, database, and path surfaces plus their host-runtime caveats.
  `env IDASDK=<userhome>/dev/idax/build-test-fetch/_deps/ida_sdk-src/src npm
  test` passes from `bindings/node` with 182/182 checks, and
  `env -u IDASDK cargo test -p idax
  ui_tests::test_codedump_typed_forms_reject_empty_markup_without_modal_ui --lib`
  plus `env -u IDASDK cargo test -p idax --lib --no-run` pass from
  `bindings/rust`.
- 2026-05-28 P22 host-evidence log verifier:
  Added `scripts/check_codedump_parity_evidence_log.sh` so default, Hex-Rays,
  modal typed-form, and Qt clipboard host-gate logs can be checked before
  closing P22.H1/P22.H2. `scripts/check_codedump_parity_evidence_log.sh
  build-codedump-parity-host/codedump-host-default.log default` passes against
  the current default evidence log. The verifier now requires the relevant
  host-gated section headers for default, Hex-Rays, modal, and Qt clipboard
  modes plus the default clipboard-backend section, so a bare success summary
  cannot close a host gate. It also requires minimum modal/Qt pass counts,
  matching an accepted modal form and a clipboard write/read roundtrip.
  Synthetic validation confirms that it accepts strong unskipped modal/Qt
  sections and rejects skipped, missing, or weak-pass modal/Qt sections plus
  missing default clipboard and Hex-Rays sections. The self-test now also
  rejects failed summaries, unknown gate names, and skipped Hex-Rays evidence.
  `scripts/check_codedump_parity_evidence_log.sh --self-test` codifies those
  cases and passes.
- 2026-05-28 P22 modal evidence acceptance hardening:
  `tests/integration/codedump_parity_host_gates_test.cpp` now requires the
  codedump-shaped modal form to be accepted when `IDAX_RUN_MODAL_FORMS=1` is
  set; a cancelled dialog fails the host evidence run instead of looking like
  closure. `cmake --build build-test-fetch --target
  idax_codedump_parity_host_gates_test -j2` passed, `ctest --test-dir
  build-test-fetch -R codedump_parity_host_gates --output-on-failure` passed,
  and `env -u IDASDK IDAX_EVIDENCE_LOG=build-codedump-parity-host/codedump-host-default.log
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/simple_appcall_linux64 RelWithDebInfo` refreshed the default
  evidence log with 3 checks, 0 failures, and 3 expected skips. The hardened
  default verifier accepts that log.
- 2026-05-28 P22 host runner fixture preflight:
  `scripts/run_codedump_parity_host_gates.sh` now canonicalizes and validates
  the fixture path before CMake configure/build work. With
  `IDAX_RUN_HEXRAYS_SESSION=1`, a missing fixture fails immediately with an
  explicit fixture error instead of surfacing later as a configure or runtime
  issue. `env -u IDASDK IDAX_RUN_HEXRAYS_SESSION=1
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/does-not-exist RelWithDebInfo` exits nonzero with the
  intended message, while `env -u IDASDK
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/simple_appcall_linux64 RelWithDebInfo` still passes with 3
  checks, 0 failures, and 3 expected skips. The consolidated
  `scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` sweep also passes after the preflight change.
- 2026-05-28 P22 host runner evidence auto-verification:
  When `IDAX_EVIDENCE_LOG` is set,
  `scripts/run_codedump_parity_host_gates.sh` now infers the enabled
  evidence modes from `IDAX_RUN_MODAL_FORMS`, `IDAX_RUN_QT_CLIPBOARD`, and
  `IDAX_RUN_HEXRAYS_SESSION`, then runs
  `scripts/check_codedump_parity_evidence_log.sh` after the run output has
  been fully captured. With no opt-in gates it verifies the log in `default`
  mode. `env -u IDASDK
  IDAX_EVIDENCE_LOG=build-codedump-parity-host/codedump-host-default.log
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/simple_appcall_linux64 RelWithDebInfo` passes and records the
  automatic `default` verifier result in the log. A logged missing-fixture run
  still exits nonzero with the intended preflight error. The consolidated
  `scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` sweep passes with the race-free auto-verifying runner.
- 2026-05-28 P22 composable evidence verifier:
  `scripts/check_codedump_parity_evidence_log.sh` now accepts stronger
  combined host-gate summaries for non-default modes. Hex-Rays evidence still
  requires the Hex-Rays section to be present and unskipped, but it now
  accepts 9-or-more passed checks with zero failures so a single modal + Qt +
  Hex-Rays run can verify all enabled gates. The verifier self-test includes a
  synthetic combined 14-pass/0-failure/0-skip log that passes `hexrays`,
  `modal`, and `qt-clipboard` modes, plus a weak 8-pass Hex-Rays log that
  fails as intended. `scripts/check_codedump_parity_evidence_log.sh
  --self-test` and the consolidated local validation sweep both pass.
- 2026-05-28 P22 Hex-Rays auto-verifying host evidence:
  Reran the locally available scoped Hex-Rays gate through the race-free
  auto-verifying runner:
  `env -u IDASDK IDADIR=<userhome>/ida-pro-9.3 IDAX_RUN_HEXRAYS_SESSION=1
  IDAX_EVIDENCE_LOG=build-codedump-parity-host/codedump-host-hexrays.log
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/simple_appcall_linux64 RelWithDebInfo`. The run passed with
  9 checks, 0 failures, and 2 expected skips, restored the default `.i64`
  fixture, and appended automatic `hexrays` verifier output to the evidence
  log. An explicit
  `scripts/check_codedump_parity_evidence_log.sh
  build-codedump-parity-host/codedump-host-hexrays.log hexrays` also passes.
- 2026-05-28 P22 local validation runner:
  Added `scripts/run_codedump_parity_local_validation.sh` to refresh focused
  C++ parity targets/CTest, default host-gate evidence and verifier checks,
  Node native build/unit coverage, optional Node fixture integration, and Rust
  typed-form/no-run coverage with one command. `scripts/run_codedump_parity_local_validation.sh
  build-test-fetch RelWithDebInfo` passes with Node integration skipped after
  the section-presence verifier hardening, and
  `env IDAX_RUN_NODE_INTEGRATION=1 IDADIR=<userhome>/ida-pro-9.3
  scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` passes including the 63/63 Node fixture integration checks.
  The runner restores the default `.i64` fixture when local host runs dirty it.
- 2026-05-28 P22 current full local parity sweep:
  Reran `env IDAX_RUN_NODE_INTEGRATION=1 IDADIR=<userhome>/ida-pro-9.3
  scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` after the composable verifier and race-free logged runner
  changes. The sweep passed focused C++ build/CTest (6/6 selected tests),
  default host-gate evidence with automatic default verifier output, verifier
  self-test, compact parity probe example build, Node native build/unit
  coverage (182/182), Node fixture integration (63/63), Rust typed-form
  validation, Rust library no-run, and Rust type-declaration integration
  no-run.
- 2026-05-28 P22 lower-level migration cleanup audit:
  Reconciled the updated ida-cdump notes for remaining `get_func`,
  `decode_insn`, comment/name/type, path, and bulk declaration SDK calls with
  existing idax APIs. These are now recorded as downstream migration cleanup in
  `docs/codedump_parity_tasks.md` and `docs/codedump_migration_checklist.md`,
  not as missing idax parity surfaces.
  `scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` passes after the classification update, covering focused C++
  build/CTest (6/6 selected tests), default host-gate evidence with verifier,
  verifier self-test, compact parity probe example build, Node native
  build/unit coverage (182/182), Rust typed-form validation, Rust library
  no-run, and Rust type-declaration integration no-run. Node fixture
  integration was skipped for this refresh because `IDAX_RUN_NODE_INTEGRATION`
  was not set.
- 2026-05-28 P22 local validation host-mode support:
  `scripts/run_codedump_parity_local_validation.sh` now infers the same host
  evidence modes as `scripts/run_codedump_parity_host_gates.sh` and writes
  mode-specific logs for opt-in gates. `env IDAX_RUN_HEXRAYS_SESSION=1
  IDADIR=<userhome>/ida-pro-9.3
  scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` passes, including focused C++ build/CTest (6/6 selected
  tests), Hex-Rays host evidence with automatic and explicit `hexrays`
  verifier output, compact parity probe example build, Node native build/unit
  coverage (182/182), Rust typed-form validation, Rust library no-run, and Rust
  type-declaration integration no-run. The default path also passes with
  `scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo`, including default host evidence verification.
- 2026-05-28 P22 local validation mode self-test:
  Added `scripts/run_codedump_parity_local_validation.sh --self-test` for
  default, modal, Qt clipboard, Hex-Rays, and combined host-evidence mode
  inference. `bash -n scripts/run_codedump_parity_local_validation.sh
  scripts/run_codedump_parity_host_gates.sh
  scripts/check_codedump_parity_evidence_log.sh`,
  `scripts/run_codedump_parity_local_validation.sh --self-test`,
  `scripts/check_codedump_parity_evidence_log.sh --self-test`, and current
  default/Hex-Rays evidence-log verification all pass.
  `scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` also passes the full default local sweep after the self-test
  addition.
- 2026-05-28 P22 evidence verifier negative coverage:
  Expanded `scripts/check_codedump_parity_evidence_log.sh --self-test` to
  reject failed summaries, contaminated mixed failed+successful summaries,
  unknown gate names, and skipped Hex-Rays evidence in addition to missing
  sections, weak pass counts, and skipped modal/Qt sections. `bash -n
  scripts/check_codedump_parity_evidence_log.sh
  scripts/run_codedump_parity_host_gates.sh
  scripts/run_codedump_parity_local_validation.sh`,
  `scripts/check_codedump_parity_evidence_log.sh --self-test`,
  `scripts/run_codedump_parity_host_gates.sh --self-test`,
  `scripts/run_codedump_parity_local_validation.sh --self-test`, and current
  default/Hex-Rays evidence-log verification all pass. The Qt clipboard gate
  still fails before CMake with the intended `IDAX_QT6_DIR` requirement when
  requested as `IDAX_RUN_QT_CLIPBOARD=1 IDAX_ENABLE_QT_CLIPBOARD=ON` without a
  namespaced Qt package.
- 2026-05-28 P22 host-gate runner mode self-test:
  Refactored `scripts/run_codedump_parity_host_gates.sh` so auto-verification
  uses a shared host-evidence mode inference helper, and added
  `scripts/run_codedump_parity_host_gates.sh --self-test` for default, modal,
  Qt clipboard, Hex-Rays, and combined mode inference without configuring or
  building. `bash -n scripts/run_codedump_parity_host_gates.sh
  scripts/run_codedump_parity_local_validation.sh
  scripts/check_codedump_parity_evidence_log.sh`,
  `scripts/run_codedump_parity_host_gates.sh --self-test`,
  `scripts/run_codedump_parity_local_validation.sh --self-test`, and
  `scripts/check_codedump_parity_evidence_log.sh --self-test` all pass.
  `scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` also passes the full default local sweep after the preflight
  self-test expansion.
  Refreshed default evidence with `env -u IDASDK
  IDAX_EVIDENCE_LOG=build-codedump-parity-host/codedump-host-default.log
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/simple_appcall_linux64 RelWithDebInfo`, and refreshed
  Hex-Rays evidence with `env -u IDASDK IDADIR=<userhome>/ida-pro-9.3
  IDAX_RUN_HEXRAYS_SESSION=1
  IDAX_EVIDENCE_LOG=build-codedump-parity-host/codedump-host-hexrays.log
  scripts/run_codedump_parity_host_gates.sh build-codedump-parity-host
  tests/fixtures/simple_appcall_linux64 RelWithDebInfo`; both runs append the
  expected verifier output.
- 2026-05-28 P22 host runner preflight self-test:
  Expanded `scripts/run_codedump_parity_host_gates.sh --self-test` so it also
  proves no-build failures for missing `IDAX_QT6_DIR`, a nonexistent
  `IDAX_QT6_DIR` path, and a missing Hex-Rays fixture. `bash -n
  scripts/run_codedump_parity_host_gates.sh
  scripts/run_codedump_parity_local_validation.sh
  scripts/check_codedump_parity_evidence_log.sh`,
  `scripts/run_codedump_parity_host_gates.sh --self-test`,
  `scripts/run_codedump_parity_local_validation.sh --self-test`, and
  `scripts/check_codedump_parity_evidence_log.sh --self-test` all pass.
- 2026-05-28 P22 evidence verifier contaminated-log rejection:
  Hardened `scripts/check_codedump_parity_evidence_log.sh` to reject any
  `codedump_parity_host_gates_test` summary with a nonzero failure count before
  accepting a matching successful summary. The verifier self-test now includes
  a contaminated log containing both failed and successful default summaries
  and rejects it. `bash -n scripts/check_codedump_parity_evidence_log.sh
  scripts/run_codedump_parity_host_gates.sh
  scripts/run_codedump_parity_local_validation.sh`,
  `scripts/check_codedump_parity_evidence_log.sh --self-test`,
  `scripts/run_codedump_parity_host_gates.sh --self-test`,
  `scripts/run_codedump_parity_local_validation.sh --self-test`, and current
  default/Hex-Rays evidence-log verification all pass.
- 2026-05-28 P22 concrete remaining implementation tasks:
  Reconciled the updated `<userhome>/dev/ida-cdump/docs/IDAX_GAPS.md` notes
  against current idax implementation state and converted the remaining queue
  into concrete closure subtasks: P22.H1.1-H1.3 for accepted modal typed-form
  evidence, P22.H2.1-H2.3 for Qt clipboard evidence with an IDA-compatible
  `QT_NAMESPACE=QT` Qt package, and P22.V1.1-V1.2 for final local validation
  and documentation refresh. The follow-up ida-cdump port audit then identified
  concrete residual C++ API tasks P22.R1-P22.R4 for processor operand access
  metadata, type dependency traversal, ctree/type collection snapshots,
  and serializable lvar locator metadata. P22.R5 graph recovery switch
  metadata was subsequently implemented with `ida::graph::switch_table`.
- 2026-05-28 P22.R1 processor operand metadata closure:
  Added `ida::instruction::Operand::is_read()` / `is_written()` metadata from
  canonical processor operand feature bits and migrated ida-cdump
  `analysis/register_analyzer.cpp` to `ida::instruction::decode()` without
  raw `insn_t`, `decode_insn`, `get_canon_feature`, `has_cf_use`,
  `has_cf_chg`, `get_dtype_size`, or `get_reg_name`. Verified with
  `cmake --build build-test-fetch --target idax_api_surface_check -j2` and
  `IDASDK=<dev-root_>/ida-cdump/build/_deps/ida_sdk-src cmake --build build -j2`.
- 2026-05-28 P22.R4 lvar locator metadata closure:
  Added serializable `LocalVariableUserSetting` / `LocalVariableLocator`
  plus `saved_user_lvar_settings`, `apply_user_lvar_setting`, and
  `apply_user_lvar_settings`. Migrated ida-cdump metadata lvar export/apply
  to those APIs, removing direct `lvar_uservec_t`, `lvar_saved_info_t`,
  `restore_user_lvar_settings`, `modify_user_lvar_info`, and direct per-lvar
  `parse_decl` use from `transfer/metadata*.cpp`. Verified with
  `cmake --build build-test-fetch --target idax_api_surface_check -j2` and
  `IDASDK=<dev-root_>/ida-cdump/build/_deps/ida_sdk-src cmake --build build -j2`.
- 2026-05-28 P22.R3 partial ctree provenance migration:
  Added read-only `ExpressionView` helpers for expression type sizing,
  pointed-object sizing, member-name resolution, ternary third operands, and
  assignment-LHS detection. Migrated ida-cdump `analysis/ctree_analyzer.*` to
  `ida::decompiler::DecompiledFunction` / `ExpressionView` traversal without
  raw `cfunc_t`, `cexpr_t`, `carg_t`, `ctree_visitor_t`, or `get_func`.
  Verified with `cmake --build build-test-fetch --target idax_api_surface_check -j2`
  and `IDASDK=<dev-root_>/ida-cdump/build/_deps/ida_sdk-src cmake --build build -j2`.
- 2026-05-28 P22.R2/R3/R6 ida-cdump parity closure:
  Added idax type declaration renderers, dependency-ordered ordinal
  declarations, used-member trimming, DOT type graph rendering,
  `ida::decompiler::collect_referenced_types(Address)`, and
  `ida::ui::attach_registered_action` for popup-ready registered actions.
  Migrated ida-cdump type collection, type rendering, type graph output,
  metadata type export, and Local Types popup attachment to those APIs;
  removed the local `type_formatter` and `type_graph_dot` sources. Residual
  ida-cdump scan hits are idax calls, field names, IDA ABI primitives, or
  local formatting utilities rather than parity-blocking SDK analysis calls.
  Verified with `cmake --build build-test-fetch --target idax_api_surface_check -j2`,
  `IDASDK=<dev-root_>/ida-cdump/build/_deps/ida_sdk-src cmake --build build -j2`,
  and `git diff --check` in both checkouts.
- 2026-05-28 P22 refreshed local parity evidence:
  `bash -n scripts/check_codedump_parity_evidence_log.sh
  scripts/run_codedump_parity_host_gates.sh
  scripts/run_codedump_parity_local_validation.sh`,
  `scripts/check_codedump_parity_evidence_log.sh --self-test`,
  `scripts/run_codedump_parity_host_gates.sh --self-test`, and
  `scripts/run_codedump_parity_local_validation.sh --self-test` all pass.
  `env IDAX_RUN_NODE_INTEGRATION=1 IDADIR=<userhome>/ida-pro-9.3
  scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo` passes focused C++ build/CTest (6/6 selected tests), default
  host-gate evidence with automatic verifier output, verifier self-test,
  compact parity probe example build, Node native build/unit coverage
  (182/182), Node fixture integration (63/63), Rust typed-form validation,
  Rust library no-run, and Rust type-declaration integration no-run. The
  locally available Hex-Rays host mode also passes with
  `env IDAX_RUN_HEXRAYS_SESSION=1 IDADIR=<userhome>/ida-pro-9.3
  scripts/run_codedump_parity_local_validation.sh build-test-fetch
  RelWithDebInfo`, including Hex-Rays evidence verification with 9 checks,
  zero failures, and the expected modal/clipboard skips. Explicit verification of
  `build-codedump-parity-host/codedump-host-default.log` in `default` mode and
  `build-codedump-parity-host/codedump-host-hexrays.log` in `hexrays` mode
  passes. Remaining closure evidence is unchanged: P22.H1 accepted modal form
  execution and P22.H2 clipboard execution in an IDA UI host with clipboard
  access.

- 2026-07-13 Phase 24 IDA-names ergonomic parity:
  Added `ida::ui::current_widget`, `ida::decompiler::on_switch_pseudocode`,
  arbitrary-symbol `ida::name::demangled`, stable live-widget identity, and
  matching Node/Rust surfaces. Migrated the IDA-names example to the exact
  polling/switch APIs and an isolated Qt host-title bridge. Focused C++ build
  and runtime validation passes 4/4 selected CTest targets; the Qt example
  target links successfully. Node clean/incremental native build passes, its
  structural suite passes 184/184, and its real-IDA fixture integration passes
  65/65. Rust formatting and library tests pass 127/127. The complete C++
  sweep builds and passes 24/25 targets; the one failure is the independent
  menu-detach contract regression F370 (2 failed checks in
  `loader_processor_scenario`). Rust real-IDA integration was attempted but
  is not counted as pass evidence because the shared init/open/analysis
  sequence stalled (F371).

- 2026-07-13 Phase 25 action-attachment state hardening:
  Replaced reliance on IDA 9.3's ambiguous menu-detach boolean with counted
  wrapper-managed menu/toolbar attachment state and unregister cleanup.
  `loader_processor_scenario` now exercises registration, attach, detach,
  second-detach `NotFound`, reattach, unregister cleanup, and post-unregister
  `NotFound`. Focused validation passes, and a clean relink plus complete CTest
  sweep passes 25/25 targets in 32.64 s. Rust formatting plus the plugin unit
  subset pass 2/2; the Node addon relinks and its structural suite passes
  184/184. The fixture IDB was restored after runtime execution.

- 2026-07-13 Phase 26 Rust real-IDA main-thread harness:
  Live process sampling localized F371 to standard libtest topology: process
  main was parked awaiting its worker while worker-side IDAPython initialization
  synchronously waited on IDA's main-thread executor. The `integration` target
  now uses `harness = false` with an explicit registry of 83 sequential cases,
  substring/exact filtering, skips/platform ignores, panic capture, and one
  same-thread database close. The formerly stalled arbitrary-demangle case
  passes 1/1 with real IDA. The complete suite executes to termination with
  82/83 passing after cache-invalidating the microcode-filter test; its sole
  remaining failure is the independent observable comment-append defect F374,
  promoted to a separate semantic-hardening item. Compile-only, `--list`, and
  no-`IDADIR` filtered-skip modes also pass.
