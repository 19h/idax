# Validation Report

Date: 2026-02-15 (base report; current local full-sweep evidence updated 2026-07-14 after Phase 29)

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

**Current total: 25/25 CTest targets pass**

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

- 2026-07-13 Phase 27 deterministic comment append:
  Replaced direct `append_cmt` dispatch with a bounded wrapper-level
  read/compose/write contract: append creates the comment without a leading
  newline when absent and writes `existing + "\n" + text` otherwise. Exact
  function-start and repeated data-item assertions now pass. Focused C++
  comment targets pass 2/2; complete CTest passes 25/25 in 28.42 s. The Rust
  filtered regression passes 1/1 and the complete real-IDA suite now passes
  83/83; Rust library tests pass 127/127. The Node addon rebuilds, unit tests
  pass 184/184, and its real-IDA integration suite passes 66/66. The fixture
  IDB was restored after runtime mutation tests.

- 2026-07-13 post-push GitHub Actions audit:
  The three workflow families do not currently provide source validation.
  Integrations CI, Bindings CI, and Validation Matrix fail across Linux,
  macOS, and Windows in `Install IDA Pro` before setup/build/test execution.
  HCLI downloads IDA 9.3 successfully but reports no license matching the
  configured ID `96-0000-0000-XX` and cannot obtain the corresponding
  `.hexlic` file. This is tracked as F377 and requires external HCLI/license or
  GitHub Actions secret correction; no source/workflow build patch is supported
  by the logs.

- 2026-07-13 Phase 28 typed IDB change-tracking events:
  Added nine opaque post-change event families in C++ and converged Node/Rust
  payloads and typed subscriptions. Event-entry token ceilings, shared route
  ownership, route-liveness checks, deferred final listener unhook, and Rust
  callback-depth context reclamation establish callback-side mutation safety;
  Node exposes 64-bit item/segment sizes as `bigint`. Focused `event_stress`
  passes 103 checks with one F379 host skip; complete C++ build and CTest pass
  25/25 in 21.08 s. The change-tracker example links. Node build and
  structural tests pass 184/184, and real-IDA fixture integration passes 68/68.
  Rust formatting and library tests pass 128/128; the complete main-thread
  real-IDA suite passes 85/85. The current macOS IDA 9.3 idalib host did not
  emit documented `destroyed_items` for two successful destruction paths, so
  that one runtime assertion remains an explicit host-limited skip (F379),
  while ABI/API coverage and the other eight event families pass. The fixture
  IDB was restored after every runtime suite.

- 2026-07-14 Phase 29 fixed-width data-definition units:
  Corrected all ten then-audited data-definition families to interpret `count`
  as an element count and perform checked conversion to the SDK's total byte
  length. Phase 30 subsequently superseded the provisional 10-byte tbyte width.
  Added 256-bit yword and 512-bit zword surfaces across C++, Node, and Rust;
  retained byte units for string/structure definition and undefinition. Exact
  tests cover default one-element and three-element arrays plus zero,
  multiplication-overflow, and address-range-overflow rejection. The audit also
  corrected Rust's shim error-category offset (F382) and made Node/Rust analysis
  idle tests establish their stated wait precondition (F383). Complete C++
  build and CTest pass 25/25 in 21.35 s. Node build/unit pass 191/191 and
  real-IDA integration passes 69/69. Rust workspace unit tests pass 130/130 and
  complete real-IDA integration passes 86/86. Bindgen output matches the
  checked pre-generated bindings exactly; the mutable fixture is restored.

- 2026-07-14 Phase 30 processor-aware extended-real definitions:
  Replaced the provisional universal tbyte width with active-processor
  `tbyte_size` resolution and independent `a_tbyte`/`a_packreal` assembler
  availability checks. Added explicit tbyte/packed-real element-size queries
  and checked positive-element definition APIs across C++, Node, and Rust.
  Tests assert exact one- and three-element item sizes when a representation is
  available and exact `Unsupported` behavior otherwise. Complete C++ build and
  CTest pass 25/25 in 23.93 s. Node native build and structural tests pass
  194/194, with real-IDA integration 69/69. Rust formatting passes, library
  tests pass 130/130, and IDA Professional 9.4 integration passes 86/86 with no
  skips. Generated bindgen output exactly matches checked bindings;
  `git diff --check` passes and the mutable fixture is restored.

- 2026-07-14 Phase 31 custom data type/format lifecycle:
  Added owned opaque registrations with distinct IDs restricted to
  `1..0xFFFE`, copied metadata snapshots, custom/standard format attachment,
  fixed and callback-derived sizing, explicit/inferred item creation, stored
  identity, callback invocation, exception/panic barriers, and deterministic
  explicit teardown across C++, Node, and Rust. The dedicated C++ real-IDA
  lifecycle path passes 234 checks, including variable-size kernel
  revalidation. Complete C++ build and CTest pass 25/25 in 21.41 s. Node native
  build and strict TypeScript declaration validation pass, structural tests
  pass 218/218, and IDA 9.4 integration passes 70/70. Rust formatting passes,
  library tests pass 131/131, and the process-main-thread IDA 9.4 integration
  suite passes 87/87. All generated bindgen outputs are byte-identical to the
  checked binding; `git diff --check` passes and the mutable fixture is clean.

- 2026-07-14 Phase 32 scoped hotkey and action ownership:
  Added wrapper-owned registered-action adapters, move-only C++/Rust
  `ScopedHotkey` lifecycles, programmatic action activation, generated opaque
  shortcut action IDs, and C++ exception/Rust panic barriers. Successful
  unregister now reclaims callback state deterministically without depending
  on host-timed `ADF_OWN_HANDLER` destruction; active callbacks retain their
  adapter through self-unregister. DriverBuddy now models its menu action and
  shortcut-only callback separately, and its plugin target links. Complete C++
  build and CTest pass 25/25 in 20.89 s; the focused action target reports
  237 passes and three explicit headless activation skips. Node build, strict
  declaration compilation, and 218/218 structural tests pass, with IDA 9.4
  integration passing 70/70. Rust formatting passes, workspace library tests
  pass 132/132 plus 0 sys tests, and IDA 9.4 integration passes 88/88. The
  newest generated bindgen output is byte-identical to the checked binding.
  IDA 9.3 idalib rejects `process_ui_action`, so actual activation dispatch
  remains interactive-UI-host-gated (F393); registration, release, and callback
  reclamation are proven headlessly.

- 2026-07-14 Phase 33 forward-compatible processor profile:
  Corrected unsupported processor-ID provenance: installed SDK refs from v9.2
  through the 9.4 placeholder end the public `PLFM_*` range at
  `PLFM_NDS32 = 76`; no searched ref defines the formerly claimed
  `PLFM_MCORE = 77`, while `idp.hpp` reserves values above `0x8000` for
  third-party modules (F394). Added raw-ID-preserving `ProcessorProfile`,
  optional verified typed identity, checked conversion, and optional ABI across
  C++, Node, and Rust. Legacy `Mcore = 77` remains source-compatible but is
  never produced by normalization. Both idapcode adaptations now consume the
  profile; the external Sleigh language-selection policy remains explicit.
  Complete C++ build and CTest pass 25/25 in 22.31 s, and the opt-in
  Sleigh-backed idapcode plugin links. Node native build, strict declaration
  compilation, and structural tests pass 222/222; IDA 9.4 integration passes
  71/71. Rust formatting and the idapcode example check pass, library tests
  pass 132/132 plus 0 sys tests, and process-main-thread IDA 9.4 integration
  passes 89/89. The generated bindgen output is byte-identical to the checked
  binding, `git diff --check` passes, and the mutable fixture is restored.

- 2026-07-14 Phase 34 Intelligent Function Inliner port:
  Preserved decoded-operand read/write access through Node's ordinary and
  decompiler callback snapshots plus Rust's C transfer and safe value model.
  Added an interactive C++ plugin action and a headless Rust report/apply
  adaptation of the original scoring workflow. The port marks selected
  functions with the SDK's `FUNC_OUTLINE` attribute; it does not rewrite
  machine instructions. Complete C++ build and CTest pass 25/25 in 21.48 s,
  and the plugin links. Node native build and strict example declaration
  compilation pass, structural tests pass 223/223, and IDA 9.4 integration
  passes 72/72. Rust formatting and example checks pass, library tests pass
  133/133 plus 0 sys tests, the scoring unit passes 1/1, and process-main-thread
  IDA 9.4 integration passes 90/90. On an isolated fixture copy, report mode
  selected 5/18 processed functions without mutation, apply mode changed all
  five with zero failures, and a fresh reopen observed all five persisted
  outline markers. Generated bindgen output is byte-identical to the checked
  binding, `git diff --check` passes, and the mutable repository fixture is
  clean.

- 2026-07-14 Phase 35 IDAMagicStrings port:
  Added copied configurable string-list inventory and copied half-open
  source-file mappings across C++, Node, and Rust, including normalization of
  IDA 9.3's one leading `strtypes` bookkeeping byte. Closed safe Rust's missing
  filtered `name::all` inventory, then added interactive C++ and headless Rust
  adaptations of the original non-NLTK analysis and explicit rename workflow.
  Complete C++ build and CTest pass 26/26 in 22.63 s, including the dedicated
  `string_source_metadata` target, and the C++ plugin links. The disposable
  CTest runner leaves the tracked fixture hash unchanged before/after the
  complete suite. Node native build,
  strict example declaration compilation, structural tests, and IDA integration
  pass 230/230 and 74/74. Rust formatting/example checks pass, library tests pass
  136/136 plus 0 sys tests, pure port tests pass 3/3, and process-main-thread
  IDA 9.4 integration passes 91/91. On an isolated stripped Mach-O, report mode
  found one `sub_* -> uniqueHandler` candidate without mutation, explicit apply
  renamed 1/1 with zero failures, and a fresh reopen retained the name.

- 2026-07-14 Phase 36 Auto Enum port:
  Added immutable metadata-preserving indexed function-argument replacement
  and opaque named operand-enum representation/readback across C++, Node, and
  Rust. The public all-operands index `-1` is translated to native `OPND_ALL`
  (`0x0F`) only at the SDK boundary. Added an interactive C++ port preserving
  global imported-prototype enrichment and cursor-selected selector-dependent
  annotation, plus a headless Rust global report/apply adaptation backed by a
  representative dependency-free Linux/Windows corpus. Complete C++ build and
  CTest pass 26/26 in 23.07 s, the Auto Enum plugin links, and the tracked IDB
  Git blob object ID remains `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd`
  before and after. Node native
  build, strict declaration compilation, structural tests, and IDA 9.4
  integration pass 232/232 and 76/76. Rust formatting/all-example checks,
  library/sys/port tests, and process-main-thread IDA 9.4 integration pass
  137/137, 0 sys, 2/2, and 93/93. On a disposable host-native fixture, report
  mode found 6 imports/8 candidate arguments without mutation, apply changed
  6 functions/8 arguments with zero failures, and a fresh reopen observed all
  8 positions as already enum-typed. Generated bindgen output is byte-identical
  to the checked binding (SHA-256
  `89ab07dacbbe5a8cfb1696e800a6933fd036c67403a7febce24b50dd87978a66`).

- 2026-07-14 Phase 37 Symless structure reconstruction port:
  Added maturity-explicit owned function-level microcode graphs across C++,
  Node, and Rust, including copied argument/return locations, CFG adjacency,
  addressed recursive instructions, address references, call arguments, and
  forward-compatible `Other` values. Added an interactive C++ plugin and
  headless Rust adaptation for the explicitly bounded one-argument
  intraprocedural workflow; neither claims full Symless parity. Complete C++
  build and CTest pass 26/26 in 22.99 s, the Symless plugin links, and the
  tracked IDB Git blob object ID remains
  `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd` (file SHA-256
  `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b`).
  Node native build, strict declaration compilation, structural tests, and
  IDA 9.4 integration pass 232/232 and 77/77. Rust formatting/all-example
  checks, library/sys/port tests, and process-main-thread IDA 9.4 integration
  pass 138/138, 0 sys, 3/3, and 94/94. A host-native fixture recovered exact
  `+4/4 B` write, `+8/8 B` read, `+18/2 B` read, and `+24/1 B` read fields;
  report mode did not create the UDT, explicit apply created 4/4 members and
  changed argument 0, and fresh-process reopen was idempotent. Generated
  bindgen output is byte-identical to the checked binding (SHA-256
  `dc548a8c3f5b0c00a28db45827a5570c2530d20a9d06fa01a87416daf942a4b8`).

- 2026-07-14 Phase 38 Symless interprocedural structure propagation:
  Added metadata-preserving function-return replacement and explicit default-off
  call analysis across C++, Node, and Rust. Extended both Symless adaptations
  with depth-bounded resolved direct-call argument injection, active/repeated
  context guards, conservative terminal-return consensus, propagated-site
  reporting, and zero-shift-only argument/return mutation. Complete C++ build
  and CTest pass 26/26 in 23.00 s, the plugin links, and the tracked fixture
  remains Git blob `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd` with SHA-256
  `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b`.
  Node native build, strict declarations, structural tests, and IDA 9.4
  integration pass 234/234 and 77/77. Rust formatting/all-example checks,
  library/sys/port tests, and process-main-thread IDA 9.4 integration pass
  138/138, 0 sys, 6/6, and 94/94. A host-native arm64 fixture (source SHA-256
  `3f6c0a873a5c58ddc20a49286d03ebd95935626bff6c296822dc50aa41adb382`;
  binary SHA-256
  `c35d86971a29a8bb54da74170b39ee3bb6018db95891e04de41cd7220d1dd635`)
  follows 2 calls/3 functions and recovers exact `+4/4 B`, `+8/8 B`, and
  `+24/1 B` reads; depth zero omits the callee-only field. First apply creates
  3/3 members and types 3/3 arguments plus 1/1 return; fresh-process reopen is
  idempotent. Generated bindings are byte-identical at SHA-256
  `6a14f8a22c18ecd8576773854a99b96c8463631860aafbd76a0449900dd2b0e4`.

- 2026-07-14 Phase 39 Symless allocator seed and wrapper discovery:
  Added metadata-preserving function-argument renaming across C++, Node, and
  Rust. Extended both Symless adaptations with declarative malloc/calloc/realloc
  locators, exact direct-call classification, bounded static sizes,
  terminal-call-token wrapper confirmation, cycle-safe heir traversal,
  allocation-call structure roots, extent checks, distinct root UDTs, and
  generic allocator prototype enrichment. Complete C++ build/CTest pass 26/26
  in 24.91 s and the four-action C++ plugin links. Node native build, strict
  declarations, structural tests, and IDA 9.4 integration pass 234/234 and
  77/77. Rust formatting/all-target checks, library/sys/port tests, and
  process-main-thread IDA 9.4 integration pass 138/138, 0 sys, 10/10, and
  94/94. The host-native arm64 fixture (source SHA-256
  `25dc8ab5303f5d8cbe4dad89e19f3c36ce8c8e095d9a007a97a30ef29491109e`;
  binary SHA-256
  `6e85799ebf264654b5a898c44ae77c6990cf5c3b772e1ba9fd8106a04721fac6`)
  yields one malloc wrapper and one 32 B root with exact `+4/4 B`, `+8/8 B`,
  and `+24/1 B` read/write fields and zero extent violations. First apply
  creates one UDT/three members and changes two generic prototypes; a fresh
  process reuses all members and recognizes both prototypes with zero changes.
  Generated bindings are byte-identical at SHA-256
  `414fe27fd05155e75246ee686c98919c0cab40e44b02c692fe927632e925c428`.

- 2026-07-14 Phase 40 Symless constructor and vtable root discovery:
  Added metadata-preserving C++ object/vftable UDT semantics across C++, Node,
  and Rust. Extended both Symless adaptations with bounded function-pointer
  table scanning, exact argument-zero constructor-store proof, ambiguous-root
  rejection, secondary-offset reporting, recovered class fields, semantic
  class/vftable materialization, existing-layout preflight, vftable application,
  and eligible `this` prototype typing. Complete C++ build and CTest pass 26/26
  in 22.16 s and the six-action plugin links. Node native build, strict
  declarations, structural tests, and IDA 9.4 integration pass 234/234 and
  78/78. Rust formatting/all-target checks, library/sys/port tests, and
  process-main-thread IDA 9.4 integration pass 138/138, 0 sys, 12/12, and
  95/95. The host-native arm64 fixture (source SHA-256
  `6002d19ff61a9a1029412e508be59445ead0ffe7df41f02b648650c702da2b4b`;
  binary SHA-256
  `ee4b8c55449a6163716b6ca5f86744381c4bccd153b13073c49ee53bda47fab8`)
  yields one three-method table and one constructor with exact `+8/4 B`,
  `+16/8 B`, and `+24/1 B` writes. First apply creates two semantic UDTs and
  seven members, types four prototypes, and applies one vftable; fresh-process
  reopen reuses all seven members and recognizes all four prototypes with zero
  changes. Generated bindings are byte-identical at SHA-256
  `5a91e0e932583a98f7079e32cfacc9493d1dee27e4d80c938a1b3da5b44ef949`.

- 2026-07-14 Phase 41 Symless shifted-pointer metadata:
  Added copied exact pointer details and immutable metadata-preserving shifted
  parent/delta construction across C++, Node, generated C ABI, and safe Rust.
  Extended both Symless adaptations to apply proven nonzero argument shifts,
  recognize exact parent/delta metadata on reopen, preserve mismatched complex
  pointers, and continue excluding shifted returns. Full C++ build and CTest
  pass 26/26 in 22.40 s; the Symless plugin links. Node native build, strict
  example declarations, structural tests, and IDA 9.4 integration pass 234/234
  and 79/79. Rust format/all-target checks, library/sys/port tests, and
  process-main-thread IDA 9.4 integration pass 138/138, 0 sys, 12/12, and
  96/96. The host-native arm64 fixture (source SHA-256
  `51077b3f7811c4d8f7d185d7fe2bd23bdefdceaa8736b0b726790acfa13b4c12`;
  binary SHA-256
  `f2d9e2cb641377ead4d855a4d994768cabbabd53e33f015500b32bef0df5306b`)
  yields root shift `0 B`, callee shift `+8 B`, and exact `+4/4 B`, `+8/8 B`,
  and `+24/1 B` fields. First apply creates one UDT/three members and changes two
  arguments including one shifted argument; fresh-process reopen reuses all
  members and recognizes both arguments with zero mutation. Generated bindings
  are byte-identical at SHA-256
  `4b0958634a70f67ce68945a13a9d89c27ed9bd7b0d3a1fcdb451a1dc9a3f484c`.

- 2026-07-14 Phase 42 Symless forward local-type replacement:
  Added explicit local forward-declaration state/kind and failure-atomic,
  ordinal-preserving same-name structure/union replacement across C++, Node,
  generated C ABI, and safe Rust. Extended both Symless adaptations to replace
  exact forwards only during explicit apply, retain complete/incompatible
  definitions, and report creation/reuse/replacement independently. Full C++
  build and CTest pass 26/26 in 22.04 s; the Symless plugin links. Node native
  build, strict example declarations, structural tests, and IDA 9.4 integration
  pass 234/234 and 80/80. Rust formatting/all-target checks, library/sys/port
  tests, and process-main-thread IDA 9.4 integration pass 138/138, 0 sys,
  12/12, and 97/97. The DWARF host fixture (source SHA-256
  `031535bef12bf6b7559501ad30e719a2a013c14f78299ae7fe5953665d8220dd`;
  arm64 binary SHA-256
  `108394bb40d9a50db4b63fe0d7f535c383632da1110f5527afda0b362dc45b3b`)
  yields exact `+4/4 B`, `+8/8 B`, and `+24/1 B` reads. First apply replaces
  one forward ordinal, adds three members, creates no duplicate UDT, and
  recognizes the existing pointer argument as already typed; fresh-process
  reopen performs zero replacement/addition and reuses all three members.
  Generated bindings are byte-identical at SHA-256
  `82702ed7f7a98b3e446c1e9053704d84e0f47c7d8f2cbd9cad126363f8473ac8`.
  The tracked executable and adjacent IDB remain respectively SHA-256
  `af23d4fde7d2b5ebe20385f5aa8c23221988fd1bdbab777c18daf8c9d9543f80`
  and Git blob `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd` / SHA-256
  `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b`.

- 2026-07-14 Phase 43 Symless member-TID informational references:
  Added opaque exact-member `member_references(byte_offset)` and
  `ensure_member_reference(byte_offset, source_address)` across C++, Node,
  generated C ABI, and safe Rust. The implementation requires a complete saved
  local UDT, one exact member offset, stable internal member identity, and a
  mapped source item head; it ensures verified `dr_I | XREF_USER` persistence
  without exposing a TID. Both Symless adaptations now count candidates in
  report mode and classify added/reused/skipped references during explicit
  apply for ordinary, allocator, and class/vtable structures. Full C++ build
  and CTest pass 26/26 in 22.95 s. Node native build, strict example
  declarations, structural tests, and IDA 9.4 integration pass 234/234 and
  81/81. Rust formatting/all-target checks, library/sys/port tests, and
  process-main-thread IDA 9.4 integration pass 138/138, 0 sys, 13/13, and
  98/98. Generated bindings are byte-identical at SHA-256
  `5613b4d1672f5c2a51b3b6705f0ad34d67faf15ed37eae600773280c23683212`.
  The DWARF fixture source SHA-256 is
  `031535bef12bf6b7559501ad30e719a2a013c14f78299ae7fe5953665d8220dd`;
  the temporary arm64 executable is
  `db57dccb7c56f0487edf1ff3c7d477e84b6b1bc45e12ad3ccf6fd98376ab79f0`.
  Report mode found three exact fields/sites and three candidates without an
  IDB; first apply added three persistent member references; a fresh process
  reopening the saved `.i64` added zero and reused all three. The tracked
  executable and adjacent IDB remain respectively SHA-256
  `af23d4fde7d2b5ebe20385f5aa8c23221988fd1bdbab777c18daf8c9d9543f80`
  and Git blob `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd` / SHA-256
  `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b`.

- 2026-07-14 Phase 44 Symless exact operand struct-offset paths:
  Replaced public native structure/member-ID path metadata with copied root and
  ordered member names across C++, Node, generated C ABI, and safe Rust. Added
  conflict-safe exact-member ensure with complete saved-local UDT validation,
  arbitrary-operand representation preflight, two-component apply/readback,
  post-apply verification, and failure-atomic cleanup. Owned microcode register
  operands now retain copied processor-register IDs from `mreg2reg`. Both
  Symless adaptations preserve direct memory and size-zero pointer add/sub
  evidence, group by `(instruction, processor register)`, select the upstream
  phrase/displacement or register-preceded immediate, and report exact
  candidate/add/reuse/skip counts for ordinary, allocator, and class/vtable
  reconstructions. Full C++ build and CTest pass 26/26 in 22.90 s; the Symless
  plugin links. Node native build, authoritative strict example declarations,
  structural tests, and ABI-matched live integration pass 238/238 and 82/82.
  Rust formatting/all-target checks, library/sys/port tests, and
  process-main-thread IDA Professional 9.4 integration pass 139/139, 0 sys,
  14/14, and 99/99. Generated bindings are byte-identical at SHA-256
  `3a143a13309725ed66c5ebce1dd5199fafcc30ea8a0d92b33404c9fef66d7a13`.
  The final fresh arm64 fixture (source SHA-256
  `031535bef12bf6b7559501ad30e719a2a013c14f78299ae7fe5953665d8220dd`;
  executable SHA-256
  `1c1f7d72a5d13a6f74101e09c0f46048d1321190c3272a728dbc0bce94bb0843`)
  recovers three fields and three operand candidates. Report mode creates no
  IDB; first apply adds three two-component paths plus three members/references;
  fresh-process apply adds zero and reuses all three of each. The reopened IDB
  SHA-256 is
  `5eacc6b9554734a9d58fec4475697c09207eeb42330edda16f13047ffa2e4f94`.
  Tracked executable and adjacent IDB remain respectively SHA-256
  `af23d4fde7d2b5ebe20385f5aa8c23221988fd1bdbab777c18daf8c9d9543f80`
  and Git blob `84ff142e9cd6c39dbd22d94c7d164b2db48c64dd` / SHA-256
  `ce6d678f484d681a5bc147dab49c272e3a7f9883b3c15c41974ec52cb95a431b`.
