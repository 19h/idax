# PR 6 Swift review and rewrite baseline

Reviewed head: `25b002ade3ed02df9566f432e945d78ec4c32f1b`.
Reference branch: `review/swift-pr-6-original`.
Fresh implementation branch: `rewrite/swift-bindings`, based on CI correction `852ed24f7bd4ffec81b4ba1fb43c9679b4eaa05e`.

The incoming PR has the following reproducible defects. The user subsequently requested a fresh implementation of its capabilities under the current IDAX architecture; Phase 72 tracks that implementation. This document records the incoming revision and does not claim the replacement is complete.

## Reproduced findings

1. **P1: Existing microcode serialization loses fields.** `bindings/rust/idax-sys/shim/idax_shim.cpp:10524` zeroes instruction storage but no longer copies address, text, or destination-modification state. Its operand converter also drops processor-register mapping, referenced operands, call arguments/target, and display text. A harness using the exact changed converters and populated inputs returns zero/null for every removed field. The existing Rust owned-graph integration test requires nonempty instruction text. Restore the complete established transport model.
2. **P1: Added workflow actions violate the checked inventory.** `.github/workflows/bindings-ci.yml:604` adds two checkout uses and one setup-uv use. `scripts/check_ci_action_pins.py` still expects 15 and 6 respectively; actual counts are 17 and 7. The checker fails before each native validation profile can configure. Audit the new uses and update the inventory together.
3. **P1: New public domains invalidate Python declaration coverage.** `include/ida/idax.hpp:50` adds `dyld_cache` and `microcode` without corresponding Python inventory entries. The umbrella digest and database/decompiler/instruction/plugin header digests are also stale. The declaration gate fails immediately; changing a digest alone cannot supply the missing declarations/bindings.
4. **P1: Swift processor customization does not dispatch.** `Processor.swift:496` declares optional callbacks solely in the protocol extension. Native trampolines operate through `any ProcessorModule`, so conformer overrides are ignored. An executable using the actual compiled module returns `1` from concrete `isCall` and `0` from the existential; custom `onNewFile` executes only through the concrete receiver. Declare customization signatures in the protocol and keep extension defaults.
5. **P1: Swift Appcall success is inverted.** `Debugger.swift:424` returns `0` for a nil callback result and `1` for a populated successful result; the existing C executor accepts only `0`. The actual Swift trampoline, invoked through a C lifecycle probe using the real ABI declarations, reproduces both inverted outcomes. Use the canonical status convention and a publicly constructible result.
6. **P2: Successful executor teardown leaks captures.** `Debugger.swift:433` obtains a retained callback box with `takeUnretainedValue` and never releases it. A weak capture remains live after successful unregister and the cleanup callback. Resolve ownership as one native callable-owned lifetime; account for cleanup on registration failure and in-flight dispatch.
7. **P2: Default Swift build can resolve the wrong archive.** `Package.swift:63` uses `-lidax`. On case-insensitive macOS, Swift 6.4's default `swiftbuild` places its generated `libIDAX.a` earlier on the search path, satisfying that spelling instead of the native C++ archive. The unmodified package fails with unresolved C++ symbols; passing the explicit native archive makes the same 64 tests pass. The native build engine also passes 64 tests. Use a non-colliding archive identity or explicit archive path.
8. **P2: Snapshot stack offsets are omitted.** `src/microcode.cpp:500` records stack storage but leaves every offset at `-1`. An exact IDA 9.4 probe reports 7/7 stack variables missing offsets; function `0x580`'s `retaddr` is `-1` in the proposed snapshot and `16` bytes in the established decompiler variable record. Reuse one verified location conversion.
9. **P2: LOOP predicates are reversed or incomplete.** `src/instruction.cpp:290` classifies LOOP, LOOPE, LOOPNE, and JECXZ as the same CountZero predicate. Actual decoding of a generated x86-64 ELF fixture reproduces this at offsets `0x5`, `0x7`, `0x9`, and `0xb`. LOOP tests the decremented count for nonzero; the other loop forms additionally test ZF. The pinned SDK's `allins.hpp:117` documents these distinct semantics.
10. **P2: Navigating a statement loses ancestry.** `src/decompiler.cpp:4299` constructs children without their parent's ancestry context. An initialized-host probe with parent tracking enabled loses parent information for 22/22 navigated block children. The new C shim has an independent ordering problem: its parent map is populated only when each child is visited, so preorder navigation also returns no parent in 22/22 cases. Preserve ancestry in C++ and make the binding's parent lookup independent of callback visitation order.

## Architectural requirements established by review

- Decision 19.39 already defines owned, maturity-explicit recursive microcode graphs under `ida::decompiler`; extend that model for missing information.
- Decision 19.47 deliberately removed numeric structure-ID interfaces. Retain the opaque structure/member-name model.
- The current authoritative umbrella contains 38 domains plus core/error. Historical counts and the incoming Swift namespace count do not establish full coverage.
- Decisions 19.61 and 19.63 require complete errors, declaration-level coverage, resource/callback ownership, and actual plugin/loader/processor host exports.
- The rewrite preserves the existing C ABI's deep-copy/free behavior and all established language bindings.

## Evidence and limits

Native probes used the exact IDA SDK revision `6929db6868a524496eb66e76e4ec6c9d720a0594`, an installed IDA 9.4 runtime, and disposable copies of `tests/fixtures/simple_appcall_linux64`. Swift probes used Swift 6.4 on macOS arm64. The native-builder suite and the explicit-archive default-builder suite each passed 64 tests in 32 suites. The dyld-cache test returned early because its dedicated database fixture was absent; that is not dyld-cache runtime evidence. Regenerated Rust declarations were not inferred from a `DOCS_RS` compile check.

| Assumption | Stress test / falsification probe | Dependent result |
|---|---|---|
| The review applies to the recorded incoming head | Recheck PR head and diff before applying findings | All incoming-PR findings |
| The executor probe models the real C contract | Compare registration, status handling, and destructor cleanup against `CAppcallExecutor` | Findings 5–6 |
| Archive lookup is case-insensitive and Swift product search precedes native search | Compare default, native-engine, and explicit-archive builds | Finding 7 |
| Copied raw fixtures exercise the named semantics under exact IDA 9.4 | Repeat initialized-host traversal, stack-location, and instruction-decode probes | Findings 8–10 |

Bounded impacts: existing-binding regressions and callback/dispatch errors **high**; metadata loss, retained captures, and conditional packaging failure **medium**. UI presentation and full dyld-cache fixture behavior remain **unknown**. No physical-unit calculation is required beyond explicitly byte-valued offsets. Snapshot conversion and traversal are linear in copied records/edges; callback dispatch and ownership transfer are constant-time apart from user callbacks.

Quality gates for this review: no normative judgment required; assumptions and probes are explicit; all 71 changed files were allocated to source/build/ownership review; reported results distinguish actual execution from static evidence; no unsupported runtime claim or fabricated reference is included. Implementation closure is tracked separately in Phase 72.
