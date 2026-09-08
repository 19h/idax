# Swift rewrite validation

Implementation revision: `2efc56f2b82d47aa9c0cadb710b7a7f3b8587699` on `rewrite/swift-bindings`.

The fresh implementation replaces the incoming PR's Swift package and private adapters. The [original PR review](pr-6-swift.md) records the reproduced defects. The [package guide](../../bindings/swift/README.md), [contract](../../bindings/swift/CONTRACT.md) and [declaration mappings](../../bindings/swift/api_mapping) describe the resulting API and its explicit adaptations.

## Evidence

| Check | Result and scope |
|---|---|
| Canonical declarations | 3,604 declarations across 41 headers: 39 domains plus core/error. Source attributes, defaults, fields, overloads and export macros are included. |
| Actual Swift API | 3,538 compiler-extracted public symbols. Every canonical declaration has a reviewed target: 2,861 direct, 650 adapted, 93 private bridge. No public native transport pointers appear in the symbol graph. |
| Inventory portability | Apple Clang and upstream Clang 20 produce identical normalized C++ inventories; actual Swift 6.0 passes the same gate. A changed native default still fails it. |
| Native tests | Full local native run: 46/46. Subsequent compiler-path checks: 4/4. Final form correction: 3/3 targeted tests, including 38 new controlled SDK-dispatch assertions. |
| Swift tests | Final clean helper: 32/32 XCTest, all initialized runtime suites, 40 populated decompiler/microcode graphs, the inventory example and a clean transitive consumer. |
| Custom Appcall executors | Request values/options and result diagnostics round-trip; weak-capture tests pass for successful registration, duplicate-registration failure and self-unregister. Borrowed type/database close attempts are rejected during dispatch. |
| Native add-ons | Four rebuilt add-ons share one support image. Relocated host checks pass two independent plugins, loader acceptance/selection, and processor decoding/rendering. |
| Distributions | Final 793-file Git source archive passes privacy and extracted Swift compilation. Native CPack has 57 entries/49 regular files and passes bytewise privacy after path mapping. All four add-on images and shared support pass byte/string privacy scans. |
| Existing bindings | Local Python declaration/type/package checks and Node structural/TypeScript checks pass; cross-platform existing-binding results are covered by the final CI matrix below. |

Native evidence uses IDA SDK revision [`6929db6868a524496eb66e76e4ec6c9d720a0594`](https://github.com/HexRaysSA/ida-sdk/tree/6929db6868a524496eb66e76e4ec6c9d720a0594) and the actual IDA Professional 9.4 runtime. Local Swift validation uses Swift 6.4. The declared Swift 6.0/macOS 13 deployment baseline is checked with actual Swift 6.0 and 6.3 CI toolchains; deployment-target compilation is distinct from execution on macOS 13.

## Final implementation CI

| Workflow | Jobs | Result | Complete-log privacy |
|---|---:|---|---|
| [Validation Matrix](https://github.com/19h/idax/actions/runs/34190905249) | 6 | Pass | Pass: 6 logs, 896,626 bytes |
| [Integrations CI](https://github.com/19h/idax/actions/runs/34190905299) | 3 | Pass | Pass: 3 logs, 518,924 bytes |
| [Bindings CI](https://github.com/19h/idax/actions/runs/34190905262) | 11 | Pass | Pass: 11 logs, 5,658,342 bytes |

All 20 configured jobs conclude success; each workflow retains its explicit platform-specific runtime boundaries. The existing automatic complete-log audit is restricted to default-branch pushes. This branch therefore uses complete per-job log downloads, verified run/revision identity, complete job enumeration, byte-preserving transfer and terminal-step boundaries, and the same repository log-privacy scanner. All 20 logs pass, totaling 7,073,892 uncompressed UTF-8 bytes. The [audit metadata](swift-rewrite-ci-log-audits.json) records job identities, byte counts, timestamps, completeness checks and SHA-256 hashes without raw logs or host paths.

The documentation-only closure commit records this tested implementation without changing executable sources. Phase 72 is complete in the roadmap and removed from active work.

## Assumptions and evidence limits

The [SW.A1–SW.A11 assumption register](../../bindings/swift/CONTRACT.md#assumption-register) identifies dependent results and falsification probes. Declaration coverage is distinct from runtime behavior. Language adaptations and native-only construction/host-pointer boundaries are recorded explicitly in the map.

Interactive modal-form rendering/acceptance and GUI shortcut activation remain unknown on this host. Nonmodal form preparation and controlled native return/commit tests pass. The SDK's result zero remains ambiguous among No/cancellation/allocation/syntax outcomes. Nested dynamic substitutions inside field labels, arbitrary toolkit embedding and unsupported native callback/pointer form controls remain outside the opaque Swift form/Widget APIs. Linux Swift runtime execution is not established by the macOS matrix. Actual debugger-process Appcall evidence retains the project's separately tracked host boundary.

## Bounded findings and quality gates

- **High impact:** the rewrite and its tests corrected native semantic metadata/branch/coordinate defects, owner/session/callback hazards, loader initialization order, compiler/toolchain compatibility and identifying paths in native distributions.
- **Medium impact:** custom form layout/return behavior, optional-string/default preservation and transitive/source package behavior now have explicit checks and boundaries.
- Complexity, byte/bit/millisecond conventions and compiler/SDK provenance are recorded in the contract and Knowledge Base entries 35.289–35.315. SDK internals whose cost or behavior has not been established remain unknown.

| Quality gate | Result and evidence |
|---|---|
| QG1 | Pass: the scope is technical; no normative judgment is required. |
| QG2 | Pass: SW.A1-SW.A11 identify assumptions, dependent results and falsification probes. |
| QG3 | Pass: the original PR review, fresh implementation, declaration mappings, ownership/module checks, distributions, all 20 CI jobs and complete-log audits are recorded. |
| QG4 | Pass: byte/bit/millisecond conventions and wrapper complexity are explicit; unknown SDK costs are identified. |
| QG5 | Pass within the stated scope: tested edge cases and unsupported or host-dependent behavior are distinguished; no unresolved contradiction is identified. |
| QG6 | Pass: claims refer to authoritative headers, the pinned SDK, actual compiler/runtime execution, linked CI runs and retained audit metadata. |
| QG7 | Pass: high/medium impacts and the bounded opportunities, risks and evidence limits are recorded. |
