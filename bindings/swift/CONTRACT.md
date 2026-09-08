# Swift binding contract

This package implements the current IDAX C++ domain model. `cpp_api_inventory.json` records declarations, overloads, enum cases, and fields from the authoritative headers. `value_schema.json` specifies the transport rules for generated value operations. Neither file by itself proves behavioral parity; dedicated adapters and executable clients cover ownership, callbacks, and operations absent from the shared C transport.

## Runtime and errors

Initialize `Runtime` once on the process main thread for an idalib program. A native add-on attaches to the existing host during module bootstrap. Subsequent SDK operations execute on that same operating-system thread; Swift actor isolation does not establish an operating-system thread identity. Foreign-thread access fails before SDK entry.

`IDAError` carries the exact native category, code, message, and context. The legacy C display message remains unchanged for existing consumers; separate additive accessors transport the unmodified message and context. Swift input strings reaching C-string interfaces reject embedded NUL. Output strings require valid UTF-8. IDC value strings use explicit byte lengths and preserve embedded NUL.

## Values, resources, and callbacks

Copied records, enums, arrays, and strings own their contents. Public record initializers support independent construction. Native resources are reference types without `Sendable` conformance. Explicit `copy()` creates an independent native value where the C++ model supports copying; assignment preserves ordinary Swift reference semantics.

Native resource holders validate both their owner thread and database lifetime. Opening or closing a database invalidates database-bound native resources in reverse acquisition order. Retained Swift objects remain closed after a later database opens. Explicit close is idempotent; ARC destruction on a foreign thread queues native release for the runtime thread. Database replacement is rejected until the current database is closed.

Lifecycle registration consumes a retained Swift callback context on native entry, including failure paths. Native callable ownership controls its final release. Borrowed callback views validate a lease on every operation and fail after callback return. Registration close and resource invalidation preserve an in-flight callback until its dispatch completes. Deferred action unregistration acceptance is distinct from completed native teardown.

## Packaging

SwiftPM uses stable Swift language mode 6 and declares macOS 13 as its deployment baseline. CMake builds the non-colliding `idax_swift_native` archive, including the canonical Rust C transport and private Swift adapters. A private system-library target consumes generated pkg-config metadata. The manifest contains no unsafe linker flags or experimental interop features. Executable clients supply an rpath to their actual licensed IDA runtime; source distributions do not contain the proprietary runtime, host paths, or compiled local products.

Add-ons link one shared `IDAXShared` image for Swift classes and native runtime state. Each add-on separately owns its SDK descriptor and factory symbols; those factories use hidden visibility to prevent interposition between add-ons. The helper installs relative support-library search paths, and relocated multi-add-on host probes validate that layout.

Plugin, loader, and processor examples must produce real native `PLUGIN`, `LDSC`, and `LPH` exports and dispatch into protocol requirements implemented by Swift conformers. Object construction alone is not module-host evidence.

## Assumption register

| ID | Assumption | Stress test / falsification probe | Dependent result |
|---|---|---|---|
| SW.A1 | Current public headers and superseding decisions define the intended surface | Rebuild the declaration inventory; require a reviewed mapping for every declaration, field, and overload | Coverage claims |
| SW.A2 | Stable Swift 6 language constructs can meet the declared deployment envelope | Build with the minimum supported toolchain and deployment target; inspect public consumers and load commands | Platform availability |
| SW.A3 | All SDK operations use one initializing operating-system thread | Invoke initialization, ordinary calls, resource access, and ARC destruction from foreign threads | Thread confinement |
| SW.A4 | Closing/opening a database invalidates all database-bound native resources | Retain values over close/reopen and require deterministic rejection; record LIFO destructor order | Session safety |
| SW.A5 | Native callable lifetime owns each transferred callback context exactly once | Weak-capture tests for success, failure, self-unregister, automatic stop, and in-flight teardown | Callback ownership |
| SW.A6 | The actual SDK revision and runtime are IDA 9.4 | Compile against pinned revision `6929db6868a524496eb66e76e4ec6c9d720a0594`; execute isolated host fixtures | Native runtime results |
| SW.A7 | The C transport's documented status, allocation, and enum conventions match its implementation | Inspect each mapped conversion/free path; exercise false-valued successes, empty arrays, optional absence, and malformed inputs | Generated value adapters |

Bounded impacts: omitted overloads, lifetime errors, and broken native module dispatch **high**; package transitivity and semantic metadata loss **medium**. The generated value layer costs O(n) time and space for n copied records/bytes. With R retained native holders and Q queued finalizers, the owner-thread guard scans up to R holders; draining queued holder releases can cost O(R + QR), in addition to native destruction and callback work. Database invalidation can scan retained closed holders repeatedly, giving an O(R²) worst case. Individual holder-state access after these guards is O(1). Offsets explicitly identify bytes or bits, and wait configuration explicitly identifies milliseconds.

This contract is an acceptance specification. Phase 72 remains active until declaration mapping, regression/runtime evidence, package checks, existing-language CI, privacy audits, staged review, commits, and pushes are complete.

- **SW.A8 — synchronous native borrow boundaries.** SDK callbacks execute on the runtime owner thread within guarded native operations. Probe escaped ctree children, callback close/reopen, early Hex-Rays session closure, and ARC release during dispatch. Session and lease-dependent results require these probes; no runtime pass is inferred from source compilation.

- **SW.A9 — custom registration generations.** Type/format/fixup identities issued by this Swift bridge carry opaque generations. Probe explicit unregister followed by actual SDK slot reuse, stale queries/mutations, and old-owner close/ARC; require the replacement callback and metadata to survive. Arbitrary external SDK unregister/re-register with the same numeric slot and same name has no observable SDK generation signal. Detection of that external sequence is unknown; wrapper-mediated registration results depend on this boundary.
- **SW.A10 — one shared add-on support image per host.** All simultaneously loaded add-ons use the same built IDAXShared image, with separate hidden module factories. Probe a relocated plugin/loader/processor tree and two different plugins in one host; require independent callbacks, no duplicate Swift class diagnostics, and normal teardown. Mixing incompatible support-library builds is outside the validated package configuration.

- **SW.A11 — supported custom form grammar.** The pinned FORM_C grammar defines placeholder storage, field identifiers, directives and group argument order. Probe compatible scalar/text/path/dynamic-label storage, interleaved groups, buffer capacities, malformed markup, mismatched arguments, the 64-argument limit and -2/-1/0/1 outcomes. Nonmodal validation and controlled native-dispatch probes establish those paths; actual modal acceptance remains unknown on this host. Native callbacks/toolkit-pointer controls and nested substitutions inside field labels are not supported by the opaque argument model. Arbitrary Qt/toolkit embedding through native widget-host pointers is likewise outside the public Swift API; checked Widget operations are not asserted to replace that capability.

Custom form validation/preparation takes O(markup bytes + argument count + copied value bytes + requested character-buffer capacities) time and O(argument count + copied value bytes + requested character-buffer capacities) storage. Character capacities are byte counts; the default native command capacity is independent of the platform path capacity. SDK display complexity is unknown. Results -1 and 0 do not commit bindings; zero retains the SDK's ambiguity among No/cancellation/allocation/syntax outcomes. Results below -1 remain SDK failures.
